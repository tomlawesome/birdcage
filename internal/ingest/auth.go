package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// canaryTokenCtxKey is the unexported type behind the context key
// requireBearerToken stores the resolved store.CanaryToken under, so
// handleBatch can recover it without a second lookup and without any
// package outside this one being able to collide with the key.
type canaryTokenCtxKey struct{}

// canaryTokenFromContext recovers the store.CanaryToken requireBearerToken
// placed on the request context. The second return is false only if
// requireBearerToken was somehow bypassed -- every route on this
// package's mux is wrapped by it, so a handler seeing false has a wiring
// bug, not a client error, and should fail closed (500) rather than
// proceed with a zero-value identity.
func canaryTokenFromContext(ctx context.Context) (store.CanaryToken, bool) {
	tok, ok := ctx.Value(canaryTokenCtxKey{}).(store.CanaryToken)
	return tok, ok
}

// bearerToken extracts the raw token from an "Authorization: Bearer
// <token>" header value. ok is false for a missing header, a different
// scheme, or an empty token -- every one of those is the same "missing"
// case issue #32's fail-closed rule folds into a uniform 401.
func bearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	raw := strings.TrimPrefix(header, prefix)
	if raw == "" {
		return "", false
	}
	return raw, true
}

// requireBearerToken wraps next so it is only ever reached by a request
// carrying a live canary token: missing, unknown and revoked tokens all
// get the identical 401 (issue #32 fail-closed: "uniform 401, identical
// in status and shape across all three, before the request body is
// read") -- store.LookupCanaryTokenByHash already can't distinguish
// unknown from revoked (slice 1: a revoked row never resolves), and a
// missing/malformed header is rejected before any lookup happens at all,
// so all three paths converge on the same response with no lookup ever
// running for the first case and identical output for the other two.
//
// The body is never touched here or before this returns -- database is
// consulted with a hash lookup only, matching the threat model's "the
// pre-auth cost of a junk request is deliberately tiny: one SHA-256 and
// one indexed lookup".
//
// This is also where issue #32 item 8's per-canary requests/min cap is
// charged, once every request that authenticates on any of this mux's
// three routes -- not only POST /ingest/events. Charged here rather than
// in each handler because the limit is per canary and this is the one
// place every route shares that already has the resolved identity;
// handleBatch used to charge it itself and no longer does, so a batch is
// still charged exactly once.
func requireBearerToken(database *db.DB, now func() time.Time, limiters *limiterRegistry, coalescer *auditCoalescer, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			writeIngestError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		hash := store.HashToken(raw)

		tok, err := store.LookupCanaryTokenByHash(r.Context(), database, hash)
		if err != nil {
			if !errors.Is(err, store.ErrTokenNotFound) {
				// Birdcage's own storage is in trouble; this says
				// nothing about the credential. Issue #32's fail-closed
				// rule is explicit that an infrastructure failure is
				// never reported as a rejection, and a 401 is permanent
				// to the agent -- a database blip would otherwise look
				// to every canary like a dead credential and send it to
				// re-enrolment. 503 denies the request just as firmly
				// and the agent retries, which dedup makes free.
				slog.Error("ingest: token lookup failed", "err", err)
				writeIngestError(w, http.StatusServiceUnavailable, "service unavailable")
				return
			}
			recordTokenConflictIfSuccessorActive(r.Context(), database, now, coalescer, hash)
			writeIngestError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		// Recovered before RecordCanaryTokenUse below overwrites it: nil
		// here means this is the token's first use (issue #32 slice 5),
		// the trigger for completeRotation's revoke-every-older-token
		// sweep further down.
		firstUse := tok.LastUsedAt == nil

		if err := store.RecordCanaryTokenUse(r.Context(), database, tok.ID, now().UTC()); err != nil {
			// The credential is valid regardless of whether this
			// bookkeeping write lands; failing the request over it would
			// turn an authenticated agent away because of birdcage's own
			// storage trouble, exactly what the ack semantics elsewhere
			// in issue #32 avoid on the write path too.
			slog.Error("ingest: record token use", "canary", tok.CanaryID, "err", err)
		}

		if firstUse {
			completeRotation(r.Context(), database, now, tok)
		}

		if !limiters.allowRequest(tok.CanaryID) {
			recordRateLimitCrossed(r.Context(), database, now, coalescer, tok.CanaryID, "requests/min")
			writeIngestError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		ctx := context.WithValue(r.Context(), canaryTokenCtxKey{}, tok)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// recordTokenConflictIfSuccessorActive is issue #32 slice 5's separate
// internal lookup for the token-conflict signal (fail-closed: "slice 1's
// lookup deliberately cannot see revoked rows, so slice 5 adds a
// separate internal lookup for the conflict check; the external 401
// must not change"). It never changes the response the caller already
// got -- a uniform 401 either way -- and any error here is only ever
// logged, never turned into a different status code.
//
// Reaching this function costs no working credential -- a revoked token
// is enough -- so issue #57 routes the actual write through coalescer:
// see auditcoalesce.go for why a caller-controlled rate of revoked-token
// presentations must not become a caller-controlled rate of audit_log
// writes.
func recordTokenConflictIfSuccessorActive(ctx context.Context, database *db.DB, now func() time.Time, coalescer *auditCoalescer, hash string) {
	tok, err := store.LookupCanaryTokenByHashAnyStatus(ctx, database, hash)
	if err != nil {
		if !errors.Is(err, store.ErrTokenNotFound) {
			slog.Error("ingest: token-conflict lookup failed", "err", err)
		}
		return // the hash was never minted at all: noise, not a conflict.
	}
	if tok.RevokedAt == nil {
		// Resolves and isn't revoked -- LookupCanaryTokenByHash above
		// would have found it too, so requireBearerToken has a wiring
		// bug, not a conflict. Never reached in practice.
		return
	}

	active, err := store.CanaryHasActiveToken(ctx, database, tok.CanaryID)
	if err != nil {
		slog.Error("ingest: check active canary token failed", "canary", tok.CanaryID, "err", err)
		return
	}
	if !active {
		// Every token for this canary is revoked: not "a successor is
		// active", so this is noise (or a fully retired canary), not the
		// stolen-token/cloned-box signal item 5 defines.
		return
	}

	at := now().UTC()
	write, occurrences := coalescer.admit(tok.CanaryID, "ingest.token_conflict", at)
	if !write {
		return
	}

	if _, err := audit.Append(ctx, database, audit.Entry{
		Action:      "ingest.token_conflict",
		Target:      tok.CanaryID,
		Reason:      coalescedReason("revoked token presented while a successor token is active", occurrences, "presentations"),
		TriggeredBy: tok.CanaryID,
		CreatedAt:   at,
	}); err != nil {
		slog.Error("ingest: record token conflict", "canary", tok.CanaryID, "err", err)
	}
}

// completeRotation applies issue #32 slice 5's central rule (owner,
// 2026-09-14): "first use of the new token revokes every older token for
// that canary, not just the one presented". It runs on every route this
// package's requireBearerToken guards -- not only POST /ingest/rotate --
// because the rule triggers on the token's first use, whichever route it
// first authenticates. Revoking zero other tokens means tok is the
// canary's only token, i.e. this is its first-ever mint rather than a
// rotation: not itself a rotation, so #45's rotation record stays silent
// for it -- but item 10 ("every mint, first use and revocation" is
// audited) still wants the first use itself recorded, which the
// no-older-tokens branch below now does.
func completeRotation(ctx context.Context, database *db.DB, now func() time.Time, tok store.CanaryToken) {
	revoked, err := store.RevokeCanaryTokensSupersededBy(ctx, database, tok, now().UTC())
	if err != nil {
		slog.Error("ingest: revoke superseded tokens failed", "canary", tok.CanaryID, "err", err)
		return
	}
	if revoked == 0 {
		// No older token existed to supersede: this is the first-ever
		// use of a canary's first token, not a rotation completing.
		// Item 10 wants first use audited regardless, so this is the one
		// case the "ingest.token_rotated" entry below never covers.
		if _, err := audit.Append(ctx, database, audit.Entry{
			Action:      "ingest.token_first_use",
			Target:      tok.CanaryID,
			Reason:      "first use of a canary's first token",
			TriggeredBy: tok.CanaryID,
			CreatedAt:   now().UTC(),
		}); err != nil {
			slog.Error("ingest: record first token use", "canary", tok.CanaryID, "err", err)
		}
		return
	}

	if _, err := audit.Append(ctx, database, audit.Entry{
		Action:      "ingest.token_rotated",
		Target:      tok.CanaryID,
		Reason:      fmt.Sprintf("first use of a new token revoked %d older token(s)", revoked),
		TriggeredBy: tok.CanaryID,
		CreatedAt:   now().UTC(),
	}); err != nil {
		slog.Error("ingest: record completed rotation", "canary", tok.CanaryID, "err", err)
	}
}
