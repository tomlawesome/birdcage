package ingest

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

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
func requireBearerToken(database *db.DB, now func() time.Time, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			writeIngestError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		tok, err := store.LookupCanaryTokenByHash(r.Context(), database, store.HashToken(raw))
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
			writeIngestError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		if err := store.RecordCanaryTokenUse(r.Context(), database, tok.ID, now().UTC()); err != nil {
			// The credential is valid regardless of whether this
			// bookkeeping write lands; failing the request over it would
			// turn an authenticated agent away because of birdcage's own
			// storage trouble, exactly what the ack semantics elsewhere
			// in issue #32 avoid on the write path too.
			slog.Error("ingest: record token use", "canary", tok.CanaryID, "err", err)
		}

		ctx := context.WithValue(r.Context(), canaryTokenCtxKey{}, tok)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
