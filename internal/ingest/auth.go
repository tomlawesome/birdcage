package ingest

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
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

// clientCertCtxKey is the context key requireBearerToken stores the
// presented certificate's store.ClientCert row under (issue #130), for
// handleRenew and the heartbeat's version observation.
type clientCertCtxKey struct{}

// clientCertFromContext recovers the certificate row requireBearerToken
// resolved. false means the request carried no client certificate --
// only possible without TLS, i.e. in handler tests.
func clientCertFromContext(ctx context.Context) (store.ClientCert, bool) {
	c, ok := ctx.Value(clientCertCtxKey{}).(store.ClientCert)
	return c, ok
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

// requireBearerToken wraps route.handler so it is only ever reached by a
// request carrying a live canary token whose kind route allows: missing,
// unknown and revoked tokens all get the identical 401 (issue #32
// fail-closed: "uniform 401, identical in status and shape across all
// three, before the request body is read") -- store.LookupCanaryTokenByHash
// already can't distinguish unknown from revoked (slice 1: a revoked row
// never resolves), and a missing/malformed header is rejected before any
// lookup happens at all, so all three paths converge on the same
// response with no lookup ever running for the first case and identical
// output for the other two.
//
// The body is never touched here or before this returns -- database is
// consulted with a hash lookup only, matching the threat model's "the
// pre-auth cost of a junk request is deliberately tiny: one SHA-256 and
// one indexed lookup".
//
// Order of checks past the token lookup (issue #106, design note section
// 2; issue #130): certificate CN matches the token's canary; the
// certificate is a live row in client_certs (ADR-0012 B2); the token is
// bound to that certificate (B3); then the two kind checks, then
// token-use and certificate-use bookkeeping, rotation and renewal
// completion, the dual-use observation (B4) and the rate limiter. Every
// credential refusal is a 401 and comes before any 403. A cross-kind post must not advance last_used_at or trigger
// completeRotation's revocation sweep, so both kind checks sit ahead of
// that bookkeeping, not after it.
//
// This is also where issue #32 item 8's per-canary requests/min cap is
// charged, once every request that authenticates on any of this mux's
// routes -- not only POST /ingest/events. Charged here rather than in
// each handler because the limit is per canary and this is the one place
// every route shares that already has the resolved identity; handleBatch
// used to charge it itself and no longer does, so a batch is still
// charged exactly once.
//
// hook (issue #47 step 8) is threaded straight through to completeRotation
// below, which is the only place it's ever called -- nil disables the
// first-contact self-test entirely, the same stance handleRotate already
// takes on RotationSucceeded.
//
// dualUse is B4's tracker; nil (some tests) skips the dual-use
// observation and nothing else.
func requireBearerToken(database *db.DB, now func() time.Time, limiters *limiterRegistry, coalescer *auditCoalescer, dualUse *dualUseTracker, hook SelfTestRotationHook, route ingestRoute) http.HandlerFunc {
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

		// Mutual TLS (issue #47 slice 3): a real HTTPS connection through
		// this package's own NewTLSServer, with clientCAs set (as the
		// ingest listener's is), always has r.TLS set and a verified
		// client certificate by the time the handshake completes -- the
		// server-side ClientAuth setting enforces that before any
		// request is even read. This check is what ties that certificate
		// to the bearer token that already resolved above: the
		// certificate's CommonName (internal/ca.SignClient's own
		// convention) must name the same canary. r.TLS == nil is the one
		// exemption, so every existing handler test built on plain
		// httptest.NewRequest keeps working unchanged; a plain HTTP
		// request never reaches a real deployment of this listener in
		// the first place.
		if r.TLS != nil {
			var presentedCN string
			if len(r.TLS.PeerCertificates) > 0 {
				presentedCN = r.TLS.PeerCertificates[0].Subject.CommonName
			}
			if presentedCN != tok.CanaryID {
				recordClientCertMismatch(r.Context(), database, now, tok.CanaryID, presentedCN)
				writeIngestError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
		}

		// Issue #130, ADR-0012 B2 and B3: the certificate must be one
		// birdcage recorded issuing to this canary and has not revoked,
		// whatever its signature, and the token must be bound to it.
		// Inside the r.TLS != nil exemption only because a plain request
		// has no certificate to look up; production's listener always
		// has one (RequireAndVerifyClientCert).
		var presented *store.ClientCert
		if r.TLS != nil {
			if len(r.TLS.PeerCertificates) == 0 {
				// The CN check above already refuses this (an empty CN
				// never names a canary); kept so the index below can
				// never panic whatever that check becomes.
				writeIngestError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			cert, status := checkClientCertificate(r.Context(), database, now, coalescer, tok, r.TLS.PeerCertificates[0])
			if status != 0 {
				msg := "unauthorized"
				if status == http.StatusServiceUnavailable {
					msg = "service unavailable"
				}
				writeIngestError(w, status, msg)
				return
			}
			presented = &cert
		}

		// Kind check 1 of 2, the registry: does this canary's registered
		// kind (tok.Kind, from LookupCanaryTokenByHash's own LEFT JOIN)
		// belong on this route at all? Deliberately unconditional --
		// never nested inside the r.TLS != nil block above, or the
		// httptest exemption that block grants for certificate carriage
		// would double as an authorisation hole for every handler test
		// in this package (issue #106, design note section 7's own
		// trap). A live token whose canaries row is missing resolves
		// with tok.Kind == "" (store.CanaryToken's own doc comment),
		// which kindAllowed refuses here rather than a handler ever
		// seeing it -- deliberate: this route now refuses 403 instead of
		// (for /ingest/heartbeat) reaching handleHeartbeat's own 404 for
		// the same unregistered-canary case.
		if !kindAllowed(route.kinds, tok.Kind) {
			recordKindRefused(r.Context(), database, now, coalescer, tok.CanaryID, tok.Kind, route.pattern, route.kinds)
			writeIngestError(w, http.StatusForbidden, "forbidden")
			return
		}

		// Kind check 2 of 2, the certificate (ADR-0009 decision 3, the
		// defence in depth): when a real client certificate is present,
		// its subject OU must name exactly one registered kind and that
		// kind must equal the registry's own tok.Kind -- never merely
		// "one of the route's allowed kinds", so a tampered registry row
		// disagreeing with the immutable certificate refuses even when
		// both individually look like they'd pass. r.TLS == nil is the
		// same httptest exemption the CN check above takes, for
		// certificate carriage only.
		if r.TLS != nil {
			certKind, ok := certificateKind(r.TLS.PeerCertificates)
			if !ok || certKind != tok.Kind {
				recordKindMismatch(r.Context(), database, now, coalescer, tok.CanaryID, presentedOrganizationalUnit(r.TLS.PeerCertificates))
				writeIngestError(w, http.StatusForbidden, "forbidden")
				return
			}
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
			completeRotation(database, now, tok, r, hook)
		}

		if presented != nil {
			if presented.FirstUsedAt == nil {
				completeRenewal(r.Context(), database, now, *presented)
			}
			if dualUse != nil {
				if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
					if prev, dual := dualUse.observe(presented.Fingerprint, host, false, now().UTC()); dual {
						recordDualUse(r.Context(), database, now, coalescer, tok.CanaryID, store.DualUseAddresses, prev, host)
					}
				}
			}
		}

		if !limiters.allowRequest(tok.CanaryID) {
			recordRateLimitCrossed(r.Context(), database, now, coalescer, tok.CanaryID, "requests/min")
			writeIngestError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		ctx := context.WithValue(r.Context(), canaryTokenCtxKey{}, tok)
		if presented != nil {
			ctx = context.WithValue(ctx, clientCertCtxKey{}, *presented)
		}
		route.handler(w, r.WithContext(ctx))
	}
}

// checkClientCertificate is ADR-0012 B2 and B3's check on the presented
// leaf, for requireBearerToken. It returns the certificate's row, or a
// non-zero status to refuse with: 401 for every credential refusal, 503
// when birdcage's own storage failed (never a 401 for that, the same
// rule the token lookup follows: a 401 sends an agent to re-enrolment).
//
//   - No row for the fingerprint, or a row for another canary: a
//     certificate birdcage did not record issuing to this node --
//     including every certificate from before issue #130, so every such
//     node re-enrols once (ADR-0012, Consequences). ingest.cert_unknown.
//   - A revoked row: ingest.cert_conflict when a successor is live
//     (ADR-0012 B4, "superseded credential still in use"), otherwise a
//     plain 401 -- a node the operator revoked entirely is noise, not a
//     conflict.
//   - A token not bound to it (store.TokenBoundToCert):
//     ingest.token_cert_mismatch.
//
// All three are coalesced: reaching them needs a CA-signed certificate
// and a live token, but a node enrolled before #130 reaches the first on
// every request, and a copy reaches the others on every retry.
func checkClientCertificate(ctx context.Context, database *db.DB, now func() time.Time, coalescer *auditCoalescer, tok store.CanaryToken, leaf *x509.Certificate) (store.ClientCert, int) {
	fp := store.CertFingerprint(leaf.Raw)
	cert, err := store.LookupClientCertByFingerprint(ctx, database, fp)
	if err != nil && !errors.Is(err, store.ErrClientCertNotFound) {
		slog.Error("ingest: client certificate lookup failed", "canary", tok.CanaryID, "err", err)
		return store.ClientCert{}, http.StatusServiceUnavailable
	}
	if err != nil || cert.CanaryID != tok.CanaryID {
		recordCoalesced(ctx, database, now, coalescer, tok.CanaryID, "ingest.cert_unknown",
			fmt.Sprintf("client certificate serial %s is not on record as issued to canary %s", leaf.SerialNumber.Text(16), tok.CanaryID), "presentations")
		return store.ClientCert{}, http.StatusUnauthorized
	}
	if !cert.Live() {
		live, err := store.CanaryHasLiveClientCert(ctx, database, cert.CanaryID)
		if err != nil {
			slog.Error("ingest: check live client certificate failed", "canary", cert.CanaryID, "err", err)
		} else if live {
			recordCoalesced(ctx, database, now, coalescer, cert.CanaryID, "ingest.cert_conflict",
				fmt.Sprintf("revoked client certificate serial %s presented while a successor certificate is live", cert.Serial), "presentations")
		}
		return store.ClientCert{}, http.StatusUnauthorized
	}
	bound, err := store.TokenBoundToCert(ctx, database, tok, cert)
	if err != nil {
		slog.Error("ingest: token binding check failed", "canary", tok.CanaryID, "err", err)
		return store.ClientCert{}, http.StatusServiceUnavailable
	}
	if !bound {
		recordCoalesced(ctx, database, now, coalescer, tok.CanaryID, "ingest.token_cert_mismatch",
			fmt.Sprintf("token %s presented over client certificate serial %s, which it is not bound to", tok.ID, cert.Serial), "presentations")
		return store.ClientCert{}, http.StatusUnauthorized
	}
	return cert, 0
}

// recordCoalesced is the shared shape of every coalesced audit write
// issue #130 adds: admit through coalescer, append on admission, log on
// failure, never change the response.
func recordCoalesced(ctx context.Context, database *db.DB, now func() time.Time, coalescer *auditCoalescer, canaryID, action, reason, noun string) {
	at := now().UTC()
	write, occurrences := coalescer.admit(canaryID, action, at)
	if !write {
		return
	}
	if _, err := audit.Append(ctx, database, audit.Entry{
		Action:      action,
		Target:      canaryID,
		Reason:      coalescedReason(reason, occurrences, noun),
		TriggeredBy: canaryID,
		CreatedAt:   at,
	}); err != nil {
		slog.Error("ingest: record "+action, "canary", canaryID, "err", err)
	}
}

// completeRenewal is ADR-0012 B2's one-way rule, completeRotation's
// certificate twin: the first authenticated use of a certificate
// revokes every older certificate of its canary. When that revoked
// anything this was a renewal completing, audited ingest.cert_renewed;
// a canary's first certificate revokes nothing and its first use is
// already audited as ingest.token_first_use. Errors are logged, never
// turned into a refusal: the request is already fully authenticated.
func completeRenewal(ctx context.Context, database *db.DB, now func() time.Time, cert store.ClientCert) {
	at := now().UTC()
	first, revoked, err := store.RecordClientCertFirstUse(ctx, database, cert, at)
	if err != nil {
		slog.Error("ingest: record certificate first use failed", "canary", cert.CanaryID, "err", err)
		return
	}
	if !first || revoked == 0 {
		return
	}
	if _, err := audit.Append(ctx, database, audit.Entry{
		Action:      "ingest.cert_renewed",
		Target:      cert.CanaryID,
		Reason:      fmt.Sprintf("first use of client certificate serial %s revoked %d older certificate(s)", cert.Serial, revoked),
		TriggeredBy: cert.CanaryID,
		CreatedAt:   at,
	}); err != nil {
		slog.Error("ingest: record completed renewal", "canary", cert.CanaryID, "err", err)
	}
}

// kindAllowed reports whether k is one of allowed -- the registry kind
// check's own comparison (issue #106). k == "" (a token whose canaries
// row is missing, or was never given a kind) never matches, since
// allowed only ever holds registered kinds.
func kindAllowed(allowed []agentkind.Kind, k agentkind.Kind) bool {
	for _, a := range allowed {
		if a == k {
			return true
		}
	}
	return false
}

// certificateKind extracts the single registered kind a peer
// certificate's subject OU carries (issue #106, design note section 1):
// ok is false for any shape other than exactly one registered value --
// zero (every pre-#106 certificate), more than one, or a string
// agentkind.Valid rejects. Never a "contains" check over the slice.
func certificateKind(certs []*x509.Certificate) (agentkind.Kind, bool) {
	if len(certs) == 0 {
		return "", false
	}
	ou := certs[0].Subject.OrganizationalUnit
	if len(ou) != 1 {
		return "", false
	}
	k := agentkind.Kind(ou[0])
	return k, agentkind.Valid(k)
}

// presentedOrganizationalUnit reads back the raw OU value(s) a peer
// certificate presented, for recordKindMismatch's audit reason -- a
// certificate subject, safe to log verbatim, matching
// recordClientCertMismatch's own stance on the presented CN. Returns nil
// (renders as "[]") when there is no certificate to read at all.
func presentedOrganizationalUnit(certs []*x509.Certificate) []string {
	if len(certs) == 0 {
		return nil
	}
	return certs[0].Subject.OrganizationalUnit
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

// recordClientCertMismatch writes ingest.client_cert_mismatch (issue #47
// slice 3): the bearer token resolved to canaryID, but the TLS
// connection's client certificate either named a different canary or
// (presentedCN == "") presented no certificate at all -- unreachable in
// production against a real ClientAuth: RequireAndVerifyClientCert
// listener, but defended anyway. Reason names the presented CN, which is
// a certificate subject, not a secret, so it is safe to log and audit
// verbatim -- unlike the bearer token or enrolment secret, neither of
// which this package's audit entries ever include.
func recordClientCertMismatch(ctx context.Context, database *db.DB, now func() time.Time, canaryID, presentedCN string) {
	reason := fmt.Sprintf("bearer token resolved to canary %s but the presented client certificate CN was %q", canaryID, presentedCN)
	if _, err := audit.Append(ctx, database, audit.Entry{
		Action:      "ingest.client_cert_mismatch",
		Target:      canaryID,
		Reason:      reason,
		TriggeredBy: canaryID,
		CreatedAt:   now().UTC(),
	}); err != nil {
		slog.Error("ingest: record client cert mismatch", "canary", canaryID, "err", err)
	}
}

// recordKindRefused writes ingest.kind_refused (issue #106): canaryID's
// registered kind is not among the kinds route allows -- a honeypot
// posting to the scanner's route, or the reverse. Routed through
// coalescer like every other caller-triggered write in this file:
// reaching this check costs nothing but a live token, so an attacker
// holding one honeypot's credential could otherwise flood audit_log for
// the price of retrying its own (correctly refused) requests --
// auditcoalesce.go's own rationale.
func recordKindRefused(ctx context.Context, database *db.DB, now func() time.Time, coalescer *auditCoalescer, canaryID string, kind agentkind.Kind, route string, allowed []agentkind.Kind) {
	at := now().UTC()
	write, occurrences := coalescer.admit(canaryID, "ingest.kind_refused", at)
	if !write {
		return
	}

	reason := fmt.Sprintf("canary %s (kind %q) posted to %s, which allows kind(s) %s", canaryID, kind, route, formatKinds(allowed))
	if _, err := audit.Append(ctx, database, audit.Entry{
		Action:      "ingest.kind_refused",
		Target:      canaryID,
		Reason:      coalescedReason(reason, occurrences, "refusals"),
		TriggeredBy: canaryID,
		CreatedAt:   at,
	}); err != nil {
		slog.Error("ingest: record kind refusal", "canary", canaryID, "route", route, "err", err)
	}
}

// recordKindMismatch writes ingest.kind_mismatch (issue #106): the
// certificate on this connection did not carry exactly one registered
// kind equal to the registry's own tok.Kind -- a legacy pre-#106
// certificate (no OU at all), a malformed one (more than one OU), an
// unregistered string, or one that simply disagrees with what the
// database says this canary is. presentedOU is logged verbatim -- a
// certificate subject, safe to log and audit, matching
// recordClientCertMismatch's own stance on the presented CN. Coalesced
// for the same reason recordKindRefused is.
func recordKindMismatch(ctx context.Context, database *db.DB, now func() time.Time, coalescer *auditCoalescer, canaryID string, presentedOU []string) {
	at := now().UTC()
	write, occurrences := coalescer.admit(canaryID, "ingest.kind_mismatch", at)
	if !write {
		return
	}

	reason := fmt.Sprintf("certificate for canary %s carries organizational unit %v, want exactly one value naming its registered kind", canaryID, presentedOU)
	if _, err := audit.Append(ctx, database, audit.Entry{
		Action:      "ingest.kind_mismatch",
		Target:      canaryID,
		Reason:      coalescedReason(reason, occurrences, "presentations"),
		TriggeredBy: canaryID,
		CreatedAt:   at,
	}); err != nil {
		slog.Error("ingest: record kind mismatch", "canary", canaryID, "err", err)
	}
}

// formatKinds renders a route's allowed kinds for an audit reason, e.g.
// "honeypot, scanner" -- never Go's %v slice syntax, which would read
// like a debug dump rather than prose.
func formatKinds(kinds []agentkind.Kind) string {
	strs := make([]string, len(kinds))
	for i, k := range kinds {
		strs[i] = string(k)
	}
	return strings.Join(strs, ", ")
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
//
// r and hook are issue #47 step 8's addition, used only inside that same
// no-older-tokens branch: revoked == 0 can only mean tok is the canary's
// first token and this is that token's first use, which happens at most
// once per canary's lifetime -- exactly "the first successful mTLS
// request from that canary after provisioning" #47 asks for. r's own
// source address is recorded as this canary's last-seen address (the
// same store.SetCanaryLastSeenAddr internal/ingest/heartbeat.go's own
// last-seen write uses) before the hook fires, so the self-test scheduler
// has an address to probe before any heartbeat has ever landed; an
// ordinary heartbeat overwrites it moments later with the same or an
// updated value regardless, so this is a harmless head start, not a new
// source of truth for the field. hook is nil in every test in this
// package and any deployment that hasn't started a scheduler, and its
// call must never affect this request's own response either way -- any
// error inside it is the hook's own to log, the same contract
// handleRotate's own RotationSucceeded call already keeps.
func completeRotation(database *db.DB, now func() time.Time, tok store.CanaryToken, r *http.Request, hook SelfTestRotationHook) {
	ctx := r.Context()
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
		if hook != nil {
			recordLastSeenAddr(r, database, tok.CanaryID)
			hook.FirstContact(ctx, tok.CanaryID, now().UTC())
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
