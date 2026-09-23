package ingest

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/store"
)

// SelfTestRotationHook lets an external scheduler (internal/selftestsched,
// issue #46 item 5c) learn the instant a canary's token rotation
// succeeds, so it can mint a self-test command immediately for a canary
// using the "same schedule as key rotation" setting. A structural
// interface, not a concrete type: internal/ingest never imports
// internal/selftestsched (which would need to import internal/ingest
// back, for this very type), and internal/selftestsched never imports
// internal/ingest either -- cmd/birdcage's main is the only thing that
// knows both packages, and it hands the handler something satisfying
// this method (or leaves it nil).
//
// RotationSucceeded must not block or fail handleRotate's own response:
// it is called after the rotation has already committed, and any error
// it hits is the hook's own to log.
//
// FirstContact (issue #47 step 8) is this interface's second method,
// added without touching the first: it fires once per canary, from
// requireBearerToken's completeRotation (auth.go), the instant the very
// first authenticated request from a newly provisioned canary lands --
// "first use of a canary's first token", the same branch that already
// writes the ingest.token_first_use audit entry. Unlike RotationSucceeded
// it is never gated on selftest_enabled or the rotation-coupled schedule
// setting: enrolment proof is not the daily self-test schedule. Same
// contract as RotationSucceeded otherwise -- must not block or fail the
// request it rides in on, and any error it hits is the hook's own to log.
type SelfTestRotationHook interface {
	RotationSucceeded(ctx context.Context, canaryID string, at time.Time)
	FirstContact(ctx context.Context, canaryID string, at time.Time)
}

// rotateResponse is POST /ingest/rotate's response body: the freshly
// minted raw token, shown here and never again -- issue #32's "the raw
// token is shown once at mint and never stored" applies to a rotation
// mint exactly as it does to the first one.
type rotateResponse struct {
	Token string `json:"token"`
}

// handleRotate serves POST /ingest/rotate, reached only through
// requireBearerToken with the agent's CURRENT token. It mints a fresh
// token for the same canary and returns it; the presented token is left
// completely untouched here. Issue #32's fail-closed rule: "rotation
// failure at any point before the new token's first use leaves the old
// token live -- birdcage must never strip an agent of its only working
// credential by failing." Revocation happens later and elsewhere, in
// requireBearerToken's completeRotation, the moment the new token is
// first used for anything on this mux (including a second call here) --
// not at mint time, and not only on this route.
//
// The mint and its audit entry (item 10: "every mint ... written to the
// audit log. A mint or revoke whose audit write fails, fails with it")
// run in one transaction, not mint-then-undo: if the audit append fails,
// the whole transaction rolls back, so the newly minted token was never
// actually persisted and can never be looked up or used -- a stronger
// guarantee than revoking it after the fact, and simpler, since there is
// no revoke-then-fail-again window to reason about. Either way the
// presented token (tok) is never touched by this handler, so a failure
// here never costs the agent its only working credential.
func (h *ingestHandler) handleRotate(w http.ResponseWriter, r *http.Request) {
	tok, ok := canaryTokenFromContext(r.Context())
	if !ok {
		// requireBearerToken wraps every route on this mux; reaching here
		// without it is a wiring bug, not a client error. Fail closed.
		slog.Error("ingest: handleRotate reached without a canary token in context")
		writeIngestError(w, http.StatusInternalServerError, "internal error")
		return
	}

	tx, err := h.db.Begin(r.Context())
	if err != nil {
		slog.Error("ingest: begin rotate transaction failed", "canary", tok.CanaryID, "err", err)
		writeIngestError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rerr := tx.Rollback(); rerr != nil && !errors.Is(rerr, sql.ErrTxDone) {
			slog.Error("ingest: rollback rotate transaction failed", "canary", tok.CanaryID, "err", rerr)
		}
	}()

	raw, newTok, err := store.MintCanaryToken(r.Context(), tx, tok.CanaryID, h.now().UTC())
	if err != nil {
		// A mint failure is birdcage's own storage trouble, not the
		// credential's fault -- the presented token (tok) remains fully
		// valid and unaffected by this failure either way. 503 tells the
		// agent to retry the rotation later; it has no reason to believe
		// its current token stopped working.
		slog.Error("ingest: mint rotated token failed", "canary", tok.CanaryID, "err", err)
		writeIngestError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}

	if _, err := audit.Append(r.Context(), tx, audit.Entry{
		Action:      "ingest.token_minted",
		Target:      tok.CanaryID,
		Reason:      "rotation minted a new token",
		TriggeredBy: tok.CanaryID,
		CreatedAt:   h.now().UTC(),
	}); err != nil {
		// Fail-closed per item 10: the mint fails with its audit write.
		// The deferred rollback above undoes the insert above, so newTok
		// is never actually stored and can never be looked up -- the
		// agent gets 503 and keeps using tok, exactly as a mint failure
		// itself would be handled above.
		slog.Error("ingest: record token mint failed; rotation aborted", "canary", tok.CanaryID, "new_token_id", newTok.ID, "err", err)
		writeIngestError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}

	if err := tx.Commit(); err != nil {
		slog.Error("ingest: commit rotate transaction failed", "canary", tok.CanaryID, "err", err)
		writeIngestError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	committed = true

	// Issue #46 item 5c: the rotation-coupled self-test schedule mints
	// immediately after a rotation succeeds, not on a tick -- this is
	// that hook. Nil when no scheduler was wired in (every test in this
	// package, and any deployment that hasn't started one), in which
	// case it is simply skipped; never lets a self-test concern affect
	// this response either way.
	if h.rotationHook != nil {
		h.rotationHook.RotationSucceeded(r.Context(), tok.CanaryID, h.now().UTC())
	}

	writeJSON(w, http.StatusOK, rotateResponse{Token: raw})
}
