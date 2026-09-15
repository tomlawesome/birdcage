package ingest

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/store"
)

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

	writeJSON(w, http.StatusOK, rotateResponse{Token: raw})
}
