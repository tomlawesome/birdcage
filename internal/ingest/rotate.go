package ingest

import (
	"log/slog"
	"net/http"

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
func (h *ingestHandler) handleRotate(w http.ResponseWriter, r *http.Request) {
	tok, ok := canaryTokenFromContext(r.Context())
	if !ok {
		// requireBearerToken wraps every route on this mux; reaching here
		// without it is a wiring bug, not a client error. Fail closed.
		slog.Error("ingest: handleRotate reached without a canary token in context")
		writeIngestError(w, http.StatusInternalServerError, "internal error")
		return
	}

	raw, _, err := store.MintCanaryToken(r.Context(), h.db, tok.CanaryID, h.now().UTC())
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

	writeJSON(w, http.StatusOK, rotateResponse{Token: raw})
}
