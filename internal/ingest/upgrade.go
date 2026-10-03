package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/store"
)

// Issue #54's upgrade token on the ingest side (ADR-0012's B4
// amendment). The upgrade command runs the new agent image's
// `upgrade-token` subcommand once, after the old agent is removed and
// before the new one starts, against the agent's own state volume
// (mounted read-only). It presents the token here over the agent's own
// mTLS certificate and bearer token -- so the credential, not the body,
// names the agent -- and birdcage opens the five-minute window before
// the new build's first heartbeat can report its version. That ordering
// is the whole reason this is a route of its own, run by a one-shot
// process, rather than a field on the new agent's heartbeat or a step
// after it starts: B4 observes the version on that first heartbeat, so a
// window opened any later would open after the flag.

// upgradeTokenMaxBodyBytes bounds the body: one 64-character token in a
// one-field object.
const upgradeTokenMaxBodyBytes = 1024

// ingestUpgradeToken is POST /ingest/upgrade-token's body.
type ingestUpgradeToken struct {
	UpgradeToken string `json:"upgrade_token"`
}

// ingestUpgradeTokenResponse is its answer. Outcome is "accepted" or
// "refused"; Reason says why a refusal was one (store.UpgradeTokenOutcome's
// wording -- the presenter already holds this agent's credential, and
// "expired" or "already used" is what the operator running the command
// needs to read) but never names another agent. WindowUntil is set on
// acceptance only.
type ingestUpgradeTokenResponse struct {
	Outcome     string `json:"outcome"`
	Reason      string `json:"reason,omitempty"`
	WindowUntil string `json:"window_until,omitempty"`
}

// handleUpgradeToken serves POST /ingest/upgrade-token, reached only
// through requireBearerToken, which resolved tok from the credential.
// Every refusal is a 200 with outcome "refused": the request itself was
// well formed and authenticated, and the subcommand needs an answer to
// print, not a retry. 400 is kept for a body that is not the one-field
// object; 503 for birdcage's own storage trouble, which the subcommand
// retries.
func (h *ingestHandler) handleUpgradeToken(w http.ResponseWriter, r *http.Request) {
	tok, ok := canaryTokenFromContext(r.Context())
	if !ok {
		slog.Error("ingest: handleUpgradeToken reached without a canary token in context")
		writeIngestError(w, http.StatusInternalServerError, "internal error")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, upgradeTokenMaxBodyBytes)
	var body ingestUpgradeToken
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeIngestError(w, http.StatusBadRequest, "malformed upgrade token body")
		return
	}
	if dec.More() {
		writeIngestError(w, http.StatusBadRequest, "malformed upgrade token body: trailing data")
		return
	}

	now := h.now().UTC()
	res, err := store.PresentUpgradeToken(r.Context(), h.db, tok.CanaryID, body.UpgradeToken, now)
	if err != nil {
		slog.Error("ingest: settle upgrade token", "canary", tok.CanaryID, "err", err)
		writeIngestError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}

	if res.Outcome == store.UpgradeTokenAccepted {
		if _, err := audit.Append(r.Context(), h.db, audit.Entry{
			Action: "ingest.upgrade_token_accepted",
			Target: tok.CanaryID,
			Reason: fmt.Sprintf("upgrade window open until %s: agent builds %q and %q on this credential are not credential_conflict until then",
				res.WindowUntil.Format(time.RFC3339), res.FromVersion, res.ToVersion),
			TriggeredBy: tok.CanaryID,
			CreatedAt:   now,
		}); err != nil {
			slog.Error("ingest: record upgrade token acceptance", "canary", tok.CanaryID, "err", err)
		}
		writeJSON(w, http.StatusOK, ingestUpgradeTokenResponse{
			Outcome:     "accepted",
			WindowUntil: res.WindowUntil.Format(time.RFC3339),
		})
		return
	}

	reason := "upgrade token refused: " + res.Outcome.String()
	if res.Outcome == store.UpgradeTokenWrongAgent {
		reason += " (" + res.TokenCanaryID + ")"
	}
	reason += "; no upgrade window opened"
	h.recordKeyedAudit(r.Context(), tok.CanaryID, "ingest.upgrade_token_refused",
		"ingest.upgrade_token_refused:"+res.Outcome.String(), reason, "presentations")
	writeJSON(w, http.StatusOK, ingestUpgradeTokenResponse{Outcome: "refused", Reason: res.Outcome.String()})
}

// recordKeyedAudit is recordSelfTestAudit with a coalescer key separate
// from the action, so one action's different reasons are coalesced
// separately rather than the first reason standing for all of them.
// Used for every audit row a holder of one credential can cause once
// per request.
func (h *ingestHandler) recordKeyedAudit(ctx context.Context, canaryID, action, key, reason, noun string) {
	at := h.now().UTC()
	write, occurrences := h.coalescer.admit(canaryID, key, at)
	if !write {
		return
	}
	if _, err := audit.Append(ctx, h.db, audit.Entry{
		Action:      action,
		Target:      canaryID,
		Reason:      coalescedReason(reason, occurrences, noun),
		TriggeredBy: canaryID,
		CreatedAt:   at,
	}); err != nil {
		slog.Error("ingest: record audit entry", "canary", canaryID, "action", action, "err", err)
	}
}
