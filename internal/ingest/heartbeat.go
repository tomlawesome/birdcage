package ingest

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/tomlawesome/birdcage/internal/store"
)

// heartbeatMaxBodyBytes bounds the ingest heartbeat body -- far smaller
// than a batch's, since this is a handful of scalar self-report fields,
// never a list of events.
const heartbeatMaxBodyBytes = 4 * 1024

// ingestHeartbeat is POST /ingest/heartbeat's body (issue #32 slice 5a):
// the agent's own self-report (#48), which is what #45's "not
// delivering" state stands on since birdcage never connects to the
// agent to check on it directly. CanaryID is accepted (so
// DisallowUnknownFields doesn't reject a caller that sends it) but never
// trusted as identity -- see handleHeartbeat's comparison against the
// token's own canary id, mirroring ingestBatch.NodeID in batch.go.
//
// Dropped, Rejected, EventIDCollisions and PositionFound (#48's
// process-composition note, gap 3) are pointers, not plain values, on
// purpose: an agent built before this change -- or mid-rollout -- sends
// the original four fields only, and DisallowUnknownFields below still
// accepts that body. A pointer left nil by json.Decode because the field
// was absent must never be treated the same as one explicitly set to
// zero/false -- zero dropped is good news, absent is no news. See
// handleHeartbeat's construction of store.AgentHeartbeat, which carries
// that same nil-vs-value distinction into storage.
type ingestHeartbeat struct {
	CanaryID          string `json:"canary_id,omitempty"`
	QueueDepth        int    `json:"queue_depth"`
	LogReadOK         bool   `json:"log_read_ok"`
	LastEventID       string `json:"last_event_id,omitempty"`
	AgentVersion      string `json:"agent_version,omitempty"`
	Dropped           *int64 `json:"dropped,omitempty"`
	Rejected          *int64 `json:"rejected,omitempty"`
	EventIDCollisions *int64 `json:"event_id_collisions,omitempty"`
	PositionFound     *bool  `json:"position_found,omitempty"`
}

// handleHeartbeat serves POST /ingest/heartbeat, reached only through
// requireBearerToken. Issue #32 item 6 (owner, 2026-09-14): heartbeat
// moves off the dashboard's human-auth seam onto this submux,
// authenticated by the canary token, identity from the token. The
// dashboard's POST /api/heartbeat (internal/api/handlers.go) is left
// exactly as it is -- see this file's package doc and the commit message
// for what still depends on it -- this is a second, independent write
// path onto the same canaries/heartbeats registry.
//
// Fail-closed (issue #32): an invalid body is a 4xx and the canary's
// last-seen does NOT advance -- a broken agent must look broken, never
// healthy. That falls out of the ordering below: store.RecordCanaryAgentHeartbeat
// is only ever reached after the body has decoded cleanly.
func (h *ingestHandler) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	tok, ok := canaryTokenFromContext(r.Context())
	if !ok {
		slog.Error("ingest: handleHeartbeat reached without a canary token in context")
		writeIngestError(w, http.StatusInternalServerError, "internal error")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, heartbeatMaxBodyBytes)
	var body ingestHeartbeat
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeIngestError(w, http.StatusBadRequest, "malformed heartbeat body")
		return
	}
	if dec.More() {
		writeIngestError(w, http.StatusBadRequest, "malformed heartbeat body: trailing data")
		return
	}

	if body.CanaryID != "" && body.CanaryID != tok.CanaryID {
		// Never trusted as identity, exactly like ingestBatch.NodeID
		// (issue #32: "the canary is the token's, whatever the body
		// says").
		slog.Warn("ingest: heartbeat payload named a different canary than its token; ignoring",
			"token_canary", tok.CanaryID, "payload_canary_id", body.CanaryID)
	}

	report := store.AgentHeartbeat{
		QueueDepth:        body.QueueDepth,
		LogReadOK:         body.LogReadOK,
		LastEventID:       body.LastEventID,
		AgentVersion:      body.AgentVersion,
		Dropped:           body.Dropped,
		Rejected:          body.Rejected,
		EventIDCollisions: body.EventIDCollisions,
		PositionFound:     body.PositionFound,
	}
	if err := store.RecordCanaryAgentHeartbeat(r.Context(), h.db, tok.CanaryID, h.now().UTC(), report); err != nil {
		if errors.Is(err, store.ErrCanaryNotFound) {
			// Mirrors internal/api's own handleHeartbeat: a live token
			// implies the canary_tokens row exists, but that table
			// carries no foreign key into canaries (0004's own comment),
			// so an unregistered canary id is a real, if unusual, state
			// -- not birdcage's own storage trouble.
			writeIngestError(w, http.StatusNotFound, "unknown canary")
			return
		}
		slog.Error("ingest: record agent heartbeat failed", "canary", tok.CanaryID, "err", err)
		writeIngestError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
