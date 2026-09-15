package ingest

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/tomlawesome/birdcage/internal/store"
)

// ingestEvent is one event in a batch's `events` array. Field names are
// birdcage's own choice: the wire format OpenCanary's agent (#48) will
// actually send is that issue's to pin, not yet built as of this slice,
// so this shape mirrors store.AlertInsert's existing fields (minus
// InstanceID and ReceivedAt, both identity/timestamp values issue #32
// says must never come from the payload -- see ingestBatch.NodeID and
// handleBatch's use of h.now()).
type ingestEvent struct {
	EventID  string `json:"event_id"`
	SourceIP string `json:"source_ip"`
	DestPort int    `json:"dest_port"`
	Service  string `json:"service"`
	Raw      string `json:"raw"`
}

// ingestBatch is POST /ingest/events' request body. NodeID is accepted
// but never trusted as identity -- see handleBatch's comparison against
// the token's own canary id (issue #32: "a payload naming another canary
// is ignored and logged, never trusted").
//
// This slice's decoding is deliberately minimal -- no body size cap, no
// DisallowUnknownFields, no per-event validation, no rate limiting.
// Issue #32 slice 3 ("batch body, validation, limits") is exactly those
// four; this slice is only the endpoint and its auth.
type ingestBatch struct {
	NodeID string        `json:"node_id,omitempty"`
	Events []ingestEvent `json:"events"`
}

// ackResponse is POST /ingest/events' response body: the ids stored.
// Rejection and the full three-way ack vocabulary (issue #32 item 4)
// arrive with slice 3's validation and slice 4's identity-binding work.
type ackResponse struct {
	Stored []string `json:"stored"`
}

// handleBatch serves POST /ingest/events, reached only through
// requireBearerToken -- so tok is always present and always the
// authenticated caller's own identity, never anything the payload
// claims.
func (h *ingestHandler) handleBatch(w http.ResponseWriter, r *http.Request) {
	tok, ok := canaryTokenFromContext(r.Context())
	if !ok {
		// requireBearerToken wraps every route on this mux; reaching here
		// without it is a wiring bug, not a client error. Fail closed.
		slog.Error("ingest: handleBatch reached without a canary token in context")
		writeIngestError(w, http.StatusInternalServerError, "internal error")
		return
	}

	var batch ingestBatch
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		writeIngestError(w, http.StatusBadRequest, "malformed batch body")
		return
	}
	if batch.NodeID != "" && batch.NodeID != tok.CanaryID {
		// Never trusted as identity -- logged and otherwise ignored
		// (issue #32: "a payload node_id that disagrees is ignored and
		// logged, never trusted").
		slog.Warn("ingest: payload named a different canary than its token; ignoring",
			"token_canary", tok.CanaryID, "payload_node_id", batch.NodeID)
	}

	resp := ackResponse{Stored: []string{}}
	receivedAt := h.now().UTC()
	for _, ev := range batch.Events {
		insert := store.AlertInsert{
			InstanceID: tok.CanaryID, // identity from the token, never the payload
			SourceIP:   ev.SourceIP,
			DestPort:   ev.DestPort,
			Service:    ev.Service,
			Raw:        ev.Raw,
			ReceivedAt: receivedAt, // birdcage's own receipt time, never agent-supplied
			EventID:    ev.EventID,
		}
		stored, err := store.InsertAlertIfNew(r.Context(), h.db, insert)
		if err != nil {
			slog.Error("ingest: insert alert failed; no ack, agent will retry",
				"canary", tok.CanaryID, "event_id", ev.EventID, "err", err)
			continue
		}
		resp.Stored = append(resp.Stored, ev.EventID)
		if stored && h.hub != nil {
			h.hub.PublishAlert(insert)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
