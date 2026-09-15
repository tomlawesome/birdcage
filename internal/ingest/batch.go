package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/store"
)

const (
	// maxBodyBytes is the ingest batch body cap, issue #32 item 8's own
	// arithmetic: 60,000 events/min at 3,000 requests/min averages 20
	// events per request, with 1-2 KiB of `raw` per event, "so the cap
	// is a few hundred KiB, not the 64 KiB the single-event plan
	// assumed". 300 KiB covers maxEventsPerBatch events at up to ~3 KiB
	// of raw each, comfortably inside "a few hundred KiB" with headroom
	// for JSON structure overhead.
	maxBodyBytes = 300 * 1024

	// maxEventsPerBatch bounds one batch's event count well above the
	// ~20-60/request the same arithmetic implies is typical, so a
	// legitimate agent never trips it while a hostile one can't use a
	// single request to force birdcage to loop over an unbounded slice.
	maxEventsPerBatch = 100
)

// eventIDPattern is issue #32 item 8 / research #4's exact rule: "event_id
// is validated as exactly 64 lowercase hex characters; anything else is a
// per-event rejection." Without this the field is an arbitrary-string
// sink into an indexed column (alerts.event_id).
var eventIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

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
// (so DisallowUnknownFields doesn't reject a caller that sends it) but
// never trusted as identity -- see handleBatch's comparison against the
// token's own canary id (issue #32: "a payload naming another canary is
// ignored and logged, never trusted").
type ingestBatch struct {
	NodeID string        `json:"node_id,omitempty"`
	Events []ingestEvent `json:"events"`
}

// ackResponse is POST /ingest/events' response body: every event id in
// the batch is either stored (including a duplicate, which acks as
// stored -- idempotent success) or rejected with a reason, keyed by the
// id the client sent even when that id itself is what's invalid, so the
// agent can always match a rejection back to the event it sent. An id
// present in neither list got no ack at all -- issue #32's "infra error
// is never a rejection; uncertainty resolves to no ack" -- and the agent
// retries it, which the dedup index makes free.
type ackResponse struct {
	Stored   []string          `json:"stored"`
	Rejected map[string]string `json:"rejected"`
}

// handleBatch serves POST /ingest/events, reached only through
// requireBearerToken. Order of operations matters: the per-canary
// request-rate limit is checked before the body is even read (bounding
// the cost of a request this handler will reject anyway), the body cap
// and envelope shape are enforced next, then the per-canary event-rate
// limit (now that the batch's size is known), and only then does any
// individual event reach validation or storage.
func (h *ingestHandler) handleBatch(w http.ResponseWriter, r *http.Request) {
	tok, ok := canaryTokenFromContext(r.Context())
	if !ok {
		// requireBearerToken wraps every route on this mux; reaching here
		// without it is a wiring bug, not a client error. Fail closed.
		slog.Error("ingest: handleBatch reached without a canary token in context")
		writeIngestError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if !h.limiters.allowRequest(tok.CanaryID) {
		h.recordLimitCrossed(r.Context(), tok.CanaryID, "requests/min")
		writeIngestError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var batch ingestBatch
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&batch); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeIngestError(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		writeIngestError(w, http.StatusBadRequest, "malformed batch body")
		return
	}
	if dec.More() {
		writeIngestError(w, http.StatusBadRequest, "malformed batch body: trailing data")
		return
	}
	if len(batch.Events) == 0 {
		writeIngestError(w, http.StatusBadRequest, "batch must contain at least one event")
		return
	}
	if len(batch.Events) > maxEventsPerBatch {
		writeIngestError(w, http.StatusBadRequest, fmt.Sprintf("batch exceeds %d events", maxEventsPerBatch))
		return
	}

	if batch.NodeID != "" && batch.NodeID != tok.CanaryID {
		// Never trusted as identity -- logged and otherwise ignored
		// (issue #32: "a payload node_id that disagrees is ignored and
		// logged, never trusted").
		slog.Warn("ingest: payload named a different canary than its token; ignoring",
			"token_canary", tok.CanaryID, "payload_node_id", batch.NodeID)
	}

	if !h.limiters.allowEvents(tok.CanaryID, len(batch.Events)) {
		h.recordLimitCrossed(r.Context(), tok.CanaryID, "events/min")
		writeIngestError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	resp := ackResponse{Stored: []string{}, Rejected: map[string]string{}}
	receivedAt := h.now().UTC()
	noAck := 0
	for _, ev := range batch.Events {
		if reason, ok := validateEvent(ev); !ok {
			resp.Rejected[ev.EventID] = reason
			continue
		}

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
			// An infrastructure failure is never turned into a rejection
			// (issue #32 fail-closed): this id gets no ack at all, and
			// the agent's retry is free because of the dedup index.
			slog.Error("ingest: insert alert failed; no ack, agent will retry",
				"canary", tok.CanaryID, "event_id", ev.EventID, "err", err)
			noAck++
			continue
		}

		resp.Stored = append(resp.Stored, ev.EventID)
		if stored && h.hub != nil {
			h.hub.PublishAlert(insert)
		}
	}

	if noAck > 0 && noAck == len(batch.Events) {
		// Every event in the batch hit an infrastructure failure: a
		// whole-request failure, which issue #32's fail-closed rule
		// answers with 5xx (retry), not a 200 whose ack lists are both
		// empty.
		writeIngestError(w, http.StatusServiceUnavailable, "storage unavailable")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// validateEvent applies issue #32 item 8's per-field validation. reason
// is empty and ok is true when ev passes every check.
func validateEvent(ev ingestEvent) (reason string, ok bool) {
	if !eventIDPattern.MatchString(ev.EventID) {
		return "invalid event_id", false
	}
	if net.ParseIP(ev.SourceIP) == nil {
		return "invalid source_ip", false
	}
	if ev.DestPort < 1 || ev.DestPort > 65535 {
		return "invalid dest_port", false
	}
	if ev.Service == "" {
		return "service must not be empty", false
	}
	return "", true
}

// recordLimitCrossed writes an audit entry for a rate limit crossing
// (issue #32: "crossing a limit is recorded and surfaced, never a silent
// discard"). Surfacing it on the dashboard is #45's job; this is the
// durable record #45 will read. A failure to write it is logged but
// never turned into a different response to the client -- the 429 the
// caller already got stands regardless.
func (h *ingestHandler) recordLimitCrossed(ctx context.Context, canaryID, limit string) {
	_, err := audit.Append(ctx, h.db, audit.Entry{
		Action:      "ingest.rate_limited",
		Target:      canaryID,
		Reason:      limit + " limit exceeded",
		TriggeredBy: canaryID,
		CreatedAt:   h.now().UTC(),
	})
	if err != nil {
		slog.Error("ingest: record rate limit crossing", "canary", canaryID, "limit", limit, "err", err)
	}
}
