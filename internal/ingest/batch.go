package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"time"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/opencanary"
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

	// SelfTestMarker is #46 slice 3's one addition to the wire: an
	// attributed-grade claim (ntp, portscan) the agent made locally,
	// before this event ever left the canary (note 19897 -- see
	// cmd/mockingbird/claim.go). Optional and empty for every other
	// event, exactly like Raw it carries no dedicated length bound of
	// its own -- both ride on maxBodyBytes and maxEventsPerBatch, the
	// batch's own caps, since a marker that is simply too long to match
	// anything is no more dangerous than one that is merely wrong (it is
	// refused by store.MatchSelfTestClaim the same way).
	SelfTestMarker string `json:"self_test_marker,omitempty"`
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
// requireBearerToken, which has already charged this request against
// the per-canary request-rate limit (issue #32 item 8) before dispatching
// here -- charging it again in this handler would double-count a single
// request against that cap, so this handler's own limit check is only
// the per-canary event-rate limit, once the batch's size is known: the
// body cap and envelope shape are enforced first, then events/min, and
// only then does any individual event reach validation or storage.
func (h *ingestHandler) handleBatch(w http.ResponseWriter, r *http.Request) {
	tok, ok := canaryTokenFromContext(r.Context())
	if !ok {
		// requireBearerToken wraps every route on this mux; reaching here
		// without it is a wiring bug, not a client error. Fail closed.
		slog.Error("ingest: handleBatch reached without a canary token in context")
		writeIngestError(w, http.StatusInternalServerError, "internal error")
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
		recordRateLimitCrossed(r.Context(), h.db, h.now, h.coalescer, tok.CanaryID, "events/min")
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

		service := ev.Service
		if service == "" {
			// Issue #53: an empty service is not genuine rubbish -- the
			// parser (parse.go's serviceForLogType) has always stored
			// "unknown" rather than reject, and the agent that computes
			// this field itself (#48) may leave it unset the same way.
			service = "unknown"
		}

		if opencanary.IsBase(service) {
			// Issue #117: OpenCanary's own start-up lines (logtype
			// 1000-1006, service "base") are forwarded by the agent --
			// #65 will use them later to know which modules started --
			// but birdcage owns the filter: they ack like any other
			// stored event, so the agent's queue drains, but are never
			// persisted as an alert or counted in a canary's hits. Never
			// self-test matched either: a start-up line is never the
			// marker MatchSelfTest or MatchSelfTestClaim is looking for.
			slog.Info("ingest: skipping OpenCanary start-up line", "canary", tok.CanaryID, "event_id", ev.EventID, "message", ev.Raw)
			resp.Stored = append(resp.Stored, ev.EventID)
			continue
		}

		insert := store.AlertInsert{
			InstanceID: tok.CanaryID, // identity from the token, never the payload
			SourceIP:   ev.SourceIP,
			DestPort:   ev.DestPort,
			Service:    service,
			Raw:        ev.Raw,
			ReceivedAt: receivedAt, // birdcage's own receipt time, never agent-supplied
			EventID:    ev.EventID,
		}

		// Issue #46 item 3: every event is checked against the live
		// self-test index before it is stored, so a marker birdcage
		// itself planted is recorded as synthetic rather than a real
		// hit. A MatchSelfTest error (a failure recording the match,
		// not a "no match") is logged and the event falls through to
		// storing as real -- "on any error: log, store the alert as
		// real, continue. Never drop" (brief for this slice): losing
		// the self-test/real distinction on a bookkeeping failure is
		// far cheaper than losing the event entirely.
		//
		// #46 slice 3: an event carrying self_test_marker is an
		// attributed-grade claim the agent made locally (note 19897) --
		// corroborated independently by MatchSelfTestClaim, never taken
		// on trust, and never falling back to a raw substring match (a
		// marked-grade service proves itself with raw; a claim naming
		// one is refused, not silently reinterpreted). A refusal is
		// audited once, by canary/service/reason -- never the marker.
		if ev.SelfTestMarker != "" {
			matched, refusal, err := store.MatchSelfTestClaim(r.Context(), h.db, h.selfTestIndex, insert, ev.SelfTestMarker, receivedAt)
			if err != nil {
				slog.Error("ingest: self-test claim corroboration failed; storing as a real alert", "canary", tok.CanaryID, "event_id", ev.EventID, "err", err)
			} else if matched {
				insert.Synthetic = true
			} else {
				recordSelfTestClaimRefused(r.Context(), h.db, h.now, h.coalescer, tok.CanaryID, service, refusal)
			}
		} else if matched, err := store.MatchSelfTest(r.Context(), h.db, h.selfTestIndex, insert, receivedAt); err != nil {
			slog.Error("ingest: self-test match failed; storing as a real alert", "canary", tok.CanaryID, "event_id", ev.EventID, "err", err)
		} else if matched {
			insert.Synthetic = true
		}

		if opencanary.IsSelfTestResult(service) {
			// Issue #86 slice C: the agent's own report of how a
			// self-test target turned out. It has just been through the
			// matcher above -- which is the whole point of it, since the
			// target it belongs to grades silence as a pass and silence
			// produces no other event to carry a marker -- and now it
			// stops. Acked like any stored event so the agent's queue
			// drains, never persisted as an alert, never counted in a
			// canary's hits.
			//
			// Deliberately after the match rather than beside IsBase's
			// skip above: a start-up line can never be a marker, so
			// skipping it early costs nothing, whereas this event is
			// nothing but a marker and skipping it early would throw the
			// pass away.
			//
			// The raw is not logged. It carries the marker, and a marker
			// in a log line is a marker an attacker who reads logs could
			// replay to get their own traffic classified as synthetic --
			// the inversion #46 decision 4 exists to prevent.
			slog.Info("ingest: skipping a self-test result event",
				"canary", tok.CanaryID, "event_id", ev.EventID, "synthetic", insert.Synthetic)
			resp.Stored = append(resp.Stored, ev.EventID)
			continue
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

// validateEvent applies issue #32 item 8's per-field validation, as
// corrected by issue #53 (amended 2026-09-15 after a review caught that
// the first fix still rejected two real hits, port 0 and a zoned IPv6
// source): this must accept exactly what parse.go has always accepted
// from the syslog path, not a stricter shape of its own, or a permanent
// rejection here silently discards real evidence (a permanent rejection
// is never retried). reason is empty and ok is true when ev passes every
// check.
func validateEvent(ev ingestEvent) (reason string, ok bool) {
	if !eventIDPattern.MatchString(ev.EventID) {
		return "invalid event_id", false
	}
	// source_ip: empty means "not reported" (parse.go:64 leaves it empty
	// when OpenCanary's src_host is absent) or an address that parses --
	// netip.ParseAddr, not net.ParseIP, because a zoned IPv6 link-local
	// address (e.g. "fe80::1%eth0") is an ordinary hit on a LAN honeypot
	// and net.ParseIP rejects the zone suffix outright. A non-empty value
	// that parses as neither is still rejected.
	if ev.SourceIP != "" {
		if _, err := netip.ParseAddr(ev.SourceIP); err != nil {
			return "invalid source_ip", false
		}
	}
	// dest_port: -1 means "OpenCanary reported none" (parse.go:67's
	// convention, carried by the alerts table since 0001_init.sql) or
	// 0-65535 -- port 0 included deliberately, since a scan of port 0 is
	// a real event the syslog path has always stored. Anything outside
	// that range is still rejected.
	if ev.DestPort != -1 && (ev.DestPort < 0 || ev.DestPort > 65535) {
		return "invalid dest_port", false
	}
	return "", true
}

// recordSelfTestClaimRefused writes selftest.claim_refused (#46 slice
// 3): an event carried self_test_marker, but store.MatchSelfTestClaim
// could not corroborate it -- refusal names which of its four checks
// failed. The event is still stored, as an ordinary real alert; this is
// only the audit trail of the refusal.
//
// Routed through the same coalescer as recordRateLimitCrossed and
// recordKindRefused, and for the same reason: reaching this path costs
// an attacker nothing but a live token and an events/min budget it
// already has, so without coalescing a flood of bogus claims becomes a
// flood against audit_log (issue #57). canaryID and action share one
// bucket regardless of which service or check failed, matching those two
// callers' own choice not to split buckets finer than a health state
// could ever read.
func recordSelfTestClaimRefused(ctx context.Context, database *db.DB, now func() time.Time, coalescer *auditCoalescer, canaryID, service, refusal string) {
	at := now().UTC()
	write, occurrences := coalescer.admit(canaryID, "selftest.claim_refused", at)
	if !write {
		return
	}

	_, err := audit.Append(ctx, database, audit.Entry{
		Action:      "selftest.claim_refused",
		Target:      canaryID,
		Reason:      coalescedReason(fmt.Sprintf("service %s: %s", service, refusal), occurrences, "refusals"),
		TriggeredBy: canaryID,
		CreatedAt:   at,
	})
	if err != nil {
		slog.Error("ingest: record self-test claim refusal", "canary", canaryID, "service", service, "err", err)
	}
}

// recordSelfTestAudit appends one self-test audit entry for canaryID
// through the coalescer (issue #116's selftest.run_unknown,
// selftest.run_stale and selftest.stage_stale): the agent paces these,
// so the log's growth is bounded the same way every other agent-paced
// entry's is. reason never carries a run id (ADR-0012: run ids stay out
// of the audit log).
func recordSelfTestAudit(ctx context.Context, database *db.DB, now func() time.Time, coalescer *auditCoalescer, canaryID, action, reason, noun string) {
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
		slog.Error("ingest: record self-test audit entry", "canary", canaryID, "action", action, "err", err)
	}
}
