package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// MaxEventsPerBatch mirrors internal/ingest/batch.go's own cap (#32
// item 8's batch arithmetic): a batch over this size gets an
// envelope-level 400 from birdcage before any event in it is looked at.
// Exported so a caller pacing its backfill (#48: "paces its own backfill
// ... below #32's per-canary limits rather than as fast as it can") can
// size its Peek-and-push calls against the server's real limit instead
// of guessing it, or tripping it and paying for a wasted round trip.
const MaxEventsPerBatch = 100

// RequestsPerMinuteLimit and EventsPerMinuteLimit are #32 item 8's
// per-canary caps, exported for the same reason as MaxEventsPerBatch:
// a caller pacing backfill after an outage needs the real ceiling to
// stay under (#48, owner 2026-09-15: "the agent pushes its backlog
// below #32's per-canary limits rather than as fast as it can"), not a
// guess this package would otherwise keep to itself.
const (
	RequestsPerMinuteLimit = 3000
	EventsPerMinuteLimit   = 60000
)

// Event is one OpenCanary hit as PushBatch sends it -- the wire shape
// POST /ingest/events accepts (internal/ingest/batch.go's ingestEvent).
// A peer package computes ID and extracts the other fields (#48: "a
// peer is building the package that computes them -- do NOT compute ids
// here, accept them", internal/agent/queue's own doc comment); this
// package only carries them onto the wire.
type Event struct {
	// ID is the 64-char lowercase hex event id.
	ID string
	// SourceIP is "" when OpenCanary reported none.
	SourceIP string
	// DestPort is -1 when OpenCanary reported none.
	DestPort int
	// Service is "" when unknown; birdcage stores that as "unknown"
	// itself (issue #53), so this package does not translate it.
	Service string
	// Raw is the verbatim emitted JSON message this event's ID was
	// hashed from.
	Raw string
}

// wireEvent, wireBatch and wireAck mirror internal/ingest/batch.go's
// ingestEvent, ingestBatch and ackResponse field-for-field: these are
// the literal JSON shapes POST /ingest/events sends and receives, and
// any drift from the server's own types is a wire-format bug this
// package's tests (run against internal/ingest's real handler) exist to
// catch.
type wireEvent struct {
	EventID  string `json:"event_id"`
	SourceIP string `json:"source_ip"`
	DestPort int    `json:"dest_port"`
	Service  string `json:"service"`
	Raw      string `json:"raw"`
}

type wireBatch struct {
	Events []wireEvent `json:"events"`
}

type wireAck struct {
	Stored   []string          `json:"stored"`
	Rejected map[string]string `json:"rejected"`
}

// BatchResult is PushBatch's outcome: every event ID sent is named in
// exactly one of Stored, Rejected or Retry.
//
// Stored includes an idempotent duplicate (#32: "a duplicate id acks as
// stored"). Rejected is permanent -- the caller drops and counts these
// (#48: "an event birdcage permanently rejects is reported to the
// caller as rejected"). Retry means birdcage gave no verdict: an
// infrastructure failure on birdcage's side (no ack at all), a batch
// this package split and could not finish sending, or (after this
// package's own singly fallback, below) a transport failure partway
// through -- and is never a rejection (#32 fail-closed: "an
// infrastructure error is never reported as a rejection ... uncertainty
// always resolves to no ack"). The caller keeps a Retry event queued and
// sends it again later.
type BatchResult struct {
	Stored   []string
	Rejected map[string]string
	Retry    []string
}

// PushBatch sends events to POST /ingest/events and reports each one's
// disposition. An error return means the whole call is retryable
// (*RetryableError) or the token is dead (ErrUnauthorized) -- see
// pushOnce -- in which case BatchResult is the zero value and every
// event in events should be treated by the caller exactly like a Retry
// entry: still queued, not rejected.
//
// A birdcage envelope-level rejection (400: malformed batch or unknown
// field; 413: body too large) is not surfaced as an error at all. Per
// #48's ratified owner decision (2026-09-15, "Singly. We can't drop 99
// events. The goal is 0 dropped."), a batch of more than one event that
// birdcage rejects at the envelope level is resent as individual
// single-event requests, so one bad or oversized member never costs the
// good events around it. A single-event batch that is itself
// envelope-rejected has nothing smaller to fall back to (#32 research:
// "4xx answers are permanent for that request"), so it is reported as
// that one event's own permanent rejection.
func (c *Client) PushBatch(ctx context.Context, token string, events []Event) (BatchResult, error) {
	if len(events) == 0 {
		return BatchResult{}, nil
	}

	result, envelopeRejected, reason, err := c.pushOnce(ctx, token, events)
	if err != nil {
		return BatchResult{}, err
	}
	if !envelopeRejected {
		return result, nil
	}
	if len(events) == 1 {
		return BatchResult{Rejected: map[string]string{events[0].ID: reason}}, nil
	}
	return c.pushSingly(ctx, token, events)
}

// pushSingly is PushBatch's fallback for a batch birdcage rejected at
// the envelope level: it resends events one request per event and
// merges the results. It stops at the first request that fails outright
// (transport failure or ErrUnauthorized) rather than looping through
// the rest regardless -- that failure is very likely to repeat for
// every remaining event too, and a synchronous retry storm against a
// birdcage that is down or a token that is dead helps nobody. Every
// event not yet attempted when that happens is reported as Retry, per
// BatchResult's own doc: never silently dropped, never turned into a
// rejection.
func (c *Client) pushSingly(ctx context.Context, token string, events []Event) (BatchResult, error) {
	out := BatchResult{Rejected: map[string]string{}}
	for i, ev := range events {
		single, envelopeRejected, reason, err := c.pushOnce(ctx, token, []Event{ev})
		if err != nil {
			for _, remaining := range events[i:] {
				out.Retry = append(out.Retry, remaining.ID)
			}
			return out, err
		}
		if envelopeRejected {
			out.Rejected[ev.ID] = reason
			continue
		}
		out.Stored = append(out.Stored, single.Stored...)
		for id, r := range single.Rejected {
			out.Rejected[id] = r
		}
		out.Retry = append(out.Retry, single.Retry...)
	}
	return out, nil
}

// pushOnce sends exactly the given events as one POST /ingest/events
// request and classifies the response. envelopeRejected is true for a
// 400 or 413 -- issue #32's "unparseable envelope, or unknown fields ->
// 4xx, permanent for that request" and "body over the cap -> 413,
// permanent" -- which PushBatch and pushSingly resolve per #48's
// ratified singly fallback rather than surfacing to the caller as an
// error. Every other non-200 status (401 aside) is reported as a
// *RetryableError: #32's transport semantics pin 429 and 5xx to "retry",
// and this package treats any status it does not otherwise recognize
// the same way, per the fail-closed shape "uncertainty always resolves
// toward ... retrying".
func (c *Client) pushOnce(ctx context.Context, token string, events []Event) (result BatchResult, envelopeRejected bool, envelopeReason string, err error) {
	wire := wireBatch{Events: make([]wireEvent, len(events))}
	for i, e := range events {
		wire.Events[i] = wireEvent{
			EventID:  e.ID,
			SourceIP: e.SourceIP,
			DestPort: e.DestPort,
			Service:  e.Service,
			Raw:      e.Raw,
		}
	}
	body, mErr := json.Marshal(wire)
	if mErr != nil {
		return BatchResult{}, false, "", fmt.Errorf("client: encode batch: %w", mErr)
	}

	resp, doErr := c.post(ctx, "/ingest/events", token, body)
	if doErr != nil {
		return BatchResult{}, false, "", doErr
	}
	defer closeBody(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		var ack wireAck
		if err := decodeBounded(resp.Body, &ack); err != nil {
			return BatchResult{}, false, "", retryable(fmt.Errorf("client: decode batch response: %w", err))
		}
		return resolveAck(events, ack), false, "", nil
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge:
		return BatchResult{}, true, errorMessage(resp), nil
	case http.StatusUnauthorized:
		return BatchResult{}, false, "", ErrUnauthorized
	default:
		return BatchResult{}, false, "", retryable(fmt.Errorf("client: push batch: unexpected status %d (%s)", resp.StatusCode, errorMessage(resp)))
	}
}

// resolveAck turns a decoded wireAck into a BatchResult naming every
// sent event exactly once: whatever ack lists as neither stored nor
// rejected got no ack at all (#32: an infrastructure failure on
// birdcage's side), and goes into Retry.
func resolveAck(sent []Event, ack wireAck) BatchResult {
	result := BatchResult{Stored: ack.Stored, Rejected: ack.Rejected}
	pending := make(map[string]bool, len(sent))
	for _, e := range sent {
		pending[e.ID] = true
	}
	for _, id := range ack.Stored {
		delete(pending, id)
	}
	for id := range ack.Rejected {
		delete(pending, id)
	}
	for _, e := range sent {
		if pending[e.ID] {
			result.Retry = append(result.Retry, e.ID)
		}
	}
	return result
}
