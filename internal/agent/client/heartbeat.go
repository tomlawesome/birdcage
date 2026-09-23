package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// SelfReport is the agent's heartbeat body (#48 item 6, #32 item 6):
// queue depth, log-read status, last event seen, and the agent's own
// version -- what #45's "silent" and "not delivering" canary states
// stand on, since birdcage never connects to the agent to check on it
// directly.
//
// Dropped, Rejected, EventIDCollisions and PositionFound (#48's
// process-composition note, gap 3) are plain values, not pointers: a
// running agent always knows these -- MemQueue.Dropped(),
// RejectedCount() and the collision count are cumulative counters that
// start at zero, and PositionFound comes from every tailer resume -- so
// there is never a "the agent has no opinion yet" case to represent on
// this side. The nil-vs-zero distinction those fields need lives on the
// wire (wireHeartbeat below) and in storage, for the benefit of an agent
// built before this change, which never populates a SelfReport at all.
type SelfReport struct {
	QueueDepth        int
	LogReadOK         bool
	LastEventID       string
	AgentVersion      string
	Dropped           int64
	Rejected          int64
	EventIDCollisions int64
	PositionFound     bool
}

// wireHeartbeat mirrors internal/ingest/heartbeat.go's ingestHeartbeat
// field-for-field -- deliberately, since this package must never import
// internal/ingest. CanaryID is not carried here: identity comes from the
// token on every route on this submux (#32: "the canary is the token's,
// whatever the body says"), so there is nothing for this client to name.
//
// Dropped, Rejected, EventIDCollisions and PositionFound are pointers so
// that, if some future caller ever leaves a SelfReport's new fields at
// their Go zero value because it genuinely doesn't know them, the wire
// body can still omit them rather than claim zero -- the same
// omitempty-on-a-nil-pointer test in heartbeat_test.go's old-shape case
// proves the ingest side accepts. SendHeartbeat below always sends
// non-nil pointers for a real SelfReport.
type wireHeartbeat struct {
	QueueDepth        int    `json:"queue_depth"`
	LogReadOK         bool   `json:"log_read_ok"`
	LastEventID       string `json:"last_event_id,omitempty"`
	AgentVersion      string `json:"agent_version,omitempty"`
	Dropped           *int64 `json:"dropped,omitempty"`
	Rejected          *int64 `json:"rejected,omitempty"`
	EventIDCollisions *int64 `json:"event_id_collisions,omitempty"`
	PositionFound     *bool  `json:"position_found,omitempty"`
}

// SendHeartbeat posts report to POST /ingest/heartbeat on token.
//
// A non-nil error is ErrUnauthorized or a *RetryableError (429, 5xx, a
// malformed response, or any status this package does not otherwise
// recognize -- including 404, "unknown canary": a live token naming a
// canary birdcage has no row for is a real but unusual state
// (internal/ingest/heartbeat.go's own comment on ErrCanaryNotFound), and
// there is nothing more useful for this package to do about it than let
// the caller's normal heartbeat cadence try again). #32's fail-closed
// rule -- "invalid heartbeat body -> 4xx, recorded; the canary's
// last-seen does NOT advance" -- is enforced entirely on birdcage's
// side; this function just reports whichever status came back.
func (c *Client) SendHeartbeat(ctx context.Context, token string, report SelfReport) error {
	body, err := json.Marshal(wireHeartbeat{
		QueueDepth:        report.QueueDepth,
		LogReadOK:         report.LogReadOK,
		LastEventID:       report.LastEventID,
		AgentVersion:      report.AgentVersion,
		Dropped:           &report.Dropped,
		Rejected:          &report.Rejected,
		EventIDCollisions: &report.EventIDCollisions,
		PositionFound:     &report.PositionFound,
	})
	if err != nil {
		return fmt.Errorf("client: encode heartbeat: %w", err)
	}

	resp, doErr := c.post(ctx, "/ingest/heartbeat", token, body)
	if doErr != nil {
		return doErr
	}
	defer closeBody(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return ErrUnauthorized
	default:
		return retryable(fmt.Errorf("client: heartbeat: unexpected status %d (%s)", resp.StatusCode, errorMessage(resp)))
	}
}

// CommonHeartbeat is the heartbeat body every agent kind can send (issue
// #106, ADR-0009's own promise: "the small common part -- agent version,
// last contact -- is shared; the rest belongs to the kind"). A kind with
// a richer self-report -- Honeypot's SelfReport, above -- sends that
// instead; this is for a kind with nothing more honest to say, Nightjar
// today (cmd/nightjar has no log tailer, no queue, nothing SelfReport's
// other fields could report truthfully).
type CommonHeartbeat struct {
	AgentVersion string
}

// wireCommonHeartbeat mirrors internal/ingest/heartbeat.go's own
// ingestCommonHeartbeat field-for-field -- deliberately, matching
// wireHeartbeat's own stance on never importing internal/ingest.
// CanaryID is not carried here for the same reason wireHeartbeat omits
// it: identity comes from the token on every route on this submux.
type wireCommonHeartbeat struct {
	AgentVersion string `json:"agent_version,omitempty"`
}

// SendCommonHeartbeat posts report to POST /ingest/heartbeat on token,
// in the common-only shape internal/ingest's handler requires of every
// kind but Honeypot -- DisallowUnknownFields there refuses a body
// carrying any of SelfReport's own fields, so this function must never
// be used to send one. Same status handling as SendHeartbeat.
func (c *Client) SendCommonHeartbeat(ctx context.Context, token string, report CommonHeartbeat) error {
	body, err := json.Marshal(wireCommonHeartbeat{AgentVersion: report.AgentVersion})
	if err != nil {
		return fmt.Errorf("client: encode common heartbeat: %w", err)
	}

	resp, doErr := c.post(ctx, "/ingest/heartbeat", token, body)
	if doErr != nil {
		return doErr
	}
	defer closeBody(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return ErrUnauthorized
	default:
		return retryable(fmt.Errorf("client: common heartbeat: unexpected status %d (%s)", resp.StatusCode, errorMessage(resp)))
	}
}
