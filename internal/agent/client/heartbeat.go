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
type SelfReport struct {
	QueueDepth   int
	LogReadOK    bool
	LastEventID  string
	AgentVersion string
}

// wireHeartbeat mirrors internal/ingest/heartbeat.go's ingestHeartbeat
// field-for-field. CanaryID is deliberately not carried here: identity
// comes from the token on every route on this submux (#32: "the canary
// is the token's, whatever the body says"), so there is nothing for
// this client to name.
type wireHeartbeat struct {
	QueueDepth   int    `json:"queue_depth"`
	LogReadOK    bool   `json:"log_read_ok"`
	LastEventID  string `json:"last_event_id,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`
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
	body, err := json.Marshal(wireHeartbeat(report))
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
