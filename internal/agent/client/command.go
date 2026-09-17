package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// wireCommand and wireCommandResponse mirror
// internal/ingest/command.go's deliveredCommand and its
// {"command": ...} envelope field-for-field.
type wireCommand struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Params    json.RawMessage `json:"params,omitempty"`
	ExpiresAt string          `json:"expires_at"`
}

type wireCommandResponse struct {
	Command *wireCommand `json:"command"`
}

// Command is one command birdcage delivered from PollCommand (#32 slice
// 5b, #48 item 7). Params is carried opaque -- this package has no
// business interpreting a specific command kind's shape, only
// delivering it. ExpiresAt is parsed from the RFC3339Nano string
// birdcage sent: #48 "What the research changed" #6 pins expiry
// evaluation to "birdcage's clock at delivery time -- the agent never
// evaluates expiry" against its own clock, but the caller still needs a
// time.Time to log or display, which is all this field is for.
type Command struct {
	ID        string
	Kind      string
	Params    json.RawMessage
	ExpiresAt time.Time
}

// PollCommand asks POST /ingest/commands once for the next command (#32
// item 7, #48 item 7: "plain poll. No long poll" -- owner, 2026-09-15).
// A nil Command with a nil error means "nothing for you": the ordinary
// answer to a well-formed poll, not an error the caller has to
// distinguish from a real failure (mirrors
// internal/ingest/command.go's own handleCommands doc comment: 200
// with a null command, never 404).
//
// A non-nil error is ErrUnauthorized or a *RetryableError.
func (c *Client) PollCommand(ctx context.Context, token string) (*Command, error) {
	resp, doErr := c.post(ctx, "/ingest/commands", token, nil)
	if doErr != nil {
		return nil, doErr
	}
	defer closeBody(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		var out wireCommandResponse
		if err := decodeBounded(resp.Body, &out); err != nil {
			return nil, retryable(fmt.Errorf("client: decode command response: %w", err))
		}
		if out.Command == nil {
			return nil, nil
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, out.Command.ExpiresAt)
		if err != nil {
			return nil, retryable(fmt.Errorf("client: parse command expiry: %w", err))
		}
		return &Command{
			ID:        out.Command.ID,
			Kind:      out.Command.Kind,
			Params:    out.Command.Params,
			ExpiresAt: expiresAt,
		}, nil
	case http.StatusUnauthorized:
		return nil, ErrUnauthorized
	default:
		return nil, retryable(fmt.Errorf("client: poll command: unexpected status %d (%s)", resp.StatusCode, errorMessage(resp)))
	}
}
