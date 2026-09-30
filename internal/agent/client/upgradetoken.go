package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// UpgradeTokenAnswer is birdcage's answer to a presented upgrade token
// (issue #54): accepted, with the end of the window it opened, or
// refused, with birdcage's one-phrase reason ("expired", "already used",
// ...).
type UpgradeTokenAnswer struct {
	Accepted    bool
	Reason      string
	WindowUntil time.Time
}

// wireUpgradeToken and wireUpgradeTokenResponse mirror
// internal/ingest/upgrade.go's ingestUpgradeToken and
// ingestUpgradeTokenResponse field-for-field -- this package never
// imports internal/ingest.
type wireUpgradeToken struct {
	UpgradeToken string `json:"upgrade_token"`
}

type wireUpgradeTokenResponse struct {
	Outcome     string `json:"outcome"`
	Reason      string `json:"reason"`
	WindowUntil string `json:"window_until"`
}

// ErrUpgradeTokenMalformed is birdcage's 400 on POST
// /ingest/upgrade-token: the body was not the one-field object. Not
// retryable -- the same request would be refused the same way.
var ErrUpgradeTokenMalformed = errors.New("client: upgrade token request refused as malformed")

// PresentUpgradeToken presents upgradeToken to POST
// /ingest/upgrade-token on bearer, over this Client's mTLS credential --
// the agent's own, which is what names the agent to birdcage. The caller
// holds upgradeToken in memory only; this function never stores or logs
// it either.
//
// A non-nil error is ErrUnauthorized (the agent's own credential was
// refused), ErrUpgradeTokenMalformed, or a *RetryableError (no answer,
// 429, 5xx, or a 200 whose body did not decode): the token was not
// settled, and presenting it again is safe.
func (c *Client) PresentUpgradeToken(ctx context.Context, bearer, upgradeToken string) (UpgradeTokenAnswer, error) {
	body, err := json.Marshal(wireUpgradeToken{UpgradeToken: upgradeToken})
	if err != nil {
		return UpgradeTokenAnswer{}, fmt.Errorf("client: encode upgrade token: %w", err)
	}
	resp, err := c.post(ctx, "/ingest/upgrade-token", bearer, body)
	if err != nil {
		return UpgradeTokenAnswer{}, err
	}
	defer closeBody(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		var out wireUpgradeTokenResponse
		if err := decodeBounded(resp.Body, &out); err != nil {
			return UpgradeTokenAnswer{}, retryable(fmt.Errorf("client: decode upgrade token response: %w", err))
		}
		switch out.Outcome {
		case "accepted":
			until, err := time.Parse(time.RFC3339, out.WindowUntil)
			if err != nil {
				return UpgradeTokenAnswer{}, retryable(fmt.Errorf("client: upgrade token response window_until: %w", err))
			}
			return UpgradeTokenAnswer{Accepted: true, WindowUntil: until}, nil
		case "refused":
			return UpgradeTokenAnswer{Reason: out.Reason}, nil
		default:
			return UpgradeTokenAnswer{}, retryable(fmt.Errorf("client: upgrade token response has outcome %q", out.Outcome))
		}
	case http.StatusUnauthorized:
		return UpgradeTokenAnswer{}, ErrUnauthorized
	case http.StatusBadRequest:
		return UpgradeTokenAnswer{}, ErrUpgradeTokenMalformed
	default:
		return UpgradeTokenAnswer{}, retryable(fmt.Errorf("client: upgrade token: unexpected status %d (%s)", resp.StatusCode, errorMessage(resp)))
	}
}
