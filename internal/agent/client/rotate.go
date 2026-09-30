package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// wireRotateResponse mirrors internal/ingest/rotate.go's rotateResponse
// field-for-field.
type wireRotateResponse struct {
	Token string `json:"token"`
}

// RotateToken presents the agent's current token to POST /ingest/rotate
// and returns the fresh one birdcage mints in its place (#32 item 5,
// #48 item 5: "presents its current token, receives a new one"). Writing
// the new token to disk, and keeping the old one until the new one is
// proven accepted, is the caller's job: "the caller owns writing it to
// disk. Do not write files" (#48), and #32's fail-closed rule --
// "rotation: response lost, or new token unwritable -> the old token
// stays in use and rotation is retried; a credential is never deleted
// before its replacement is proven accepted" -- is exactly why this
// function never touches currentToken itself and never assumes the
// caller acted on its return value.
//
// A non-nil error is either ErrUnauthorized (currentToken is already
// dead; #48: "the agent has no channel to birdcage ... recovery is
// re-enrolment") or a *RetryableError (rotate the same currentToken
// again later; mirrors internal/ingest/rotate.go's own doc comment,
// "the presented token is left completely untouched here" on every
// failure path).
func (c *Client) RotateToken(ctx context.Context, currentToken string) (string, error) {
	resp, err := c.post(ctx, "/ingest/rotate", currentToken, nil)
	if err != nil {
		return "", err
	}
	defer closeBody(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		var out wireRotateResponse
		if err := decodeBounded(resp.Body, &out); err != nil {
			return "", retryable(fmt.Errorf("client: decode rotate response: %w", err))
		}
		if out.Token == "" {
			return "", retryable(errors.New("client: rotate response carried an empty token"))
		}
		return out.Token, nil
	case http.StatusUnauthorized:
		return "", ErrUnauthorized
	default:
		return "", retryable(fmt.Errorf("client: rotate: unexpected status %d (%s)", resp.StatusCode, errorMessage(resp)))
	}
}
