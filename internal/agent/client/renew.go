package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// RenewResult is POST /ingest/renew's successful response (ADR-0012 B2):
// the fresh certificate birdcage issued for the CSR just presented, and
// when it stops being valid.
type RenewResult struct {
	ClientCertPEM []byte
	NotAfter      time.Time
}

// wireRenewRequest mirrors internal/ingest's own renewRequest
// field-for-field.
type wireRenewRequest struct {
	CSRPEM string `json:"csr_pem"`
}

// wireRenewResponse mirrors internal/ingest's own renewResponse
// field-for-field.
type wireRenewResponse struct {
	ClientCertPEM string `json:"client_cert_pem"`
	NotAfter      string `json:"not_after"`
}

// RenewCert posts csrPEM to POST /ingest/renew, over the same mTLS
// connection and bearer token as every other route on this submux
// (ADR-0012 B2: "same mTLS client cert + bearer token as
// /ingest/rotate"). token is the agent's current bearer token, untouched
// by this call either way -- ADR-0012 B2: "the server moves the live
// bearer token to the new certificate itself; the agent keeps using its
// current token" -- so unlike RotateToken there is no new token for the
// caller to persist here, only a new certificate.
//
// The old certificate stays valid until the new one's first use
// (ADR-0012 B2), so a caller that fails to persist or switch to
// RenewResult afterwards has lost nothing: the credential this call
// authenticated with is still live, and the next heartbeat tick simply
// tries again with a fresh key and CSR.
//
// A non-nil error is either ErrUnauthorized (token itself is already
// dead -- recovery is re-enrolment, the same stance every other route in
// this package takes) or a *RetryableError (retry with a fresh key and
// CSR on the next tick; never retry the same CSR, since a fresh key each
// time is ADR-0012 B2's own requirement, not an optimization to skip on
// retry).
func (c *Client) RenewCert(ctx context.Context, token string, csrPEM []byte) (RenewResult, error) {
	body, err := json.Marshal(wireRenewRequest{CSRPEM: string(csrPEM)})
	if err != nil {
		return RenewResult{}, fmt.Errorf("client: encode renew request: %w", err)
	}

	resp, err := c.post(ctx, "/ingest/renew", token, body)
	if err != nil {
		return RenewResult{}, err
	}
	defer closeBody(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		var out wireRenewResponse
		if err := decodeBounded(resp.Body, &out); err != nil {
			return RenewResult{}, retryable(fmt.Errorf("client: decode renew response: %w", err))
		}
		if out.ClientCertPEM == "" || out.NotAfter == "" {
			return RenewResult{}, retryable(errors.New("client: renew response missing a required field"))
		}
		notAfter, err := time.Parse(time.RFC3339, out.NotAfter)
		if err != nil {
			return RenewResult{}, retryable(fmt.Errorf("client: renew response not_after: %w", err))
		}
		return RenewResult{ClientCertPEM: []byte(out.ClientCertPEM), NotAfter: notAfter}, nil
	case http.StatusUnauthorized:
		return RenewResult{}, ErrUnauthorized
	default:
		return RenewResult{}, retryable(fmt.Errorf("client: renew: unexpected status %d (%s)", resp.StatusCode, errorMessage(resp)))
	}
}
