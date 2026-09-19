package enrol

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Credentials is POST /enrol/provision's successful response ("The flow"
// step 5): the lasting identity and credentials a canary uses from here on
// -- its canary id, bearer token and mTLS client certificate/key, plus the
// heartbeat cadence to run at.
type Credentials struct {
	CanaryID           string
	CanaryToken        string
	ClientCertPEM      []byte
	ClientKeyPEM       []byte
	HeartbeatIntervalS int
}

// wireProvisionRequest mirrors internal/enrol's provisionRequest
// field-for-field.
type wireProvisionRequest struct {
	EnrolmentSecret string `json:"enrolment_secret"`
}

// wireProvisionResponse mirrors internal/enrol's provisionResponse
// field-for-field.
type wireProvisionResponse struct {
	CanaryID           string `json:"canary_id"`
	CanaryToken        string `json:"canary_token"`
	ClientCertPEM      string `json:"client_cert_pem"`
	ClientKeyPEM       string `json:"client_key_pem"`
	HeartbeatIntervalS int    `json:"heartbeat_interval_s"`
}

// Provision posts secret (Hello.EnrolmentSecret) to baseURL's POST
// /enrol/provision ("The flow" step 5) -- baseURL is the same enrolment
// listener FirstContact just talked to, not Hello.IngestURL: provisioning
// is served from the enrolment submux, same as hello, and only the ingest
// listener birdcage hands back in Hello is reached afterwards, by the
// agent's ordinary birdcage client.
//
// Unlike FirstContact, this call runs stock TLS certificate verification
// with no custom callback (matching internal/agent/client.Config.CACert's
// own rule): caPEM is the CA Hello already proved matches the pin, so there
// is no bootstrapping problem left to solve here, and a custom callback
// would only be an unverified-by-review copy of what crypto/tls already
// does correctly.
func Provision(ctx context.Context, baseURL string, caPEM []byte, secret string) (Credentials, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return Credentials{}, errors.New("enrol: caPEM contains no usable certificate")
	}
	tlsConfig := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
	}
	httpClient := newHTTPClient(tlsConfig)

	body, err := json.Marshal(wireProvisionRequest{EnrolmentSecret: secret})
	if err != nil {
		return Credentials{}, fmt.Errorf("enrol: encode provision request: %w", err)
	}

	resp, err := postJSON(ctx, httpClient, baseURL, "/enrol/provision", body)
	if err != nil {
		return Credentials{}, err
	}
	defer closeBody(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		var out wireProvisionResponse
		if err := decodeBounded(resp.Body, &out); err != nil {
			return Credentials{}, fmt.Errorf("enrol: decode provision response: %w", err)
		}
		if out.CanaryID == "" || out.CanaryToken == "" || out.ClientCertPEM == "" || out.ClientKeyPEM == "" {
			return Credentials{}, errors.New("enrol: provision response missing a required field")
		}
		return Credentials{
			CanaryID:           out.CanaryID,
			CanaryToken:        out.CanaryToken,
			ClientCertPEM:      []byte(out.ClientCertPEM),
			ClientKeyPEM:       []byte(out.ClientKeyPEM),
			HeartbeatIntervalS: out.HeartbeatIntervalS,
		}, nil
	case http.StatusUnauthorized:
		return Credentials{}, ErrRefused
	default:
		return Credentials{}, fmt.Errorf("enrol: provision: unexpected status %d (%s)", resp.StatusCode, errorMessage(resp))
	}
}
