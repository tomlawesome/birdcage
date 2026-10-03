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
// -- its canary id, bearer token and mTLS client certificate, plus the
// heartbeat cadence to run at. There is no private key here (ADR-0012
// B1): the caller generates its own key and sends only a CSR, so
// birdcage never holds a copy of any agent's private key -- see
// Provision's own doc comment.
type Credentials struct {
	CanaryID           string
	CanaryToken        string
	ClientCertPEM      []byte
	HeartbeatIntervalS int
}

// wireProvisionRequest mirrors internal/enrol's provisionRequest
// field-for-field. CSRPEM is the caller's own CSR (ADR-0012 B1: "POST
// /enrol/provision takes a CSR (ECDSA P-256, generated in the container
// into the state volume, as the kubelet does) and returns a certificate
// and the bearer token"); birdcage takes nothing from it but the public
// key -- the subject is always overwritten from the registry row.
type wireProvisionRequest struct {
	EnrolmentSecret string `json:"enrolment_secret"`
	CSRPEM          string `json:"csr_pem"`
}

// wireProvisionResponse mirrors internal/enrol's provisionResponse
// field-for-field. No client_key_pem: ADR-0012 B1 dropped it from this
// response entirely -- "the private key exists in exactly one place from
// the first second" -- the caller's own CSR is what carried its public
// key here, and the certificate birdcage signs for it is everything this
// response needs to return.
type wireProvisionResponse struct {
	CanaryID           string `json:"canary_id"`
	CanaryToken        string `json:"canary_token"`
	ClientCertPEM      string `json:"client_cert_pem"`
	HeartbeatIntervalS int    `json:"heartbeat_interval_s"`
}

// Provision posts secret (Hello.EnrolmentSecret) and csrPEM (the
// caller's own CSR, built over a key it generated and never sends) to
// baseURL's POST /enrol/provision ("The flow" step 5) -- baseURL is the
// same enrolment listener FirstContact just talked to, not
// Hello.IngestURL: provisioning is served from the enrolment submux,
// same as hello, and only the ingest listener birdcage hands back in
// Hello is reached afterwards, by the agent's ordinary birdcage client.
//
// Unlike FirstContact, this call runs stock TLS certificate verification
// with no custom callback (matching internal/agent/client.Config.CACert's
// own rule): caPEM is the CA Hello already proved matches the pin, so there
// is no bootstrapping problem left to solve here, and a custom callback
// would only be an unverified-by-review copy of what crypto/tls already
// does correctly.
func Provision(ctx context.Context, baseURL string, caPEM []byte, secret string, csrPEM []byte) (Credentials, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return Credentials{}, errors.New("enrol: caPEM contains no usable certificate")
	}
	tlsConfig := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
	}
	httpClient := newHTTPClient(tlsConfig)

	body, err := json.Marshal(wireProvisionRequest{EnrolmentSecret: secret, CSRPEM: string(csrPEM)})
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
		if out.CanaryID == "" || out.CanaryToken == "" || out.ClientCertPEM == "" {
			return Credentials{}, errors.New("enrol: provision response missing a required field")
		}
		return Credentials{
			CanaryID:           out.CanaryID,
			CanaryToken:        out.CanaryToken,
			ClientCertPEM:      []byte(out.ClientCertPEM),
			HeartbeatIntervalS: out.HeartbeatIntervalS,
		}, nil
	case http.StatusUnauthorized:
		return Credentials{}, ErrRefused
	default:
		return Credentials{}, fmt.Errorf("enrol: provision: unexpected status %d (%s)", resp.StatusCode, errorMessage(resp))
	}
}
