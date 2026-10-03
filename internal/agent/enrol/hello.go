package enrol

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Hello is POST /enrol/hello's successful response ("The flow" step 3),
// parsed and validated: CAPEM has already been proven, before FirstContact
// returns it, to parse to exactly one certificate whose SHA-256 fingerprint
// matches the pin FirstContact was called with.
type Hello struct {
	EnrolmentSecret      string
	CAPEM                []byte
	IngestURL            string
	WindowDeadline       time.Time
	AdminApprovalAddress string
	ReleaseAddress       string
}

// wireHelloRequest mirrors internal/enrol's helloRequest field-for-field.
type wireHelloRequest struct {
	Token string `json:"token"`
}

// wireHelloResponse mirrors internal/enrol's helloResponse field-for-field.
type wireHelloResponse struct {
	EnrolmentSecret      string `json:"enrolment_secret"`
	CAPEM                string `json:"ca_pem"`
	IngestURL            string `json:"ingest_url"`
	WindowDeadline       string `json:"window_deadline"`
	AdminApprovalAddress string `json:"admin_approval_address"`
	ReleaseAddress       string `json:"release_address"`
}

// FirstContact posts token to baseURL's POST /enrol/hello ("The flow" step
// 3), trusting nothing about the TLS server ahead of time except pin -- the
// lower-case hex SHA-256 fingerprint of the CA's DER bytes, printed
// alongside the deploy token by `birdcage canary enrol`
// (MOCKINGBIRD_CA_PIN, docs/enrolment.md).
//
// tls.Config.InsecureSkipVerify is set to true only so that VerifyConnection
// below runs the real check itself: normal certificate-path verification
// has no root to check against yet (that is exactly what this call is
// bootstrapping), so instead this mirrors k3s's own agent join flow
// (pkg/clientaccess: trust the server presenting a certificate whose hash
// matches the token-embedded CA hash, verify the chain against exactly that
// certificate, and nothing else) -- the standard shape for first contact
// with a CA a caller has only a fingerprint of, not a copy of yet.
// VerifyConnection receives cs.PeerCertificates unverified by Go's own TLS
// stack; everything from there is this function's own responsibility:
//   - find the certificate among cs.PeerCertificates whose SHA-256(Raw)
//     equals pin, refusing if none does;
//   - build an x509.CertPool containing only that certificate;
//   - verify cs.PeerCertificates[0] (the leaf the server is actually
//     serving) chains to it, with every other presented certificate
//     available as an intermediate, DNSName checked against cs.ServerName,
//     and KeyUsages restricted to ServerAuth;
//   - refuse if that verification fails.
//
// No system root pool and no other root is ever consulted. Once that
// succeeds and birdcage answers 200, the ca_pem in the response body is
// independently checked the same way -- parses to exactly one certificate
// whose DER also hashes to pin -- before Hello is returned, so the CA
// Provision later trusts is proven pinned twice, not merely assumed to be
// the same certificate the handshake already checked.
func FirstContact(ctx context.Context, baseURL, pin, token string) (Hello, error) {
	pinBytes, err := decodePin(pin)
	if err != nil {
		return Hello{}, fmt.Errorf("enrol: invalid pin: %w", err)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // see doc comment above: VerifyConnection does the real check
		MinVersion:         tls.VersionTLS13,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPinnedChain(cs, pinBytes)
		},
	}
	httpClient := newHTTPClient(tlsConfig)

	body, err := json.Marshal(wireHelloRequest{Token: token})
	if err != nil {
		return Hello{}, fmt.Errorf("enrol: encode hello request: %w", err)
	}

	resp, err := postJSON(ctx, httpClient, baseURL, "/enrol/hello", body)
	if err != nil {
		// postJSON classifies every httpClient.Do failure as retryable by
		// default -- correct for a dial failure, a timeout, or a
		// mid-handshake network drop, all of which might succeed on a
		// later attempt, but wrong for a handshake our own
		// VerifyConnection callback (verifyPinnedChain) refused: that is
		// as deterministic as a 401, so unwrap and return it plainly,
		// never retryable, exactly like ErrRefused below.
		var pinErr *pinRefusedError
		if errors.As(err, &pinErr) {
			return Hello{}, pinErr.err
		}
		return Hello{}, err
	}
	defer closeBody(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		var out wireHelloResponse
		if err := decodeBounded(resp.Body, &out); err != nil {
			return Hello{}, fmt.Errorf("enrol: decode hello response: %w", err)
		}

		caCert, err := parseSingleCert([]byte(out.CAPEM))
		if err != nil {
			return Hello{}, fmt.Errorf("enrol: hello response ca_pem: %w", err)
		}
		if !certMatchesPin(caCert, pinBytes) {
			return Hello{}, errors.New("enrol: hello response ca_pem does not match the pinned CA")
		}

		deadline, err := time.Parse(time.RFC3339, out.WindowDeadline)
		if err != nil {
			return Hello{}, fmt.Errorf("enrol: hello response window_deadline: %w", err)
		}

		return Hello{
			EnrolmentSecret:      out.EnrolmentSecret,
			CAPEM:                []byte(out.CAPEM),
			IngestURL:            out.IngestURL,
			WindowDeadline:       deadline,
			AdminApprovalAddress: out.AdminApprovalAddress,
			ReleaseAddress:       out.ReleaseAddress,
		}, nil
	case http.StatusUnauthorized:
		return Hello{}, ErrRefused
	default:
		return Hello{}, fmt.Errorf("enrol: hello: unexpected status %d (%s)", resp.StatusCode, errorMessage(resp))
	}
}

// decodePin parses pin as hex into raw SHA-256 bytes, refusing anything that
// isn't exactly a SHA-256-sized fingerprint.
func decodePin(pin string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(pin))
	if err != nil {
		return nil, fmt.Errorf("not valid hex: %w", err)
	}
	if len(raw) != sha256.Size {
		return nil, fmt.Errorf("want %d bytes decoded (SHA-256), got %d", sha256.Size, len(raw))
	}
	return raw, nil
}

// certMatchesPin reports whether cert's DER bytes hash to pin.
func certMatchesPin(cert *x509.Certificate, pin []byte) bool {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]) == hex.EncodeToString(pin)
}

// pinRefusedError marks a TLS handshake verifyPinnedChain itself refused --
// permanent and deterministic, unlike every other failure that can reach
// FirstContact's httpClient.Do call (dial failure, timeout, a mid-handshake
// network drop), which might genuinely succeed on a later attempt. Go's own
// TLS client returns a VerifyConnection callback's error unwrapped
// (crypto/tls/handshake_client.go), so this type is what lets FirstContact
// tell the two apart on the other side of net/http's own error wrapping,
// rather than retrying a wrong pin for no reason until the enrolment
// window closes.
type pinRefusedError struct {
	err error
}

func (e *pinRefusedError) Error() string { return e.err.Error() }

func (e *pinRefusedError) Unwrap() error { return e.err }

// verifyPinnedChain is FirstContact's tls.Config.VerifyConnection callback
// -- see FirstContact's own doc comment for what it checks and why.
func verifyPinnedChain(cs tls.ConnectionState, pin []byte) error {
	if len(cs.PeerCertificates) == 0 {
		return &pinRefusedError{errors.New("enrol: server presented no certificates")}
	}

	var pinned *x509.Certificate
	for _, cert := range cs.PeerCertificates {
		if certMatchesPin(cert, pin) {
			pinned = cert
			break
		}
	}
	if pinned == nil {
		return &pinRefusedError{errors.New("enrol: no certificate presented by the server matches the pinned CA")}
	}

	roots := x509.NewCertPool()
	roots.AddCert(pinned)

	leaf := cs.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, cert := range cs.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       cs.ServerName,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return &pinRefusedError{fmt.Errorf("enrol: server certificate found matching the pinned CA, but the presented leaf does not chain to it: %w", err)}
	}
	return nil
}

// parseSingleCert decodes pemBytes and requires it to contain exactly one
// CERTIFICATE block -- ca_pem must never be trusted with more than one
// certificate in it, since anything past the first would be an unverified
// certificate this package never asked for.
func parseSingleCert(pemBytes []byte) (*x509.Certificate, error) {
	var found *x509.Certificate
	rest := pemBytes
	count := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		count++
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		found = cert
	}
	if count != 1 {
		return nil, fmt.Errorf("want exactly one certificate, got %d", count)
	}
	return found, nil
}
