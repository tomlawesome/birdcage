// Package certkey is the one place every agent kind generates its own
// mTLS client key pair and CSR, and reads the resulting certificate's
// validity window -- ADR-0012 Part B1/B2 ("the agent makes its own key;
// birdcage never sees it", "certificates live seven days and the agent
// renews them from half-life, with a fresh key each time"). Shared by
// internal/agent/enrolment (first provisioning) and internal/agent/client
// (renewal) so both go through the identical key-generation and
// CSR-building code rather than two copies that could drift.
//
// The private key this package generates never leaves the process as
// anything but its own PEM encoding, written to the state volume by the
// caller; this package itself never logs, transmits or returns the key
// in any other form.
package certkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// SubjectPlaceholder is the CommonName every CSR this package builds
// carries. ADR-0012 B1: "the subject is overwritten from the registry
// row ... nothing from the CSR but the public key survives" -- true both
// at first provisioning (where the agent has no canary id yet) and at
// renewal (where it does, but the server ignores it just the same), so
// there is nothing to gain by threading the real id through here, and a
// fixed, obviously-placeholder value keeps the two call sites identical.
const SubjectPlaceholder = "pending-agent"

// GenerateKey returns a fresh ECDSA P-256 private key -- ADR-0012 B1:
// "ECDSA P-256, generated in the container ... as the kubelet does".
func GenerateKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("certkey: generate key: %w", err)
	}
	return key, nil
}

// MarshalKeyPEM encodes key as a PKCS#8 "PRIVATE KEY" PEM block -- the
// only on-disk form this agent's private key ever takes.
func MarshalKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("certkey: marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseKeyPEM decodes a single PKCS#8-encoded ECDSA private key PEM
// block, the inverse of MarshalKeyPEM -- used to reuse a pending key
// written by an earlier, interrupted attempt rather than regenerating
// one.
func ParseKeyPEM(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("certkey: no PEM block found")
	}
	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certkey: parse key: %w", err)
	}
	key, ok := raw.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("certkey: PEM block is not an ECDSA private key")
	}
	return key, nil
}

// BuildCSR builds a PEM-encoded PKCS#10 certificate signing request over
// key, signed by it to prove possession of the corresponding private
// key. The subject is always SubjectPlaceholder -- see its own doc
// comment for why inventing anything more specific here would be
// pointless.
func BuildCSR(key *ecdsa.PrivateKey) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: SubjectPlaceholder},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("certkey: create CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// HalfLife parses certPEM (a single CERTIFICATE PEM block -- the agent's
// own mTLS client certificate) and returns NotBefore + (NotAfter -
// NotBefore)/2, the moment ADR-0012 B2 names as the renewal loop's own
// trigger: "from the certificate's half-life ... on every heartbeat tick
// try POST /ingest/renew".
func HalfLife(certPEM []byte) (time.Time, error) {
	cert, err := parseSingleCert(certPEM)
	if err != nil {
		return time.Time{}, err
	}
	half := cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) / 2)
	return half, nil
}

// parseSingleCert decodes the first CERTIFICATE PEM block in certPEM.
// Unlike internal/agent/enrol's own parseSingleCert (which validates a
// value that arrived over the network), this reads only the agent's own
// state file, so it does not need to insist there is exactly one block
// -- the first is always the right one.
func parseSingleCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("certkey: no CERTIFICATE PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certkey: parse certificate: %w", err)
	}
	return cert, nil
}
