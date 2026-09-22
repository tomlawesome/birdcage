package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/db/dbtest"
	"github.com/tomlawesome/birdcage/internal/ingest"
	"github.com/tomlawesome/birdcage/internal/store"
)

// This file mirrors internal/agent/client's own test helpers
// (client_test.go, batch_test.go) rather than inventing a new shape:
// this package's tests exercise the same real internal/ingest handler
// through the same real internal/agent/client, just one layer up, so the
// setup is deliberately the same.

func ctx() context.Context {
	return context.Background()
}

// forEachEngine runs fn once per database engine dbtest.Targets returns,
// so a Postgres-only failure is reported distinctly from SQLite's.
func forEachEngine(t *testing.T, fn func(t *testing.T, database *db.DB)) {
	t.Helper()
	for _, tgt := range dbtest.Targets(t) {
		tgt := tgt
		t.Run(tgt.Name, func(t *testing.T) {
			fn(t, tgt.DB)
		})
	}
}

// certPEM PEM-encodes ts's own leaf certificate, so a Client can be
// built to trust exactly it.
func certPEM(t *testing.T, ts *httptest.Server) []byte {
	t.Helper()
	cert := ts.Certificate()
	if cert == nil {
		t.Fatal("test server has no certificate")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// newTestClient builds a client.Client trusting ts's own certificate. No
// mTLS material: this package's tests exercise the token/rotation/
// heartbeat loops, which are orthogonal to whether the client also
// presents its own certificate.
func newTestClient(t *testing.T, ts *httptest.Server) *client.Client {
	t.Helper()
	c, err := client.New(client.Config{BaseURL: ts.URL, CACert: certPEM(t, ts)})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c
}

// newIngestServer wraps internal/ingest's real handler (not a
// hand-written fake) in a TLS httptest.Server, and returns a Client
// configured to trust it.
//
// The server requires a client certificate (issue #47 slice 3: the
// ingest listener runs ClientAuth: RequireAndVerifyClientCert, and
// requireBearerToken binds the certificate's CommonName to the token's
// canary), so the Client presents one for testCanaryID -- the canary
// every test in this package mints its tokens for.
func newIngestServer(t *testing.T, database *db.DB) (*client.Client, *httptest.Server) {
	t.Helper()
	clientCert, clientKey := selfSignedKeyPair(t, testCanaryID)
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCert) {
		t.Fatal("failed to add generated client cert to pool")
	}
	handler := ingest.NewHandler(database, nil)
	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	c, err := client.New(client.Config{BaseURL: ts.URL, CACert: certPEM(t, ts), ClientCert: clientCert, ClientKey: clientKey})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c, ts
}

// testCanaryID is the one canary this package's real-ingest tests
// enrol, mint tokens for, and present a client certificate as.
const testCanaryID = "canary-a"

// selfSignedKeyPair mints a self-signed client certificate for cn, the
// same helper internal/agent/client's client_test.go carries.
func selfSignedKeyPair(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// enrollCanary inserts a canary row directly, the same shape
// internal/agent/client's own command_test.go and heartbeat_test.go use.
func enrollCanary(t *testing.T, database *db.DB, id string) {
	t.Helper()
	if err := store.InsertCanary(ctx(), database, store.Canary{
		ID: id, Name: id, Lane: "lan", Kind: agentkind.Honeypot, EnrolledAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("InsertCanary(%s): %v", id, err)
	}
}

// mintToken mints a fresh, active bearer token for canaryID.
func mintToken(t *testing.T, database *db.DB, canaryID string) string {
	t.Helper()
	raw, _, err := store.MintCanaryToken(ctx(), database, canaryID, time.Now().UTC())
	if err != nil {
		t.Fatalf("MintCanaryToken: %v", err)
	}
	return raw
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns
// everything it printed -- the same technique cmd/birdcage's own
// canary_test.go uses, needed here because internal/logging's component
// loggers write to whatever os.Stdout currently is (see that package's
// stdoutWriter) rather than through the stdlib log package a plain
// log.SetOutput could redirect. Not safe to run in parallel with
// another test doing the same (os.Stdout is process-global), which is
// why no test in this package calls t.Parallel().
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	fn()
	if cerr := w.Close(); cerr != nil {
		t.Fatalf("close pipe writer: %v", cerr)
	}
	os.Stdout = old
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return string(out)
}
