package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/agent/renewal"
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
// every test in this package mints its tokens for. Its subject OU is
// Honeypot (issue #106: every canary this binary is ever built into is
// one) -- ensureCanary registers testCanaryID with that same kind, a
// no-op if a test already called enrollCanary itself, so the registry
// check and the certificate check agree.
func newIngestServer(t *testing.T, database *db.DB) (*client.Client, *httptest.Server) {
	t.Helper()
	ensureCanary(t, database, testCanaryID, agentkind.Honeypot)
	clientCert, clientKey := selfSignedKeyPair(t, testCanaryID, string(agentkind.Honeypot))
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCert) {
		t.Fatal("failed to add generated client cert to pool")
	}
	handler := ingest.NewHandler(database, nil, store.NewSelfTestIndex(), nil)
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
// same helper internal/agent/client's client_test.go carries. ou is
// variadic and normally omitted; newIngestServer passes Honeypot's
// string (issue #106), since its server enforces the same
// certificate-kind check internal/ingest's real listener does.
func selfSignedKeyPair(t *testing.T, cn string, ou ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn, OrganizationalUnit: ou},
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

// newTestRenewalManager builds a renewal.Manager whose current
// certificate is freshly minted (NotBefore=now, one-hour lifetime), so
// its half-life is 30 minutes out -- far enough that Tick is a no-op for
// any test that just needs a heartbeat loop to run without also
// triggering a real renewal attempt against a fake server that doesn't
// implement POST /ingest/renew.
func newTestRenewalManager(t *testing.T) *renewal.Manager {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "renewal-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	dir := t.TempDir()
	return renewal.NewManager(dir, clientKeyFileName, clientCertFileName, certPEM, keyPEM)
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

// ensureCanary registers canaryID with kind if (and only if) no canaries
// row for it exists yet -- idempotent, so a test that already called
// enrollCanary for canaryID before minting a token doesn't collide with
// a second, conflicting insert here.
func ensureCanary(t *testing.T, database *db.DB, canaryID string, kind agentkind.Kind) {
	t.Helper()
	var exists int
	err := database.QueryRow(`SELECT 1 FROM canaries WHERE id = ?`, canaryID).Scan(&exists)
	if err == nil {
		return
	}
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("check canary %s exists: %v", canaryID, err)
	}
	if err := store.InsertCanary(ctx(), database, store.Canary{
		ID: canaryID, Name: canaryID, Lane: "lan", Kind: kind, EnrolledAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("InsertCanary(%s): %v", canaryID, err)
	}
}

// mintToken mints a fresh, active bearer token for canaryID, registering
// it as a Honeypot (issue #106: every ingest route now refuses a token
// whose canary is unregistered) unless a canaries row already exists.
func mintToken(t *testing.T, database *db.DB, canaryID string) string {
	t.Helper()
	ensureCanary(t, database, canaryID, agentkind.Honeypot)
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
