package main

import (
	"context"
	"encoding/pem"
	"io"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
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
func newIngestServer(t *testing.T, database *db.DB) (*client.Client, *httptest.Server) {
	t.Helper()
	handler := ingest.NewHandler(database, nil)
	ts := httptest.NewUnstartedServer(handler)
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return newTestClient(t, ts), ts
}

// enrollCanary inserts a canary row directly, the same shape
// internal/agent/client's own command_test.go and heartbeat_test.go use.
func enrollCanary(t *testing.T, database *db.DB, id string) {
	t.Helper()
	if err := store.InsertCanary(ctx(), database, store.Canary{
		ID: id, Name: id, Lane: "lan", EnrolledAt: time.Now().UTC(),
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
