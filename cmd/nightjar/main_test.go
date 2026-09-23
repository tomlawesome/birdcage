package main

import (
	"context"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// serverCertPEM PEM-encodes ts's own certificate, the CACert value a
// Config needs to trust it -- the same extraction newTestClient
// (heartbeat_test.go) does inline, factored out here since boot's own
// tests build a Config directly rather than going through that helper.
func serverCertPEM(t *testing.T, ts *httptest.Server) []byte {
	t.Helper()
	cert := ts.Certificate()
	if cert == nil {
		t.Fatal("test server has no certificate")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// TestBootBadClientConfig proves boot's first dependency-failure return:
// an empty BirdcageURL is client.New's own first check, refused before
// any network is touched, and boot must name that step in its error
// rather than getting as far as loadToken.
func TestBootBadClientConfig(t *testing.T) {
	cfg := Config{
		TokenPath: filepath.Join(t.TempDir(), tokenFileName),
	}
	cli, token, err := boot(cfg)
	if err == nil {
		t.Fatal("boot succeeded with an empty BirdcageURL, want an error")
	}
	if cli != nil {
		t.Error("boot returned a non-nil client alongside an error")
	}
	if token != "" {
		t.Error("boot returned a non-empty token alongside an error")
	}
	if !strings.Contains(err.Error(), "build birdcage client") {
		t.Errorf("boot error = %q, want it to name the birdcage-client step", err.Error())
	}
}

// TestBootMissingTokenPath proves boot's second dependency-failure
// return: a valid client config (so client.New succeeds) paired with a
// token path that names nothing on disk.
func TestBootMissingTokenPath(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := Config{
		BirdcageURL: ts.URL,
		CACert:      serverCertPEM(t, ts),
		TokenPath:   filepath.Join(t.TempDir(), "no-such-token"),
	}
	_, _, err := boot(cfg)
	if err == nil {
		t.Fatal("boot succeeded with a missing token file, want an error")
	}
	if !strings.Contains(err.Error(), "load token") {
		t.Errorf("boot error = %q, want it to name the load-token step", err.Error())
	}
}

// TestBootSuccess is boot's happy path, against the same real TLS
// test-server fixture scanner_real_test.go and heartbeat_test.go already
// use for the rest of this package's client-facing tests: a valid
// client config (CACert only -- ClientCert/ClientKey both empty is a
// valid client.Config, per that package's own doc comment) and a real
// token file on disk.
func TestBootSuccess(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	tokenPath := filepath.Join(t.TempDir(), tokenFileName)
	if err := os.WriteFile(tokenPath, []byte("the-token\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	cfg := Config{
		BirdcageURL: ts.URL,
		CACert:      serverCertPEM(t, ts),
		TokenPath:   tokenPath,
	}
	cli, token, err := boot(cfg)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	if cli == nil {
		t.Fatal("boot returned a nil client on success")
	}
	if token != "the-token" {
		t.Errorf("token = %q, want %q", token, "the-token")
	}
}

// TestRunStopsPromptlyOnCancelledContext proves run -- the function main
// starts its two loops through -- starts both the scan and heartbeat
// loops and returns promptly once ctx is done, with no sleep standing in
// for the wait: the context is cancelled before run is even called, so
// only a loop that actually observes cancellation (rather than blocking
// on its own interval) lets this test return inside its deadline. The
// scan interval is deliberately an hour, so a loop that ignored
// cancellation would hang this test rather than merely running slow.
func TestRunStopsPromptlyOnCancelledContext(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	cfg := Config{BirdcageURL: ts.URL, ScanInterval: time.Hour}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		run(ctx, cfg, c, "tok", "v-test", slog.New(slog.DiscardHandler))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop promptly after a cancelled context")
	}
}
