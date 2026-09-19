package ingest

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/ca"
)

// newTestCA loads a fresh internal/ca.CA in a throwaway 0700 directory
// -- the same fixture NewTLSServer's real caller (cmd/birdcage/main.go)
// produces via ca.Load, standing in here for tests that need a
// GetCertificate function without a real CA directory on disk.
func newTestCA(t *testing.T) *ca.CA {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ca")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir CA dir: %v", err)
	}
	c, _, err := ca.Load(dir, nil)
	if err != nil {
		t.Fatalf("ca.Load: %v", err)
	}
	return c
}

// TestNewTLSServerPinsHTTP1AndTLS13AndTimeouts checks the server
// construction issue #32's "what the research changed" section pins:
// HTTP/1.1 only, TLS 1.3 floor, and every pre-auth timeout/cap set
// (research #1 and #2). No network handshake is needed to verify these
// -- they're all fields on the returned *http.Server.
func TestNewTLSServerPinsHTTP1AndTLS13AndTimeouts(t *testing.T) {
	c := newTestCA(t)
	getCert := c.ServerCertificateSource([]string{"127.0.0.1"}, time.Hour, 10*time.Minute, nil)

	srv := NewTLSServer("127.0.0.1:0", http.NotFoundHandler(), getCert)

	if srv.TLSConfig == nil || srv.TLSConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("TLSConfig.MinVersion = %v, want tls.VersionTLS13", srv.TLSConfig)
	}
	if srv.TLSConfig.GetCertificate == nil {
		t.Error("TLSConfig.GetCertificate is nil")
	}
	if srv.Protocols == nil || !srv.Protocols.HTTP1() {
		t.Error("Protocols does not enable HTTP/1.1")
	}
	if srv.Protocols != nil && (srv.Protocols.HTTP2() || srv.Protocols.UnencryptedHTTP2()) {
		t.Error("Protocols enables HTTP/2 or unencrypted HTTP/2; issue #32 pins HTTP/1.1 only")
	}
	if srv.ReadHeaderTimeout == 0 || srv.ReadTimeout == 0 || srv.WriteTimeout == 0 || srv.IdleTimeout == 0 {
		t.Errorf("one or more timeouts unset: ReadHeaderTimeout=%v ReadTimeout=%v WriteTimeout=%v IdleTimeout=%v",
			srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
	if srv.MaxHeaderBytes == 0 {
		t.Error("MaxHeaderBytes unset")
	}
}

// TestNewTLSServerServesAgainstCAPool is the end-to-end check that the
// listener's GetCertificate wiring actually works: an http.Client
// trusting the CA succeeds, and one that doesn't fails verification --
// #47 slice 1's replacement for the old on-disk cert/key fixture test.
func TestNewTLSServerServesAgainstCAPool(t *testing.T) {
	c := newTestCA(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	host, _, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}

	getCert := c.ServerCertificateSource([]string{host}, time.Hour, 10*time.Minute, nil)
	srv := NewTLSServer(ln.Addr().String(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), getCert)

	go srv.ServeTLS(ln, "", "")
	defer srv.Close()

	url := "https://" + ln.Addr().String() + "/"

	trustingClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: c.Pool()},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := trustingClient.Get(url)
	if err != nil {
		t.Fatalf("GET with trusted pool: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	distrustingClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool()},
		},
		Timeout: 5 * time.Second,
	}
	if _, err := distrustingClient.Get(url); err == nil {
		t.Fatal("GET without the CA pool succeeded, want a verification error")
	}
}
