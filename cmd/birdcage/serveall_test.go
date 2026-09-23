package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/store"
	"github.com/tomlawesome/birdcage/internal/tlsconfig"
)

// waitUntilDialable polls addr until a plain TCP connection succeeds (or
// t.Fatal after 2s) -- enough to prove a listener is actually accepting,
// without completing a TLS handshake, which none of these tests need.
func waitUntilDialable(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("nothing accepting connections on %s after 2s", addr)
}

// TestServeAllUnixSocketMode drives serveAll's ModePlainUnixSocket branch
// -- untouched by TestServeAllReturnsNilOnCleanShutdown, which only
// exercises ModePlainLoopbackTCP -- proving the socket is actually
// listenable and that shutdown returns cleanly.
func TestServeAllUnixSocketMode(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "http.sock")
	dashboard := &http.Server{Handler: http.NotFoundHandler()}
	ctx, stop := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- serveAll(ctx, stop, dashboard, tlsconfig.ModePlainUnixSocket, sockPath, nil, nil, discardLog(), discardLog(), discardLog(), discardLog())
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("unix", sockPath, 50*time.Millisecond); err == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	stop()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serveAll (unix socket) after a clean shutdown = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveAll did not return within 2s of ctx cancellation")
	}
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Errorf("socket file %s still exists after shutdown", sockPath)
	}
}

// TestServeAllWithIngestAndEnrolServers drives serveAll with both the
// ingest and enrolment listeners present -- the two service goroutines
// (and their own shutdown goroutines) that TestServeAllReturnsNilOnCleanShutdown
// never starts, since it always passes nil, nil for them. Built through
// the real buildIngestServers, the same way main() does, on dynamic
// loopback ports so this can never collide with another test or agent.
func TestServeAllWithIngestAndEnrolServers(t *testing.T) {
	birdcageCA := testCA(t)
	database := openTestDB(t)
	cfg := startupConfig{
		ingestAddr: freeLoopbackAddr(t),
		enrolAddr:  freeLoopbackAddr(t),
	}
	idx := store.NewSelfTestIndex()
	ingestServer, enrolServer, err := buildIngestServers(cfg, database, birdcageCA, nil, idx, nil, discardLog(), discardLog(), discardLog())
	if err != nil {
		t.Fatalf("buildIngestServers: %v", err)
	}

	dashboardAddr := freeLoopbackAddr(t)
	dashboard := &http.Server{Addr: dashboardAddr, Handler: http.NotFoundHandler()}
	ctx, stop := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- serveAll(ctx, stop, dashboard, tlsconfig.ModePlainLoopbackTCP, "", ingestServer, enrolServer, discardLog(), discardLog(), discardLog(), discardLog())
	}()

	waitUntilDialable(t, dashboardAddr)
	waitUntilDialable(t, cfg.ingestAddr)
	waitUntilDialable(t, cfg.enrolAddr)
	stop()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serveAll (ingest+enrol) after a clean shutdown = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveAll did not return within 2s of ctx cancellation")
	}
}
