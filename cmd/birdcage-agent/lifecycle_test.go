package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
)

// TestRunHeartbeatLoopStopsOnContextCancel proves clean shutdown: a
// heartbeat send blocked mid-request returns, and the loop itself
// returns, once ctx is canceled -- without waiting for the send to
// succeed or for the next tick. Run under -race, this also proves the
// loop's own goroutine does not leak past cancellation.
func TestRunHeartbeatLoopStopsOnContextCancel(t *testing.T) {
	block := make(chan struct{})
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	defer func() {
		close(block)
		ts.Close()
	}()
	c := newTestClient(t, ts)
	tokStore := &TokenStore{current: "tok"}

	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runHeartbeatLoop(runCtx, c, tokStore, func() client.SelfReport { return client.SelfReport{} })
		close(done)
	}()

	// Let the loop start its first (now blocked) send before canceling.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runHeartbeatLoop did not return after context cancellation")
	}
}

// TestRunRotationLoopStopsOnContextCancel is TestRunHeartbeatLoopStops...
// for the rotation loop: a rotate call blocked mid-request must not
// prevent ctx cancellation from returning promptly.
func TestRunRotationLoopStopsOnContextCancel(t *testing.T) {
	block := make(chan struct{})
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	defer func() {
		close(block)
		ts.Close()
	}()
	c := newTestClient(t, ts)
	tokStore := &TokenStore{current: "tok", path: filepath.Join(t.TempDir(), "token")}

	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runRotationLoop(runCtx, c, tokStore)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runRotationLoop did not return after context cancellation")
	}
}
