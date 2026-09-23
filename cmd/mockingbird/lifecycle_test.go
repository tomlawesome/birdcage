package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/agent/queue"
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

// TestRunSenderLoopStopsOnContextCancel proves the sender's own send
// (blocked mid-request) does not prevent ctx cancellation from returning
// promptly -- the same shutdown guarantee as the heartbeat and rotation
// loops above, now for the event path this slice adds.
func TestRunSenderLoopStopsOnContextCancel(t *testing.T) {
	block := make(chan struct{})
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	defer func() {
		close(block)
		ts.Close()
	}()
	c := newTestClient(t, ts)
	in, _ := newTestIntake(t, queue.Config{})
	if err := in.webhookHandler(wrapWebhook(t, fixtureEvent(1))); err != nil {
		t.Fatalf("webhookHandler: %v", err)
	}
	tokStore := &TokenStore{current: "tok"}

	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runSenderLoop(runCtx, c, tokStore, in, newPacer())
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runSenderLoop did not return after context cancellation")
	}
}

// TestRunLogRoadStopsOnContextCancel proves the log road's own
// eviction-recovery supervisor (a goroutine on top of tailer.Follow, not
// just Follow itself) returns promptly on shutdown, with no leaked
// goroutine, even mid-catch-up.
func TestRunLogRoadStopsOnContextCancel(t *testing.T) {
	in, logPath := newTestIntake(t, queue.Config{})
	if err := os.WriteFile(logPath, []byte(fixtureEvent(1)+"\n"), 0o600); err != nil {
		t.Fatalf("write log line: %v", err)
	}

	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		in.RunLogRoad(runCtx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunLogRoad did not return after context cancellation")
	}
}

// TestCommandPollAndRunnerStopOnContextCancel proves both new command
// goroutines -- the poll loop (blocked between polls on its own jittered
// timer) and the sequential runner (blocked waiting for a command) --
// return promptly on shutdown.
func TestCommandPollAndRunnerStopOnContextCancel(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"command":null}`))
	}))
	defer ts.Close()
	c := newTestClient(t, ts)
	tokStore := &TokenStore{current: "tok"}
	commands := make(chan *client.Command, commandRunnerBuffer)
	in, _ := newTestIntake(t, queue.Config{})

	runCtx, cancel := context.WithCancel(context.Background())
	pollDone := make(chan struct{})
	runnerDone := make(chan struct{})
	go func() {
		runCommandPollLoop(runCtx, c, tokStore, commands)
		close(pollDone)
	}()
	go func() {
		runCommandRunner(runCtx, in, commands)
		close(runnerDone)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	for name, ch := range map[string]chan struct{}{"poll loop": pollDone, "runner": runnerDone} {
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s did not return after context cancellation", name)
		}
	}
}
