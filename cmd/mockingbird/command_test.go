package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
)

// validSelfTestParams is one well-formed selftest.Params, matching the
// real wire schema #46 ratified (internal/selftest/params.go) rather
// than the opaque-object placeholder this seat used to accept. Port 1
// has nothing listening in this sandbox, so the target itself fails
// fast (StatusFailed) -- irrelevant here, since runSelfTest's own
// contract is that a target failing is not a command-level refusal.
var validSelfTestParams = []byte(`{"run_id":"r1","address":"127.0.0.1","targets":[{"service":"ftp","dest_port":1,"marker":"m1"}]}`)

// TestRunCommandUnknownKindRefused proves #48's fail-closed rule: a
// command of a kind this agent does not know is refused and nothing is
// executed -- runCommand's non-nil return is the caller's cue to log the
// refusal rather than act on it.
func TestRunCommandUnknownKindRefused(t *testing.T) {
	err := runCommand(context.Background(), &client.Command{ID: "cmd-1", Kind: "upgrade"})
	if err == nil {
		t.Fatal("runCommand(unknown kind) = nil, want a refusal")
	}
}

// TestRunCommandSelfTestAccepted proves a well-formed selftest command
// is accepted regardless of how its targets fare -- the probe engine's
// per-target failures are logged, not returned as a command-level
// refusal (#46: a self-test measuring a dead service is a correct
// result, not an error).
func TestRunCommandSelfTestAccepted(t *testing.T) {
	err := runCommand(context.Background(), &client.Command{ID: "cmd-1", Kind: kindSelfTest, Params: validSelfTestParams})
	if err != nil {
		t.Errorf("runCommand(selftest, params=%s) = %v, want nil", validSelfTestParams, err)
	}
}

// TestRunCommandSelfTestUnparseableParamsRefused proves #48's
// fail-closed rule for commands: params that do not decode as a valid
// selftest.Params -- absent entirely, an empty object missing every
// required field, not even a JSON object, or malformed JSON outright --
// are refused rather than silently ignored or partially run, even for
// the one kind this agent knows.
func TestRunCommandSelfTestUnparseableParamsRefused(t *testing.T) {
	for _, params := range [][]byte{
		nil,
		[]byte(`{}`),
		[]byte(`{"marker":"m1"}`), // the old placeholder's shape: not a valid Params
		[]byte(`"just-a-string"`),
		[]byte(`42`),
		[]byte(`[1,2,3]`),
		[]byte(`{not valid json`),
	} {
		err := runCommand(context.Background(), &client.Command{ID: "cmd-1", Kind: kindSelfTest, Params: params})
		if err == nil {
			t.Errorf("runCommand(selftest, params=%s) = nil, want a refusal", params)
		}
	}
}

// TestJitteredIntervalStaysInBound proves the poll cadence's jitter
// (#48 decision 3, owner-ratified: "every 60 s with jitter") never
// strays outside base +/- jitter, and that jitter <= 0 is a no-op.
func TestJitteredIntervalStaysInBound(t *testing.T) {
	base, jitter := commandPollInterval, commandPollJitter
	for i := 0; i < 200; i++ {
		got := jitteredInterval(base, jitter)
		if got < base-jitter || got > base+jitter {
			t.Fatalf("jitteredInterval() = %v, want within [%v, %v]", got, base-jitter, base+jitter)
		}
	}
	if got := jitteredInterval(base, 0); got != base {
		t.Fatalf("jitteredInterval(base, 0) = %v, want %v unchanged", got, base)
	}
}

// TestRunSelfTestLogsOutcomesAndReturnsNil proves runSelfTest itself --
// not just the runCommand dispatch above it -- accepts a well-formed
// run and returns nil, leaving per-target reporting to its own logging
// (probe.Sweep's outcomes are exercised directly in
// internal/agent/probe's own tests).
func TestRunSelfTestLogsOutcomesAndReturnsNil(t *testing.T) {
	err := runSelfTest(context.Background(), &client.Command{ID: "cmd-1", Kind: kindSelfTest, Params: validSelfTestParams})
	if err != nil {
		t.Fatalf("runSelfTest(%s) = %v, want nil", validSelfTestParams, err)
	}
}

// TestRunCommandPollLoopDispatchesAndHandlesErrors drives
// runCommandPollLoop's own poll body -- not just the outer shutdown
// select TestCommandPollAndRunnerStopOnContextCancel already covers --
// through all three of its non-delivery outcomes (a 401, refused per
// #48 decision 4's uniform rule; a retryable server error, logged and
// retried next cycle; and an ordinary empty poll) before a real command
// is finally delivered onto the runner channel. commandPollInterval and
// commandPollJitter are shrunk for the duration of this test so those
// four poll cycles run in milliseconds rather than minutes.
func TestRunCommandPollLoopDispatchesAndHandlesErrors(t *testing.T) {
	origInterval, origJitter := commandPollInterval, commandPollJitter
	commandPollInterval, commandPollJitter = 5*time.Millisecond, 0
	defer func() { commandPollInterval, commandPollJitter = origInterval, origJitter }()

	var n atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch n.Add(1) {
		case 1:
			w.WriteHeader(http.StatusUnauthorized)
		case 2:
			w.WriteHeader(http.StatusServiceUnavailable)
		case 3:
			_, _ = w.Write([]byte(`{"command":null}`))
		default:
			_, _ = w.Write([]byte(`{"command":{"id":"cmd-1","kind":"selftest","expires_at":"2026-01-01T00:00:00Z"}}`))
		}
	}))
	defer ts.Close()
	c := newTestClient(t, ts)
	tokStore := &TokenStore{current: "tok"}
	commands := make(chan *client.Command, commandRunnerBuffer)

	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runCommandPollLoop(runCtx, c, tokStore, commands)
		close(done)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("runCommandPollLoop did not return after context cancellation")
		}
	}()

	select {
	case cmd := <-commands:
		if cmd.ID != "cmd-1" {
			t.Errorf("delivered command ID = %q, want %q", cmd.ID, "cmd-1")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no command delivered within 2s -- want the 401, 503 and empty-poll cycles to each retry rather than stopping the loop")
	}
}

// TestRunCommandPollLoopDropsOnFullBuffer proves the buffer-full branch
// (#48's process-composition note, decision 4 [contested]: "overflow
// drops the newest with a loud local log -- safe because birdcage
// re-mints from observed state"): with the runner channel already full
// and nothing draining it, a delivered command is dropped rather than
// blocking the poll loop forever.
func TestRunCommandPollLoopDropsOnFullBuffer(t *testing.T) {
	origInterval, origJitter := commandPollInterval, commandPollJitter
	commandPollInterval, commandPollJitter = 5*time.Millisecond, 0
	defer func() { commandPollInterval, commandPollJitter = origInterval, origJitter }()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"command":{"id":"cmd-1","kind":"selftest","expires_at":"2026-01-01T00:00:00Z"}}`))
	}))
	defer ts.Close()
	c := newTestClient(t, ts)
	tokStore := &TokenStore{current: "tok"}
	// Unbuffered and never read: run <- cmd can never succeed, forcing
	// every poll cycle down the "buffer full" default branch.
	commands := make(chan *client.Command)

	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	// The poll loop's whole lifetime -- start, several poll cycles,
	// cancellation and exit -- stays inside captureStdout's closure, so
	// its background goroutine never touches os.Stdout concurrently with
	// captureStdout's own swap and restore either side of this call.
	out := captureStdout(t, func() {
		go func() {
			runCommandPollLoop(runCtx, c, tokStore, commands)
			close(done)
		}()
		time.Sleep(50 * time.Millisecond) // several poll cycles at 5ms
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("runCommandPollLoop did not return after context cancellation")
		}
	})
	if !strings.Contains(out, "runner: buffer full") || !strings.Contains(out, "cmd-1") {
		t.Errorf("log output = %q, want a buffer-full drop naming cmd-1", out)
	}
}

// TestRunCommandRunnerDispatchesCommands drives runCommandRunner's own
// received-command branch -- TestCommandPollAndRunnerStopOnContextCancel
// only ever cancels it while blocked waiting, since that test's poll
// loop never delivers anything -- by sending both an acceptable and a
// refused command straight onto its channel. run is unbuffered, so each
// send only completes once the runner has received it: no sleep needed
// to know the runner actually processed each one before the next line
// runs.
func TestRunCommandRunnerDispatchesCommands(t *testing.T) {
	run := make(chan *client.Command)
	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runCommandRunner(runCtx, run)
		close(done)
	}()

	run <- &client.Command{ID: "cmd-ok", Kind: kindSelfTest, Params: validSelfTestParams}
	run <- &client.Command{ID: "cmd-bad", Kind: "unknown"}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runCommandRunner did not return after context cancellation")
	}
}
