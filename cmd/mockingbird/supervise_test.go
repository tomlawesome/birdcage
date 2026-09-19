package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestRunChildReportsExitCode proves a child that exits non-zero on its
// own -- not killed by runChild -- triggers onExit with an error
// carrying that status.
func TestRunChildReportsExitCode(t *testing.T) {
	var gotErr error
	called := make(chan struct{})

	runChild(context.Background(), []string{"sh", "-c", "exit 3"}, func(err error) {
		gotErr = err
		close(called)
	})

	select {
	case <-called:
	default:
		t.Fatal("onExit was not called")
	}

	var exitErr *exec.ExitError
	if gotErr == nil {
		t.Fatal("onExit err = nil, want a non-zero exit error")
	}
	if !errors.As(gotErr, &exitErr) {
		t.Fatalf("onExit err = %v, want *exec.ExitError", gotErr)
	}
	if code := exitErr.ExitCode(); code != 3 {
		t.Fatalf("ExitCode() = %d, want 3", code)
	}
}

// TestRunChildSIGTERMsOnCancel proves that canceling ctx while a child
// that honours SIGTERM (sleep) is running makes runChild return well
// within the grace period, without calling onExit -- the child's death
// here is runChild's own doing, not news for main to act on.
func TestRunChildSIGTERMsOnCancel(t *testing.T) {
	called := false
	runCtx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		runChild(runCtx, []string{"sleep", "30"}, func(err error) { called = true })
		close(done)
	}()

	// Let the child actually start before canceling.
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runChild did not return after context cancellation")
	}

	if elapsed := time.Since(start); elapsed >= childGracePeriod {
		t.Fatalf("runChild took %v to return, want well under the %v grace period (sleep honours SIGTERM)", elapsed, childGracePeriod)
	}
	if called {
		t.Fatal("onExit was called for a shutdown-initiated kill, want it left uncalled")
	}
}

// TestRunChildSIGKILLsAfterGracePeriod proves a child that ignores
// SIGTERM is SIGKILLed once childGracePeriod elapses. The grace period
// is shortened for the duration of this test so the SIGKILL path is
// exercised on a fast test budget rather than the real 10s.
func TestRunChildSIGKILLsAfterGracePeriod(t *testing.T) {
	orig := childGracePeriod
	childGracePeriod = 200 * time.Millisecond
	t.Cleanup(func() { childGracePeriod = orig })

	runCtx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		runChild(runCtx, []string{"sh", "-c", `trap "" TERM; sleep 30`}, func(error) {})
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runChild did not return after context cancellation (SIGKILL path)")
	}

	elapsed := time.Since(start)
	if elapsed < childGracePeriod {
		t.Fatalf("runChild returned after %v, want at least the %v grace period to have elapsed", elapsed, childGracePeriod)
	}
	if elapsed >= 5*time.Second {
		t.Fatalf("runChild took %v to return, want it to return shortly after the %v grace period", elapsed, childGracePeriod)
	}
}

// TestRunChildEmptyArgvIsNoop proves an empty argv (mockingbird run with
// no arguments -- today's behaviour) returns immediately without
// starting anything or calling onExit.
func TestRunChildEmptyArgvIsNoop(t *testing.T) {
	called := false
	start := time.Now()

	runChild(context.Background(), nil, func(error) { called = true })

	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("runChild(nil argv) took %v, want it to return immediately", elapsed)
	}
	if called {
		t.Fatal("onExit was called for an empty argv, want it left uncalled")
	}
}

// TestChildEnvWithholdsSecrets proves the OpenCanary child never sees
// the enrolment inputs or birdcage's address (#47, #61): only the
// variables its config file expands, and what twistd needs to start.
func TestChildEnvWithholdsSecrets(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"PYTHONPATH=/opt/opencanary",
		"MOCKINGBIRD_LOG_PATH=/var/log/opencanary/opencanary.log",
		"MOCKINGBIRD_LISTEN=127.0.0.1:9919",
		"MOCKINGBIRD_BIRDCAGE_URL=https://birdcage.example:8444",
		"MOCKINGBIRD_CA_PIN=abc",
		"MOCKINGBIRD_DEPLOY_TOKEN=secret-deploy-token",
		"MOCKINGBIRD_STATE_DIR=/var/lib/mockingbird",
		"SOMETHING_ELSE=1",
	}
	got := childEnv(in)
	want := []string{
		"PATH=/usr/bin",
		"PYTHONPATH=/opt/opencanary",
		"MOCKINGBIRD_LOG_PATH=/var/log/opencanary/opencanary.log",
		"MOCKINGBIRD_LISTEN=127.0.0.1:9919",
	}
	if len(got) != len(want) {
		t.Fatalf("childEnv = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("childEnv[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	for _, kv := range got {
		for _, forbidden := range []string{"DEPLOY_TOKEN", "CA_PIN", "BIRDCAGE_URL", "STATE_DIR", "secret-deploy-token"} {
			if strings.Contains(kv, forbidden) {
				t.Fatalf("child env carries %q: %q", forbidden, kv)
			}
		}
	}
}
