package main

import (
	"context"
	"errors"
	"os/exec"
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
