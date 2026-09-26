package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestWaitForShutdownReturnsOnContextCancel: the whole of this program's
// job is to stay up until asked to stop -- a cancelled context is the
// same shutdown request `docker stop`'s SIGTERM would deliver, tested
// this way because sending this test binary a real signal would also
// hit whatever else is running under `go test`.
func TestWaitForShutdownReturnsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer

	done := make(chan struct{})
	go func() {
		waitForShutdown(ctx, &out)
		close(done)
	}()

	// waitForShutdown must not return before it is asked to -- this is
	// the property that makes the container "stay up", not just "return
	// eventually". A short wait, not a race: cancel() has not been
	// called yet.
	select {
	case <-done:
		t.Fatal("waitForShutdown returned before its context was cancelled")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("waitForShutdown did not return within 2s of its context being cancelled")
	}

	if !strings.Contains(out.String(), "stopping") {
		t.Errorf("waitForShutdown wrote %q, want it to say it is stopping", out.String())
	}
}

// TestWaitForShutdownReturnsOnSIGINT proves the real path Docker and an
// operator's Ctrl-C both use: a signal sent to this process, not a
// context cancelled by other code. Sent to this test binary's own
// process, which is what signal.NotifyContext always listens on -- there
// is no way to scope it to one goroutine.
func TestWaitForShutdownReturnsOnSIGINT(t *testing.T) {
	var out bytes.Buffer
	done := make(chan struct{})
	go func() {
		waitForShutdown(context.Background(), &out)
		close(done)
	}()

	// Give the goroutine a moment to install its signal handler before
	// the signal is sent, or the send could race the subscription.
	time.Sleep(50 * time.Millisecond)
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("sending SIGINT to self: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("waitForShutdown did not return within 2s of SIGINT")
	}
}
