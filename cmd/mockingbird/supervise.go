package main

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// childGracePeriod is how long runChild waits after SIGTERM before
// SIGKILLing a child that has not exited on its own. A package variable
// rather than a constant so a test can shorten it, proving the SIGKILL
// path within a fast test budget instead of waiting out the real 10s.
var childGracePeriod = 10 * time.Second

// runChild is mockingbird supervising OpenCanary as its child process
// (#69's ratified decision, superseding a separate systemd unit):
// mockingbird is the container's main process, so nothing else restarts
// OpenCanary, reaps it, or notices it died.
//
// argv is run exactly as given, no shell, with stdout/stderr and
// mockingbird's own environment inherited, so the container log carries
// OpenCanary's own output. An empty argv means no child at all --
// runChild returns immediately, onExit is never called, and behaviour is
// exactly what it is today when mockingbird is run with no arguments.
//
// runChild blocks for the lifetime of the child. Callers run it in its
// own goroutine, started only once the intake receiver is already
// listening -- so OpenCanary's very first webhook attempt (it makes
// exactly one, and drops it on failure) finds the receiver open.
//
// Two ways out:
//
//   - ctx is canceled (SIGINT/SIGTERM reaching mockingbird, or anything
//     else that cancels the run): runChild sends SIGTERM, waits up to
//     childGracePeriod, and SIGKILLs the child if it is still alive, then
//     returns. onExit is not called on this path -- the child's death
//     here is mockingbird's own doing, not news to report.
//   - the child exits on its own, for any reason, before ctx is
//     canceled: runChild calls onExit with the exit error (nil for a
//     clean exit) and returns. main's onExit logs the status and cancels
//     the run, so every other goroutine stops as it would on a signal --
//     OpenCanary dying must take the container down so the restart
//     policy restarts both of them together (#45): a canary whose
//     honeypot is dead while its agent keeps heartbeating "healthy" is a
//     lie birdcage cannot see.
//
// No orphan reaping (no wait4(-1) loop): OpenCanary spawns no children of
// its own, and Docker's --init covers anything that would need it.
func runChild(ctx context.Context, argv []string, onExit func(error)) {
	if len(argv) == 0 {
		return
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	if err := cmd.Start(); err != nil {
		onExit(err)
		return
	}

	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()

	select {
	case err := <-waitErr:
		onExit(err)
	case <-ctx.Done():
		// Signal errors are ignored: if the child already exited between
		// the two select cases becoming ready, the process is gone and
		// there is nothing left to signal -- waitErr below still
		// unblocks either way.
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-waitErr:
		case <-time.After(childGracePeriod):
			_ = cmd.Process.Kill()
			<-waitErr
		}
	}
}
