package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
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
	cmd.Env = childEnv(os.Environ())

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

// childEnvAllowed is every environment variable the OpenCanary child is
// handed. Everything else the agent was started with is withheld -- in
// particular MOCKINGBIRD_DEPLOY_TOKEN, MOCKINGBIRD_CA_PIN and
// MOCKINGBIRD_BIRDCAGE_URL (#47, #61): OpenCanary is the process that
// faces the network, and a compromise of one of its modules must not
// read birdcage's address or a credential out of /proc/self/environ,
// spent or not. The two MOCKINGBIRD_* names here are the ones
// build/mockingbird/opencanary.conf expands; PATH/PYTHONPATH/HOME are
// what twistd needs to start at all;
// the PYTHON*/SSL_CERT_FILE ones are what build/mockingbird/Dockerfile
// sets for it.
var childEnvAllowed = map[string]bool{
	"PATH":                    true,
	"PYTHONPATH":              true,
	"PYTHONUNBUFFERED":        true,
	"PYTHONDONTWRITEBYTECODE": true,
	"SSL_CERT_FILE":           true,
	"HOME":                    true,
	"LANG":                    true,
	"TZ":                      true,
	"MOCKINGBIRD_LOG_PATH":    true,
	"MOCKINGBIRD_LISTEN":      true,
}

// childEnv filters environ (KEY=value strings, os.Environ's shape) down
// to childEnvAllowed.
func childEnv(environ []string) []string {
	out := make([]string, 0, len(childEnvAllowed))
	for _, kv := range environ {
		key, _, _ := strings.Cut(kv, "=")
		if childEnvAllowed[key] {
			out = append(out, kv)
		}
	}
	return out
}
