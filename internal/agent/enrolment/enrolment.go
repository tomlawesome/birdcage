// Package enrolment is the boot-time enrolment orchestration every agent
// kind runs: decide whether this boot needs to enrol at all, run "The
// flow"'s FirstContact/Provision steps (internal/agent/enrol) with
// bounded retry, and durably persist whatever the caller's own state
// layout requires. Factored out of cmd/mockingbird, where it was package
// main and therefore unimportable, so a second agent kind (the scanner,
// #108) can reuse it rather than copy-pasting it and drifting.
//
// Which files an enrolled agent persists, and what its state directory's
// "already enrolled" test looks like, are facts about the agent kind,
// not about enrolment itself -- Params keeps both caller-supplied so
// this package stays agent-agnostic.
package enrolment

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/atomicfile"
	"github.com/tomlawesome/birdcage/internal/agent/enrol"
)

// RetryInitialBackoff and RetryMaxElapsed bound how long boot-time
// enrolment ("The flow" steps 3, 5 and 6) keeps retrying a birdcage it
// cannot yet reach: RetryInitialBackoff, doubling each attempt, giving up
// once the total elapsed wait would exceed RetryMaxElapsed. Only a
// network failure -- dial, TLS, timeout, a refused redirect, a canceled
// context -- is retried at all; anything birdcage actually answered (a
// refusal, a malformed body) is deterministic, so retrying it would only
// spend the window for no chance of a different outcome (see
// retryEnrolStep).
const (
	RetryInitialBackoff = 2 * time.Second
	RetryMaxElapsed     = 4 * time.Minute
)

// StateFile is one file EnsureEnrolled durably writes once enrolment
// succeeds -- Name is relative to Params.StateDir.
type StateFile struct {
	Name string
	Data []byte
}

// Params is everything EnsureEnrolled needs from its caller.
type Params struct {
	// StateDir is the directory enrolment reads from and writes to.
	StateDir string
	// BirdcageURL is the enrolment listener's address.
	BirdcageURL string
	// CAPin and DeployToken are the pinned CA fingerprint and one-time
	// deploy token issued alongside it -- empty when this boot is not
	// meant to enrol.
	CAPin       string
	DeployToken string

	// DeployTokenEnvName names the deploy-token environment variable in
	// the "already enrolled" log line, e.g. "MOCKINGBIRD_DEPLOY_TOKEN" --
	// caller-supplied so the line names the right variable for whichever
	// agent kind is enrolling.
	DeployTokenEnvName string
	// RequiredFiles are the state files inside StateDir whose presence,
	// all of them, means "already enrolled". Some but not all present is
	// always a startup failure, whatever the caller passes here.
	RequiredFiles []string
	// NodeNoun is the noun the success log line uses, e.g. "canary". An
	// empty NodeNoun falls back to "agent".
	NodeNoun string
	// WriteState turns a successful enrolment's Hello/Credentials into
	// the files this agent kind persists.
	WriteState func(enrol.Hello, enrol.Credentials) []StateFile

	// Log receives every line this package prints ("enrolling with ...",
	// "already enrolled; ignoring ...", the retry warning, "enrolled as
	// ... "). Required.
	Log *slog.Logger
}

// EnsureEnrolled decides whether this boot needs to enrol before reading
// anything else out of Params.StateDir, and runs that enrolment if so.
//
//   - All of RequiredFiles present: this agent is already enrolled.
//     CAPin/DeployToken, if either is set, are ignored -- logged once,
//     and never their values.
//   - None present, and both CAPin and DeployToken are set: enrol now.
//   - None present, and CAPin/DeployToken are not both set: nothing to
//     do here -- the caller's own state-directory reads fail naming the
//     first missing file, exactly as they did before enrolment existed.
//   - Some but not all present: fail closed, naming every missing file
//     at once -- a half-enrolled state directory is not a state
//     CAPin/DeployToken can repair, whatever they're set to, and reading
//     each missing file in turn would only report the first.
func EnsureEnrolled(ctx context.Context, p Params) error {
	var present, absent []string
	for _, name := range p.RequiredFiles {
		if _, err := os.Stat(filepath.Join(p.StateDir, name)); err == nil {
			present = append(present, name)
		} else {
			absent = append(absent, name)
		}
	}

	switch {
	case len(absent) == 0:
		if p.CAPin != "" || p.DeployToken != "" {
			p.Log.Info(fmt.Sprintf("already enrolled; ignoring %s", p.DeployTokenEnvName))
		}
		return nil
	case len(present) > 0:
		return fmt.Errorf("incomplete enrolment state in state directory, missing: %s", strings.Join(absent, ", "))
	case p.CAPin == "" || p.DeployToken == "":
		return nil
	default:
		return enrolAtBoot(ctx, p)
	}
}

// enrolAtBoot runs "The flow" steps 3 (FirstContact), 5 (Provision) and 6
// (writing the resulting state to disk) in order, against
// p.BirdcageURL -- at this point in a caller's own config loading, still
// its enrolment listener's own address, since nothing has written an
// ingest-URL state file yet.
func enrolAtBoot(ctx context.Context, p Params) error {
	p.Log.Info(fmt.Sprintf("enrolling with %s", hostPort(p.BirdcageURL)))

	hello, err := retryEnrolStep(ctx, p.Log, func(ctx context.Context) (enrol.Hello, error) {
		return enrol.FirstContact(ctx, p.BirdcageURL, p.CAPin, p.DeployToken)
	})
	if err != nil {
		if errors.Is(err, enrol.ErrRefused) {
			return errors.New("deploy token refused: it may have been used already, expired, or a second container may be using it")
		}
		return fmt.Errorf("enrolment: first contact: %s", redactErr(err))
	}

	creds, err := retryEnrolStep(ctx, p.Log, func(ctx context.Context) (enrol.Credentials, error) {
		return enrol.Provision(ctx, p.BirdcageURL, hello.CAPEM, hello.EnrolmentSecret)
	})
	if err != nil {
		if errors.Is(err, enrol.ErrRefused) {
			return errors.New("enrolment secret refused: the provisioning window may have expired, or a second container may be using it")
		}
		return fmt.Errorf("enrolment: provision: %s", redactErr(err))
	}

	if err := writeState(p.StateDir, p.WriteState(hello, creds)); err != nil {
		return fmt.Errorf("enrolment: write state: %s", redactErr(err))
	}

	noun := p.NodeNoun
	if noun == "" {
		noun = "agent"
	}
	p.Log.Info(fmt.Sprintf("enrolled as %s %s", noun, creds.CanaryID))
	return nil
}

// retryEnrolStep runs step once, and again on backoff
// (RetryInitialBackoff, doubling) for as long as it keeps failing with a
// *enrol.RetryableError -- a call that never reached birdcage at all.
// Any other error, including enrol.ErrRefused, is returned immediately on
// the first attempt: both are deterministic, so retrying either would
// only spend RetryMaxElapsed's budget for no chance of a different
// outcome. Giving up once the next wait would cross RetryMaxElapsed turns
// "birdcage never became reachable" into a bounded startup failure
// instead of an indefinite hang.
func retryEnrolStep[T any](ctx context.Context, log *slog.Logger, step func(context.Context) (T, error)) (T, error) {
	backoff := RetryInitialBackoff
	deadline := time.Now().Add(RetryMaxElapsed)
	for {
		val, err := step(ctx)
		if err == nil || !enrol.IsRetryable(err) {
			return val, err
		}
		if time.Now().Add(backoff).After(deadline) {
			return val, fmt.Errorf("gave up after repeated network errors: %w", err)
		}
		log.Warn(fmt.Sprintf("network error, retrying in %s: %s", backoff, redactErr(err)))
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return val, ctx.Err()
		case <-timer.C:
		}
		backoff *= 2
	}
}

// writeState durably writes every file in files under stateDir, via
// atomicfile.Write, all mode 0600. Each write is independent: a crash or
// failure partway through leaves whichever files landed durably on disk
// and the rest simply absent, which the next boot's EnsureEnrolled
// reports as incomplete enrolment state rather than silently reusing a
// half-written credential set.
func writeState(stateDir string, files []StateFile) error {
	for _, f := range files {
		if err := atomicfile.Write(filepath.Join(stateDir, f.Name), f.Data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", f.Name, err)
		}
	}
	return nil
}

// hostPort returns rawURL's host:port for the "enrolling with ..." log
// line -- never the full URL (which is not secret, but host:port is all
// the line needs to say). An unparseable rawURL falls back to a fixed
// placeholder rather than risking printing something unexpected.
func hostPort(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "birdcage"
	}
	return u.Host
}

// redactErr mirrors cmd/mockingbird/safelog.go's safeErr: render err's
// message with any filesystem path or network address it names
// redacted, so this package's own log lines never leak a state directory
// path or a listen address through a wrapped *fs.PathError or
// *net.OpError. Duplicated rather than shared -- safeErr stays private to
// cmd/mockingbird and is not part of this move -- so keep the two in sync
// if either changes.
func redactErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()

	var pathErr *fs.PathError
	if errors.As(err, &pathErr) && pathErr.Path != "" {
		msg = strings.ReplaceAll(msg, pathErr.Path, "<path redacted>")
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Addr != nil {
		msg = strings.ReplaceAll(msg, opErr.Addr.String(), "<address redacted>")
	}

	return msg
}
