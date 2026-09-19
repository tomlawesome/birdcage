package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/enrol"
	"github.com/tomlawesome/birdcage/internal/logging"
)

var enrolLog = logging.New("enrol")

// enrolRetryInitialBackoff and enrolRetryMaxElapsed bound how long boot-time
// enrolment (#47 "The flow" steps 3, 5 and 6) keeps retrying a birdcage it
// cannot yet reach: 2s, doubling each attempt, giving up once the total
// elapsed wait would exceed four minutes. Only a network failure -- dial,
// TLS, timeout, a refused redirect, a canceled context -- is retried at
// all; anything birdcage actually answered (a refusal, a malformed body)
// is deterministic, so retrying it would only spend the window for no
// chance of a different outcome (see retryEnrolStep).
const (
	enrolRetryInitialBackoff = 2 * time.Second
	enrolRetryMaxElapsed     = 4 * time.Minute
)

// ensureEnrolled is loadConfig's own first step: decide whether this boot
// needs to enrol before reading anything else out of stateDir, and run
// that enrolment if so.
//
//   - All four of enrolStateFiles present: this canary is already
//     enrolled. caPin/deployToken, if either is set, are ignored -- logged
//     once, and never their values.
//   - None present, and both caPin and deployToken are set: enrol now
//     (enrolAtBoot), before anything else runs.
//   - None present, and caPin/deployToken are not both set: nothing to do
//     here -- loadConfig's own os.ReadFile calls fail naming the first
//     missing file, exactly as they did before this existed ("today's
//     failure").
//   - Some but not all present: fail closed, naming every missing file at
//     once -- a half-enrolled state directory is not a state envCAPin/
//     envDeployToken can repair, whatever they're set to, and reading
//     each missing file in turn would only report the first.
func ensureEnrolled(stateDir, birdcageURL, caPin, deployToken string) error {
	var present, absent []string
	for _, name := range enrolStateFiles {
		if _, err := os.Stat(filepath.Join(stateDir, name)); err == nil {
			present = append(present, name)
		} else {
			absent = append(absent, name)
		}
	}

	switch {
	case len(absent) == 0:
		if caPin != "" || deployToken != "" {
			enrolLog.Info("already enrolled; ignoring MOCKINGBIRD_DEPLOY_TOKEN")
		}
		return nil
	case len(present) > 0:
		return fmt.Errorf("incomplete enrolment state in state directory, missing: %s", strings.Join(absent, ", "))
	case caPin == "" || deployToken == "":
		return nil
	default:
		return enrolAtBoot(stateDir, birdcageURL, caPin, deployToken)
	}
}

// enrolAtBoot runs #47 "The flow" steps 3 (FirstContact), 5 (Provision) and
// 6 (writing the resulting state to disk) in order, against birdcageURL --
// which at this point in loadConfig is still envBirdcageURL verbatim, the
// enrolment listener's own address, since nothing has written
// ingestURLFileName yet.
func enrolAtBoot(stateDir, birdcageURL, caPin, deployToken string) error {
	ctx := context.Background()
	enrolLog.Info(fmt.Sprintf("enrolling with %s", hostPort(birdcageURL)))

	hello, err := retryEnrolStep(ctx, func(ctx context.Context) (enrol.Hello, error) {
		return enrol.FirstContact(ctx, birdcageURL, caPin, deployToken)
	})
	if err != nil {
		if errors.Is(err, enrol.ErrRefused) {
			return errors.New("deploy token refused: it may have been used already, expired, or a second container may be using it")
		}
		return fmt.Errorf("enrolment: first contact: %s", safeErr(err))
	}

	creds, err := retryEnrolStep(ctx, func(ctx context.Context) (enrol.Credentials, error) {
		return enrol.Provision(ctx, birdcageURL, hello.CAPEM, hello.EnrolmentSecret)
	})
	if err != nil {
		if errors.Is(err, enrol.ErrRefused) {
			return errors.New("enrolment secret refused: the provisioning window may have expired, or a second container may be using it")
		}
		return fmt.Errorf("enrolment: provision: %s", safeErr(err))
	}

	if err := writeEnrolmentState(stateDir, hello, creds); err != nil {
		return fmt.Errorf("enrolment: write state: %s", safeErr(err))
	}

	enrolLog.Info(fmt.Sprintf("enrolled as canary %s", creds.CanaryID))
	return nil
}

// retryEnrolStep runs step once, and again on backoff (enrolRetryInitialBackoff,
// doubling) for as long as it keeps failing with a *enrol.RetryableError --
// a call that never reached birdcage at all. Any other error, including
// enrol.ErrRefused, is returned immediately on the first attempt: both are
// deterministic, so retrying either would only spend enrolRetryMaxElapsed's
// budget for no chance of a different outcome. Giving up once the next
// wait would cross enrolRetryMaxElapsed turns "birdcage never became
// reachable" into a bounded startup failure instead of an indefinite hang.
func retryEnrolStep[T any](ctx context.Context, step func(context.Context) (T, error)) (T, error) {
	backoff := enrolRetryInitialBackoff
	deadline := time.Now().Add(enrolRetryMaxElapsed)
	for {
		val, err := step(ctx)
		if err == nil || !enrol.IsRetryable(err) {
			return val, err
		}
		if time.Now().Add(backoff).After(deadline) {
			return val, fmt.Errorf("gave up after repeated network errors: %w", err)
		}
		enrolLog.Warn(fmt.Sprintf("network error, retrying in %s: %s", backoff, safeErr(err)))
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

// writeEnrolmentState durably writes everything FirstContact and Provision
// returned -- #47 "The flow" step 6 -- via the same atomic-write helper
// (atomic.go) every other file this agent persists uses, all mode 0600.
// Each write is independent: a crash or failure partway through leaves
// whichever files landed durably on disk and the rest simply absent, which
// the next boot's ensureEnrolled reports as incomplete enrolment state
// rather than silently reusing a half-written credential set.
func writeEnrolmentState(stateDir string, hello enrol.Hello, creds enrol.Credentials) error {
	writes := []struct {
		name string
		data []byte
	}{
		{caFileName, hello.CAPEM},
		{clientCertFileName, creds.ClientCertPEM},
		{clientKeyFileName, creds.ClientKeyPEM},
		{tokenFileName, []byte(creds.CanaryToken)},
		{ingestURLFileName, []byte(hello.IngestURL)},
		{adminApprovalAddressFileName, []byte(hello.AdminApprovalAddress)},
		{releaseAddressFileName, []byte(hello.ReleaseAddress)},
	}
	for _, w := range writes {
		if err := writeFileAtomic(filepath.Join(stateDir, w.name), w.data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", w.name, err)
		}
	}
	return nil
}

// hostPort returns rawURL's host:port for the "enrolling with ..." log
// line -- never the full URL (which is not secret, but host:port is all
// the line needs to say). An unparseable rawURL (should not happen; it is
// envBirdcageURL, already validated non-empty by loadConfig) falls back to
// a fixed placeholder rather than risking printing something unexpected.
func hostPort(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "birdcage"
	}
	return u.Host
}
