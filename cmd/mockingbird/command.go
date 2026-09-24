package main

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/agent/poisoner"
	"github.com/tomlawesome/birdcage/internal/agent/probe"
	"github.com/tomlawesome/birdcage/internal/logging"
	"github.com/tomlawesome/birdcage/internal/selftest"
)

var (
	commandLog  = logging.New("command")
	selftestLog = logging.New("selftest")
)

// commandPollInterval and commandPollJitter are #48 decision 3, ratified
// by the owner 2026-09-15: "polls every 60 s with jitter, so a fleet
// does not knock in the same second" -- 60 s +/- 10 s (#46's own
// stagger decision narrows the jitter to this bound rather than
// spreading across the whole minute).
// var, not const: TestRunCommandPollLoopDispatchesAndHandlesErrors
// shrinks these for the duration of one test rather than waiting out
// the real 60s +/- 10s cadence to reach runCommandPollLoop's poll body.
var (
	commandPollInterval = 60 * time.Second
	commandPollJitter   = 10 * time.Second
)

// commandRunnerBuffer is #48's process-composition note, decision 4
// [contested]: "the poll loop hands commands to a sequential runner
// (buffer 4 [contested]); overflow drops the newest with a loud local
// log -- safe because birdcage re-mints from observed state."
const commandRunnerBuffer = 4

// kindSelfTest mirrors internal/store.CommandSelfTest's wire value
// ("selftest") rather than importing internal/store, which pulls
// internal/db behind it -- exactly the class of import this binary must
// never link (see main.go's package doc, and internal/agent/client's
// own wire types, which mirror internal/ingest's shapes the same way).
const kindSelfTest = "selftest"

// runCommandPollLoop polls for one command every commandPollInterval
// +/- commandPollJitter (#48 decision 2, owner: "plain poll. No long
// poll") and hands whatever it gets to run, dropping the newest command
// with a loud log if run's buffer is full -- safe, since birdcage
// re-mints a command from observed state rather than expecting one
// specific delivery (decision 3 of this same note).
func runCommandPollLoop(ctx context.Context, c *client.Client, ts *TokenStore, run chan<- *client.Command) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitteredInterval(commandPollInterval, commandPollJitter)):
		}

		cmd, err := authedRetryValue(ts, func(token string) (*client.Command, error) {
			return c.PollCommand(ctx, token)
		})
		if err != nil {
			if client.IsUnauthorized(err) {
				commandLog.Warn("poll: token unauthorized -- this canary has no channel to birdcage; recovery is re-enrolment (#47)")
			} else {
				commandLog.Warn(fmt.Sprintf("poll: failed, will retry next cycle: %s", safeErr(err)))
			}
			continue
		}
		if cmd == nil {
			continue
		}

		select {
		case run <- cmd:
		case <-ctx.Done():
			return
		default:
			commandLog.Warn(fmt.Sprintf("runner: buffer full, dropping newest command %s (%s) -- birdcage re-mints from observed state", cmd.ID, cmd.Kind))
		}
	}
}

// jitteredInterval returns base plus a uniformly random offset in
// [-jitter, +jitter]. math/rand, not crypto/rand: this only staggers a
// fleet's poll timing against itself, nothing security-relevant depends
// on its unpredictability.
func jitteredInterval(base, jitter time.Duration) time.Duration {
	if jitter <= 0 {
		return base
	}
	offset := time.Duration(rand.Int63n(int64(2*jitter+1))) - jitter
	return base + offset
}

// runCommandRunner executes commands from run one at a time, in arrival
// order (#48's process-composition note: "executes dispatched commands
// sequentially"), until ctx is done.
func runCommandRunner(ctx context.Context, in *Intake, bait baitLookup, run <-chan *client.Command) {
	for {
		select {
		case <-ctx.Done():
			return
		case cmd := <-run:
			if err := runCommand(ctx, in, bait, cmd); err != nil {
				commandLog.Warn(fmt.Sprintf("%s (%s): refused, executing nothing: %s", cmd.ID, cmd.Kind, safeErr(err)))
			}
		}
	}
}

// runCommand validates cmd against the one kind this agent knows today
// (store.CommandSelfTest is the only mintable kind; "upgrade" is
// unmintable until #54's verify path exists) and dispatches it. A
// non-nil return is a refusal -- unknown kind or unparseable params --
// and the command is never partially executed either way (#48
// fail-closed: "a command the agent cannot fully parse is an attack or
// version skew; both end in refusal").
func runCommand(ctx context.Context, in *Intake, bait baitLookup, cmd *client.Command) error {
	switch cmd.Kind {
	case kindSelfTest:
		return runSelfTest(ctx, in, bait, cmd)
	default:
		return fmt.Errorf("unknown command kind %q", cmd.Kind)
	}
}

// runSelfTest is the command runner's seat for a selftest command,
// filled in by #46's probe engine (internal/agent/probe). Decoding
// cmd.Params is the only way this function can refuse the command --
// selftest.DecodeParams enforces the same fail-closed rule #48 already
// established here ("a command the agent cannot fully parse is an
// attack or version skew; both end in refusal"), so a non-nil return
// from here means exactly that, never a probe result.
//
// Once params decode, every target is fired regardless of how the
// others land: per-target success or failure is logged, never returned
// as a command-level error, because a self-test's whole purpose is
// measuring which services answer -- a dead one is the expected,
// correctly-reported case, not a refusal. probe.Sweep also never writes
// into the event path itself (see its own doc comment): the probes
// produce ordinary OpenCanary events that reach birdcage by the normal
// two roads, and this function's job ends at firing them, watching a
// claim window for every attributed-grade target (#46 slice 3), and
// logging what happened for the operator and, eventually, the
// heartbeat's counters.
//
// The claim windows open before the sweep, not after it: an attributed
// probe's event is produced while the probe runs (the portscan detector
// fires on the fifth SYN, mid-sweep), and a window that only opened once
// probe.Sweep returned found nothing to claim -- the event had already
// passed through intake unclaimed, and the run never settled (MR !60
// pipeline 1524, e2e:enrol-and-hit). Every window stays open until
// selfTestClaimWindow after the sweep returns, so a late detector event
// still lands inside it; a target whose probe then fails simply closes
// with no candidate.
//
// in is the same Intake the sender and every intake road share -- its
// claims tracker (claim.go) is what turns an attributed probe's own fact
// into a claimed event, by watching the events those same roads are
// pushing concurrently with the sweep.
func runSelfTest(ctx context.Context, in *Intake, bait baitLookup, cmd *client.Command) error {
	params, err := selftest.DecodeParams(cmd.Params)
	if err != nil {
		return fmt.Errorf("selftest params: %w", err)
	}

	var windows []*claimWindow
	for _, t := range params.Targets {
		if probe.Attributed(t.Service) {
			windows = append(windows, in.claims.startWindow(t.Service, params.Address, t.Marker))
		}
	}

	outcomes := probe.Sweep(ctx, params)

	if len(windows) > 0 {
		select {
		case <-time.After(selfTestClaimWindow):
		case <-ctx.Done():
		}
		for _, w := range windows {
			in.claims.resolveWindow(w)
		}
	}

	var ok, failed, noCarrier, notProbeable, agentHandled int
	for _, o := range outcomes {
		switch o.Status {
		case probe.StatusOK:
			ok++
		case probe.StatusFailed:
			failed++
			selftestLog.Warn(fmt.Sprintf("%s: target %s:%d failed: %s", params.RunID, o.Service, o.DestPort, safeErr(o.Err)))
		case probe.StatusNoCarrier:
			noCarrier++
		case probe.StatusNotProbeable:
			notProbeable++
		case probe.StatusAgentHandled:
			agentHandled++
			runAgentHandledTarget(ctx, in, bait, params, targetFor(params, o.Service))
		}
	}
	selftestLog.Info(fmt.Sprintf("command %s: %s complete -- %d ok, %d failed, %d no-carrier, %d not-probeable, %d agent-handled (of %d targets)",
		cmd.ID, params.RunID, ok, failed, noCarrier, notProbeable, agentHandled, len(outcomes)))
	return nil
}

// baitLookup is the one thing runSelfTest needs from #86's poisoner
// detector: make a single bait lookup and say what answered. An interface
// rather than the concrete type so a test can drive both outcomes -- the
// silence that is a pass, and the answer that is an intrusion -- without
// opening a multicast socket.
type baitLookup interface {
	LookupOnce(ctx context.Context, proto poisoner.Protocol, name string) ([]poisoner.Answer, error)
}

// runAgentHandledTarget runs a target internal/agent/probe deliberately
// left to this binary (probe.StatusAgentHandled). Today that is #86's
// poisoner and nothing else.
//
// The grading is inverted from every other target: #86 slice C grades
// SILENCE as a pass, because the names the detector asks for do not
// exist and the only correct answer is none. So an answer here is not a
// better result than silence -- it is the worst result there is, and the
// alert for it has already gone out through the ordinary event path by
// the time LookupOnce returns.
//
// This currently reports to the operator's log and no further. Birdcage
// cannot yet be told that a poisoner target passed: every grade it
// records is proved by a marker-bearing event arriving
// (internal/store/selftest_grade.go), and silence produces no event to
// carry a marker. Nothing mints a poisoner target for that reason, so in
// this build this function runs only if something else starts minting
// one -- at which point the log line below is what says whether the bait
// went out.
func runAgentHandledTarget(ctx context.Context, in *Intake, bait baitLookup, params selftest.Params, target selftest.Target) {
	runID := params.RunID
	service := target.Service
	if service != poisoner.Service() {
		selftestLog.Warn(fmt.Sprintf("%s: target %s is agent-handled but this binary has nothing to run for it", runID, service))
		return
	}
	if bait == nil {
		// No result reported: birdcage must not be told a target passed on
		// a canary that never ran it. The run fails on the deadline sweep
		// like any other unanswered target, which is the honest outcome.
		selftestLog.Warn(fmt.Sprintf("%s: %s target skipped -- the poisoner road is not running on this canary", runID, service))
		return
	}

	// An empty protocol and an empty name ask the detector to choose from
	// its own profile and rotation, so this function never handles a bait
	// name -- see internal/agent/poisoner's package comment on why one
	// never reaches a log line.
	answers, err := bait.LookupOnce(ctx, "", "")
	if err != nil {
		// The probe never reached the wire, which is neither silence nor an
		// answer. Nothing is reported, for the reason above.
		selftestLog.Warn(fmt.Sprintf("%s: %s bait lookup did not go out: %s", runID, service, safeErr(err)))
		return
	}

	outcome := selfTestOutcomeSilence
	if len(answers) > 0 {
		outcome = selfTestOutcomeAnswered
		// The answering addresses only -- they are the attacker's own, and
		// the alert carrying the name, protocol and MAC is already on its
		// way to birdcage.
		for _, a := range answers {
			selftestLog.Warn(fmt.Sprintf("%s: %s bait lookup was ANSWERED by %s -- a poisoner is on this segment", runID, service, a.Source))
		}
	} else {
		// The pass. Silence is what a clean segment sounds like.
		selftestLog.Info(fmt.Sprintf("%s: %s bait lookup went out and nothing answered", runID, service))
	}

	reportSelfTestResult(in, runID, service, outcome, target.Marker)
}

// targetFor finds the target in params naming service. probe.Sweep returns
// one outcome per target in params.Targets order, so the service is enough
// to pair them -- selftest.Params.Validate already refuses a run with two
// targets sharing a marker, and nothing mints two for one service.
func targetFor(params selftest.Params, service string) selftest.Target {
	for _, t := range params.Targets {
		if t.Service == service {
			return t
		}
	}
	return selftest.Target{Service: service}
}

// reportSelfTestResult puts one result on the queue, carrying the marker
// birdcage minted for this target (#86 slice C).
//
// This is the only way a target whose pass is silence can pass at all:
// birdcage records a pass when a marker it minted arrives back, and nothing
// answering produces no other event to carry one. internal/ingest never
// stores these as alerts (opencanary.IsSelfTestResult) -- it matches the
// marker and then drops the event -- so reporting a result costs no entry on
// anybody's dashboard.
//
// The marker is never logged. A marker in a log line is one an attacker who
// reads logs could replay to have their own traffic classified as synthetic,
// which is the inversion #46 decision 4 exists to prevent.
func reportSelfTestResult(in *Intake, runID, target, outcome, marker string) {
	if marker == "" {
		selftestLog.Warn(fmt.Sprintf("%s: %s result not reported -- the target carried no marker", runID, target))
		return
	}
	message, err := encodeSelfTestResult(target, outcome, marker, selfTestNodeID(), time.Now())
	if err != nil {
		selftestLog.Warn(fmt.Sprintf("%s: could not encode the %s result: %s", runID, target, safeErr(err)))
		return
	}
	if err := in.SubmitSelfTestResultEvent(message); err != nil {
		selftestLog.Warn(fmt.Sprintf("%s: could not queue the %s result: %s", runID, target, safeErr(err)))
		return
	}
	selftestLog.Info(fmt.Sprintf("%s: reported the %s result as %s", runID, target, outcome))
}
