// command.go is ADR-0012's poll loop: Nightjar's one outbound request
// beyond its heartbeat and scan post, over the same mTLS channel
// (ADR-0010 decision 3, "no listener" -- this is an outbound poll, never
// an inbound one). Modelled on cmd/mockingbird/command.go's own poll
// loop -- same jitter, same "hand off to a sequential runner, drop the
// newest on a full buffer" shape -- narrowed to the one command kind
// this agent ever executes: `scan`, a birdcage-minted order to run one
// scan right now, tagged with a run_id so the resulting snapshot can be
// matched back to the run that asked for it (ADR-0012 decision 1).
//
// Every other command kind is logged and skipped, never executed --
// ADR-0012 decision 2's own fail-closed rule for a command kind this
// build does not implement, the same stance runCommand takes in
// cmd/mockingbird for a kind it does not recognise.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/logging"
)

var commandLog = logging.New("command")

// kindScan mirrors internal/store.CommandScan's wire value ("scan")
// rather than importing internal/store, which pulls internal/db behind
// it -- exactly the class of import this binary must never link
// (cmd/mockingbird/command.go's kindSelfTest makes the same duplication
// for the same reason).
const kindScan = "scan"

// commandPollInterval and commandPollJitter match
// cmd/mockingbird/command.go's own constants (#48 decision 3, ratified
// by the owner: "polls every 60 s with jitter, so a fleet does not knock
// in the same second"). var, not const, for the same test-speed reason
// that file gives.
var (
	commandPollInterval = 60 * time.Second
	commandPollJitter   = 10 * time.Second
)

// orderRunnerBuffer mirrors cmd/mockingbird's commandRunnerBuffer: the
// poll loop hands orders to a sequential runner through a small buffer;
// overflow drops the newest with a loud local log, safe because
// birdcage re-mints a scan command from the run's own retry cadence
// (ADR-0012 decision 3, the 30-minute pending-retry guard) rather than
// expecting one specific delivery.
const orderRunnerBuffer = 4

// scanOrder is one decoded `scan` command's run_id, the only thing the
// order runner needs to start a scan.
type scanOrder struct {
	commandID string
	runID     string
}

// scanParams mirrors ADR-0012's `scan` command params shape,
// `{"run_id": "..."}`.
type scanParams struct {
	RunID string `json:"run_id"`
}

// scanGate serialises timer and ordered scans so at most one refresh-
// and-scan cycle ever runs at a time (ADR-0012 decision 2: "an order
// arriving mid-timer-scan runs right after, as its own scan," never
// concurrently with it). A buffered channel of one, not a sync.Mutex, so
// a waiter can respect ctx cancellation at shutdown (acquire's select)
// instead of blocking indefinitely.
type scanGate chan struct{}

func newScanGate() scanGate {
	g := make(scanGate, 1)
	g <- struct{}{}
	return g
}

// acquire blocks until the gate is free or ctx is done, reporting which.
func (g scanGate) acquire(ctx context.Context) bool {
	select {
	case <-g:
		return true
	case <-ctx.Done():
		return false
	}
}

func (g scanGate) release() {
	g <- struct{}{}
}

// runCommandPollLoop polls POST /ingest/commands once every
// commandPollInterval +/- commandPollJitter and hands a decoded `scan`
// order to orders, dropping the newest with a loud log if the buffer is
// full. Any other command kind, an already-expired one, or one whose
// params do not decode is logged and skipped -- never executed, per this
// file's own doc comment.
func runCommandPollLoop(ctx context.Context, cli *client.Client, token string, orders chan<- scanOrder, now func() time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitteredInterval(commandPollInterval, commandPollJitter)):
		}

		cmd, err := cli.PollCommand(ctx, token)
		if err != nil {
			if client.IsUnauthorized(err) {
				commandLog.Warn("poll: token unauthorized -- this agent has no channel to birdcage; recovery is re-enrolment (#47)")
			} else {
				commandLog.Warn(fmt.Sprintf("poll: failed, will retry next cycle: %s", safeErr(err)))
			}
			continue
		}
		if cmd == nil {
			continue
		}

		if cmd.Kind != kindScan {
			commandLog.Warn(fmt.Sprintf("%s: unknown command kind %q, skipped -- never executed", cmd.ID, cmd.Kind))
			continue
		}
		// Defence in depth: ClaimNextCanaryCommand never delivers an
		// already-expired command (internal/store/command.go), but this
		// agent still checks its own copy of expires_at before acting,
		// the same fail-closed stance ADR-0009's own commands widening
		// asks every kind to take, rather than trusting delivery alone.
		if now().After(cmd.ExpiresAt) {
			commandLog.Warn(fmt.Sprintf("%s: scan command expired at %s, declined", cmd.ID, cmd.ExpiresAt.Format(time.RFC3339)))
			continue
		}

		var params scanParams
		if err := json.Unmarshal(cmd.Params, &params); err != nil || params.RunID == "" {
			commandLog.Warn(fmt.Sprintf("%s: scan command params unreadable, declined: %s", cmd.ID, safeErr(err)))
			continue
		}

		order := scanOrder{commandID: cmd.ID, runID: params.RunID}
		select {
		case orders <- order:
		case <-ctx.Done():
			return
		default:
			commandLog.Warn(fmt.Sprintf("runner: buffer full, dropping newest scan order %s (run %s) -- birdcage re-mints from observed state", cmd.ID, params.RunID))
		}
	}
}

// jitteredInterval returns base plus a uniformly random offset in
// [-jitter, +jitter]. math/rand, not crypto/rand: this only staggers a
// fleet's poll timing against itself (cmd/mockingbird/command.go's own
// identical function and doc comment).
func jitteredInterval(base, jitter time.Duration) time.Duration {
	if jitter <= 0 {
		return base
	}
	offset := time.Duration(rand.Int63n(int64(2*jitter+1))) - jitter
	return base + offset
}

// runOrderRunner executes scan orders from orders one at a time, in
// arrival order, taking the shared gate before each so it can never
// overlap a timer-triggered scan (scanner.go's runScanLoop takes the
// same gate). Runs until ctx is done.
func runOrderRunner(ctx context.Context, deps scanCycleDeps, gate scanGate, cli *client.Client, token string, log *slog.Logger, orders <-chan scanOrder) {
	for {
		select {
		case <-ctx.Done():
			return
		case order := <-orders:
			if !gate.acquire(ctx) {
				return
			}
			runScanOnce(ctx, cli, token, deps, log, order.runID)
			gate.release()
		}
	}
}

// dbRefreshReportIfFailing builds a *client.DBRefreshReport from
// tracker's current status, or nil when the refresh is healthy (no
// failing span) -- the "omitted entirely once healthy" half of ADR-0012
// decision 10's heartbeat contract. Shared by the ordinary heartbeat
// loop (heartbeat.go) and every stage report (below), so both surfaces
// agree on what "currently failing" means.
func dbRefreshReportIfFailing(tracker *dbRefreshTracker) *client.DBRefreshReport {
	if tracker == nil {
		return nil
	}
	status := tracker.get()
	if status.FailingSince.IsZero() {
		return nil
	}
	return &client.DBRefreshReport{
		LastOKAt:     status.LastOKAt,
		FailingSince: status.FailingSince,
		LastError:    status.LastError,
	}
}

// newStageReporter builds the reportStage function scanCycleDeps carries
// (scanner.go): a heartbeat sent the moment an ordered scan reaches a
// new stage, outside the ordinary 60-second tick (ADR-0012 decision 9).
// A failure to send is logged and otherwise ignored -- the ordinary
// heartbeat tick repeats the current stage regardless (decision 9: "and
// repeats the current stage on every ordinary tick until the run is
// answered"), so a single dropped stage report is not the run's only
// chance to be seen. That repeat lives in cmd/nightjar's run() wiring,
// which threads the same last-known stage into every ordinary tick via
// the same CommonHeartbeat.Run field -- see heartbeat.go.
func newStageReporter(cli *client.Client, token, version string, tracker *dbRefreshTracker, run *currentRunTracker, log *slog.Logger) func(ctx context.Context, runID, stage string) {
	return func(ctx context.Context, runID, stage string) {
		run.set(runID, stage)
		hb := client.CommonHeartbeat{
			AgentVersion: version,
			Run:          &client.RunReport{RunID: runID, Stage: stage},
			DBRefresh:    dbRefreshReportIfFailing(tracker),
		}
		if err := cli.SendCommonHeartbeat(ctx, token, hb); err != nil {
			log.Warn(fmt.Sprintf("%s: stage report %q: %s", runID, stage, safeErr(err)))
			return
		}
		log.Info(fmt.Sprintf("%s: stage %s", runID, stage))
	}
}
