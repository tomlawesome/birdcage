// scanner.go is this agent's whole reason to exist: the loop that checks
// the host mount is actually covered (issue #108, "The covering is
// enforced by the agent, not only by the run command"), runs pinned
// Grype over it, and posts the resulting snapshot to birdcage.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/hostmask"
	"github.com/tomlawesome/birdcage/internal/scan"
)

// mountinfoPath is where the running container's own mount table lives
// -- always this path in any Linux container, never configurable.
const mountinfoPath = "/proc/self/mountinfo"

// ADR-0012 decision 9's closed stage vocabulary, in order. Only Nightjar
// sets these three; `ordered` and `collected` are birdcage's own
// (mint and claim), `answered` is birdcage's own (on the snapshot).
const (
	stageMountsChecked = "mounts_checked"
	stageDBRefreshed   = "db_refreshed"
	stageScanning      = "scanning"
)

// scanCycleDeps bundles everything one scan cycle needs, as functions or
// values a test can substitute -- the same injection buildSnapshot's own
// checkMounts/runScan parameters already established, widened for
// ADR-0012's refresh-before-scan step and its ordered-run stage reports.
// Built once in run() and shared, unchanged, by every timer and ordered
// cycle: only runID (passed to buildSnapshot/runScanOnce per call) ever
// varies.
type scanCycleDeps struct {
	version     string
	now         func() time.Time
	checkMounts func() error
	// refreshDB runs `grype db update` as its own step (ADR-0012
	// decision 10). Injected, like checkMounts and runScan, so a test can
	// drive a failing or succeeding refresh without a real grype binary.
	refreshDB func(context.Context) error
	runScan   func(context.Context) (scan.Result, error)
	dbTracker *dbRefreshTracker
	// reportStage sends one heartbeat reporting runID's current stage,
	// immediately, outside the ordinary heartbeat tick (ADR-0012
	// decision 9). Only ever called with a non-empty runID.
	reportStage func(ctx context.Context, runID, stage string)
	// runTracker is cleared once an ordered run's snapshot has been
	// posted, so the ordinary heartbeat loop stops repeating its stage
	// (runstate.go, heartbeat.go).
	runTracker *currentRunTracker
}

// runScanLoop runs one scan cycle immediately, then again every
// interval, until ctx is done -- "on start and on an interval" (issue
// #108, section 4), against the real mount check and the real grype
// binary. Every cycle takes gate first (ADR-0012 decision 2: never
// concurrent with an ordered scan the command runner is handling) and
// runs with an empty runID -- a timer scan reports no stages (decision
// 9's own table: `ordered`/`collected`/`answered` are birdcage's, and
// Nightjar's three stages only mean anything for a run birdcage is
// tracking).
func runScanLoop(ctx context.Context, cli *client.Client, token string, deps scanCycleDeps, gate scanGate, interval time.Duration, log *slog.Logger) {
	runLoop(ctx, interval, func() {
		if !gate.acquire(ctx) {
			return
		}
		defer gate.release()
		runScanOnce(ctx, cli, token, deps, log, "")
	})
}

// runLoop calls cycle immediately, then again every interval, until ctx
// is done -- the cadence contract on its own, with no client or scanner
// dependency, so a test can prove "runs immediately, stops promptly on
// cancel" without building either (see scanner_test.go). A cycle's own
// failure never stops the loop: whatever cycle does with an error (log
// and continue, in runScanOnce's case) is its own concern, the same
// "keep the process alive" shape cmd/mockingbird's own long-lived loops
// follow.
func runLoop(ctx context.Context, interval time.Duration, cycle func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		cycle()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// realScan is runScanLoop's production runScan argument: pinned Grype
// over the real host bind. A test substitutes a stub here instead of
// exec'ing a real grype binary.
func realScan(ctx context.Context) (scan.Result, error) {
	return scan.Run(ctx, grypeBin, hostRoot)
}

// runScanOnce builds and posts exactly one snapshot for runID (empty for
// a timer scan): checkMounts first (never scanning if it fails), then
// refreshDB, then runScan, then SendScan. Every path through
// buildSnapshot ends in a snapshot with a status -- ADR-0010 decision 8,
// "the agent never posts an empty finding set it did not earn" -- there
// is no code path here that skips posting anything.
func runScanOnce(ctx context.Context, cli *client.Client, token string, deps scanCycleDeps, log *slog.Logger, runID string) {
	snapshot := buildSnapshot(ctx, deps, runID)
	if err := cli.SendScan(ctx, token, snapshot); err != nil {
		log.Warn(fmt.Sprintf("send scan: %s", safeErr(err)))
		return
	}
	if runID != "" && deps.runTracker != nil {
		// Answered -- birdcage now has the snapshot. The ordinary
		// heartbeat loop stops repeating this run's stage from here
		// (decision 9's "answered" close); a send failure above leaves
		// the tracker set instead, so the next ordinary tick keeps
		// reporting the last stage reached until a retry succeeds.
		deps.runTracker.clear()
	}
	log.Info(fmt.Sprintf("scan posted: run_id=%s status=%s findings=%d", snapshot.RunID, snapshot.Status, len(snapshot.Findings)))
}

// buildSnapshot runs checkMounts and, if it holds, refreshDB and then
// runScan, and turns the outcome into a client.Snapshot ready to post.
// MaskedPaths is always the full configured list (hostmask.Paths()), on
// every snapshot regardless of status -- issue #108: "present on both
// ... since the blind spot exists either way."
//
// Stage reports (ADR-0012 decision 9) are sent only when runID is
// non-empty, and only for a run that keeps going: a mount-check failure
// is posted at once as a failed snapshot with no stage report at all
// (decision 9's own table -- "a failure Nightjar can see ... is still
// posted as a status: failed snapshot at once, as today ... stages add
// nothing there"). db_refreshed is reported once refreshDB returns,
// whether or not it succeeded -- this implementation's own reading of
// decision 9's table entry ("finished, with or without success"), taken
// as the resolution of that decision's own noted ambiguity.
func buildSnapshot(ctx context.Context, deps scanCycleDeps, runID string) client.Snapshot {
	ordered := runID != ""
	takenAt := deps.now().UTC()
	maskedPaths := hostmask.Paths()

	if err := deps.checkMounts(); err != nil {
		return client.Snapshot{
			RunID:        runID,
			TakenAt:      takenAt,
			AgentVersion: deps.version,
			Status:       scan.StatusFailed,
			Reason:       err.Error(),
			MaskedPaths:  maskedPaths,
		}
	}
	if ordered {
		deps.reportStage(ctx, runID, stageMountsChecked)
	}

	refreshedAt, refreshErrText := runRefresh(ctx, deps, deps.now())
	if ordered {
		deps.reportStage(ctx, runID, stageDBRefreshed)
	}

	if ordered {
		deps.reportStage(ctx, runID, stageScanning)
	}
	result, err := deps.runScan(ctx)
	if err != nil {
		// Only returned when ctx was already done before grype could
		// even start (scan.Run's own doc comment) -- still a failed
		// scan, never silence.
		return client.Snapshot{
			RunID:        runID,
			TakenAt:      takenAt,
			AgentVersion: deps.version,
			Status:       scan.StatusFailed,
			Reason:       err.Error(),
			MaskedPaths:  maskedPaths,
			Engine:       client.Engine{DBRefreshedAt: refreshedAt, DBRefreshError: refreshErrText},
		}
	}

	snapshot := snapshotFromResult(takenAt, deps.version, result, maskedPaths)
	snapshot.RunID = runID
	snapshot.Engine.DBRefreshedAt = refreshedAt
	snapshot.Engine.DBRefreshError = refreshErrText
	return snapshot
}

// runRefresh runs deps.refreshDB, records the outcome on deps.dbTracker
// (ADR-0012 decision 10 -- "persisted ... so a restart does not forget
// it"), and returns what this cycle's snapshot should carry: the last
// successful refresh's time (unchanged from before this cycle when this
// attempt failed) and this cycle's own error text (empty on success --
// "the refresh's error text when this scan's refresh failed", not a
// stale one from an earlier cycle).
func runRefresh(ctx context.Context, deps scanCycleDeps, now time.Time) (refreshedAt time.Time, errText string) {
	if err := deps.refreshDB(ctx); err != nil {
		status := deps.dbTracker.recordFailure(now, err.Error())
		return status.LastOKAt, err.Error()
	}
	status := deps.dbTracker.recordSuccess(now)
	return status.LastOKAt, ""
}

// snapshotFromResult carries internal/scan.Result's fields onto
// client.Snapshot's wire-facing shape -- a field-for-field mirror,
// deliberately duplicated rather than sharing a type: internal/scan is
// fenced to this binary alone (ADR-0009 decision 6) and
// internal/agent/client must never depend on it, matching that
// package's own doc comment on wireScan.
func snapshotFromResult(takenAt time.Time, version string, result scan.Result, maskedPaths []string) client.Snapshot {
	findings := make([]client.Finding, len(result.Findings))
	for i, f := range result.Findings {
		findings[i] = client.Finding{
			Target:        f.Target,
			Package:       f.Package,
			Version:       f.Version,
			Type:          f.Type,
			Vulnerability: f.Vulnerability,
			Severity:      f.Severity,
			FixVersion:    f.FixVersion,
		}
	}
	return client.Snapshot{
		TakenAt:      takenAt,
		AgentVersion: version,
		Engine: client.Engine{
			Name:      result.Engine.Name,
			Version:   result.Engine.Version,
			DBBuiltAt: result.Engine.DBBuiltAt,
		},
		Status:      result.Status,
		Reason:      result.Reason,
		Findings:    findings,
		MaskedPaths: maskedPaths,
	}
}

// checkMounts is issue #108's agent-side host-mount enforcement: read
// this container's own mount table and require every existing mask to
// be covered, and every mount under hostRoot to be read-only
// (internal/hostmask.Check). A non-nil error here means the run command
// was edited and the covering silently lost, or an engine older than
// Docker 25 left a host submount writable underneath the root bind --
// either way, the caller must not scan.
func checkMounts() error {
	f, err := os.Open(mountinfoPath)
	if err != nil {
		return fmt.Errorf("read mountinfo: %s", safeErr(err))
	}
	defer func() { _ = f.Close() }()

	mounts, err := hostmask.ParseMountinfo(f)
	if err != nil {
		return err
	}

	exists := func(p string) bool {
		_, err := os.Stat(p)
		return err == nil
	}
	return hostmask.Check(hostRoot, mounts, exists)
}
