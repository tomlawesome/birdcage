package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/hostmask"
	"github.com/tomlawesome/birdcage/internal/scan"
)

func fixedNow(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// stageRecorder is a test double for scanCycleDeps.reportStage: it
// records every stage reported, in order, without sending a real
// heartbeat -- what TestBuildSnapshotOrdered* below assert against.
type stageRecorder struct {
	mu     sync.Mutex
	runIDs []string
	stages []string
}

func (r *stageRecorder) report(ctx context.Context, runID, stage string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runIDs = append(r.runIDs, runID)
	r.stages = append(r.stages, stage)
}

func (r *stageRecorder) get() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.stages...)
}

// testDeps builds a scanCycleDeps for unit tests: a healthy no-op
// refresh by default (overridden per test where the refresh path itself
// is under test), and a fresh dbTracker/runTracker so nothing here
// touches disk (a "" stateDir tracker never persists -- dbrefresh.go's
// own persistLocked).
func testDeps(now func() time.Time, checkMounts func() error, runScan func(context.Context) (scan.Result, error)) (scanCycleDeps, *stageRecorder) {
	rec := &stageRecorder{}
	return scanCycleDeps{
		version:     "v1.2.3",
		now:         now,
		checkMounts: checkMounts,
		refreshDB:   func(context.Context) error { return nil },
		runScan:     runScan,
		dbTracker:   newDBRefreshTracker("", dbRefreshStatus{}),
		reportStage: rec.report,
		runTracker:  newCurrentRunTracker(),
	}, rec
}

// TestBuildSnapshotMountCheckFailureNeverScans is ADR-0010 decision 8
// and #108's own agent-side enforcement, at the unit level: when
// checkMounts fails, runScan must never be called at all, and the
// resulting snapshot is "failed" with the mount error as its reason and
// zero findings -- never an empty finding set presented as clean. Also
// ADR-0012 decision 9: a mount-check failure reports no stage at all,
// even for an ordered run.
func TestBuildSnapshotMountCheckFailureNeverScans(t *testing.T) {
	scanCalled := false
	checkMounts := func() error { return errors.New("hostmask: /host/home exists but is not covered by a mount") }
	runScan := func(context.Context) (scan.Result, error) {
		scanCalled = true
		return scan.Result{}, nil
	}

	takenAt := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	deps, rec := testDeps(fixedNow(takenAt), checkMounts, runScan)
	deps.version = "v1.2.3"
	snap := buildSnapshot(context.Background(), deps, "run-1")

	if scanCalled {
		t.Error("runScan was called despite a failed mount check")
	}
	if snap.Status != scan.StatusFailed {
		t.Errorf("Status = %q, want %q", snap.Status, scan.StatusFailed)
	}
	if snap.Reason == "" {
		t.Error("Reason is empty on a mount-check failure")
	}
	if len(snap.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0 on a failed snapshot", len(snap.Findings))
	}
	if snap.AgentVersion != "v1.2.3" {
		t.Errorf("AgentVersion = %q, want %q", snap.AgentVersion, "v1.2.3")
	}
	if !snap.TakenAt.Equal(takenAt) {
		t.Errorf("TakenAt = %v, want %v", snap.TakenAt, takenAt)
	}
	if len(snap.MaskedPaths) != len(hostmask.Masks) {
		t.Errorf("len(MaskedPaths) = %d, want %d (present on a failed snapshot too)", len(snap.MaskedPaths), len(hostmask.Masks))
	}
	if snap.RunID != "run-1" {
		t.Errorf("RunID = %q, want run-1", snap.RunID)
	}
	if len(rec.get()) != 0 {
		t.Errorf("stages reported = %v, want none on a mount-check failure", rec.get())
	}
}

// TestBuildSnapshotScanErrorIsFailed proves a runScan Go error (context
// canceled before grype could start, scan.Run's own doc comment) also
// becomes a failed snapshot, never a silent skip.
func TestBuildSnapshotScanErrorIsFailed(t *testing.T) {
	checkMounts := func() error { return nil }
	runScan := func(context.Context) (scan.Result, error) {
		return scan.Result{}, errors.New("context canceled")
	}

	deps, _ := testDeps(fixedNow(time.Now()), checkMounts, runScan)
	snap := buildSnapshot(context.Background(), deps, "")
	if snap.Status != scan.StatusFailed {
		t.Errorf("Status = %q, want %q", snap.Status, scan.StatusFailed)
	}
	if snap.Reason == "" {
		t.Error("Reason is empty")
	}
}

// TestBuildSnapshotOKCarriesFindingsAndMasks proves the happy path:
// runScan's Result reaches the posted Snapshot unchanged, alongside the
// masked-path list -- issue #108: "the snapshot records the masked
// paths, so the blind spot is visible ... rather than implied."
func TestBuildSnapshotOKCarriesFindingsAndMasks(t *testing.T) {
	dbBuilt := time.Date(2026, 9, 20, 1, 0, 0, 0, time.UTC)
	checkMounts := func() error { return nil }
	runScan := func(context.Context) (scan.Result, error) {
		return scan.Result{
			Status: scan.StatusOK,
			Engine: scan.Engine{Name: "grype", Version: "0.119.0", DBBuiltAt: dbBuilt},
			Findings: []scan.Finding{
				{Target: "dir:/host", Package: "openssl", Version: "1.0.1f", Type: "deb", Vulnerability: "CVE-2014-0160", Severity: "critical", FixVersion: "1.0.1f-1ubuntu2.1"},
			},
		}, nil
	}

	deps, _ := testDeps(fixedNow(time.Now()), checkMounts, runScan)
	snap := buildSnapshot(context.Background(), deps, "")
	if snap.Status != scan.StatusOK {
		t.Fatalf("Status = %q, want %q", snap.Status, scan.StatusOK)
	}
	if snap.Reason != "" {
		t.Errorf("Reason = %q, want empty on success", snap.Reason)
	}
	if len(snap.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(snap.Findings))
	}
	f := snap.Findings[0]
	if f.Vulnerability != "CVE-2014-0160" || f.Package != "openssl" || f.FixVersion != "1.0.1f-1ubuntu2.1" {
		t.Errorf("Findings[0] = %+v, unexpected", f)
	}
	if snap.Engine.Name != "grype" || snap.Engine.Version != "0.119.0" || !snap.Engine.DBBuiltAt.Equal(dbBuilt) {
		t.Errorf("Engine = %+v, unexpected", snap.Engine)
	}
	if len(snap.MaskedPaths) != len(hostmask.Masks) {
		t.Errorf("len(MaskedPaths) = %d, want %d", len(snap.MaskedPaths), len(hostmask.Masks))
	}
	if snap.RunID != "" {
		t.Errorf("RunID = %q, want empty for a timer scan", snap.RunID)
	}
}

// TestBuildSnapshotOrderedEmitsThreeStagesInOrder is ADR-0012 decision 9
// at the unit level: an ordered scan that reaches Grype reports exactly
// mounts_checked, db_refreshed, scanning, in that order, and the
// resulting snapshot carries the run's id.
func TestBuildSnapshotOrderedEmitsThreeStagesInOrder(t *testing.T) {
	checkMounts := func() error { return nil }
	runScan := func(context.Context) (scan.Result, error) {
		return scan.Result{Status: scan.StatusOK}, nil
	}

	deps, rec := testDeps(fixedNow(time.Now()), checkMounts, runScan)
	snap := buildSnapshot(context.Background(), deps, "run-42")

	if snap.RunID != "run-42" {
		t.Errorf("RunID = %q, want run-42", snap.RunID)
	}
	got := rec.get()
	want := []string{stageMountsChecked, stageDBRefreshed, stageScanning}
	if len(got) != len(want) {
		t.Fatalf("stages = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("stages[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

// TestBuildSnapshotTimerScanEmitsNoStages proves the other half of
// decision 9: a timer scan (empty runID) never calls reportStage at
// all, even when it reaches Grype successfully.
func TestBuildSnapshotTimerScanEmitsNoStages(t *testing.T) {
	checkMounts := func() error { return nil }
	runScan := func(context.Context) (scan.Result, error) {
		return scan.Result{Status: scan.StatusOK}, nil
	}

	deps, rec := testDeps(fixedNow(time.Now()), checkMounts, runScan)
	snap := buildSnapshot(context.Background(), deps, "")

	if snap.RunID != "" {
		t.Errorf("RunID = %q, want empty", snap.RunID)
	}
	if len(rec.get()) != 0 {
		t.Errorf("stages reported = %v, want none for a timer scan", rec.get())
	}
}

// TestBuildSnapshotRefreshRunsBeforeEveryScan proves ADR-0012 decision
// 10's ordering: refreshDB is called, and its outcome recorded on
// dbTracker, before runScan -- for a timer scan just as much as an
// ordered one.
func TestBuildSnapshotRefreshRunsBeforeEveryScan(t *testing.T) {
	var order []string
	checkMounts := func() error { return nil }
	deps, _ := testDeps(fixedNow(time.Now()), checkMounts, func(context.Context) (scan.Result, error) {
		order = append(order, "scan")
		return scan.Result{Status: scan.StatusOK}, nil
	})
	deps.refreshDB = func(context.Context) error {
		order = append(order, "refresh")
		return nil
	}

	buildSnapshot(context.Background(), deps, "")

	if len(order) != 2 || order[0] != "refresh" || order[1] != "scan" {
		t.Errorf("order = %v, want [refresh scan]", order)
	}
}

// TestBuildSnapshotSuccessfulRefreshCarriesDBRefreshedAt proves a
// successful refresh's timestamp reaches the snapshot's
// Engine.DBRefreshedAt, and DBRefreshError is empty.
func TestBuildSnapshotSuccessfulRefreshCarriesDBRefreshedAt(t *testing.T) {
	refreshedAt := time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)
	checkMounts := func() error { return nil }
	runScan := func(context.Context) (scan.Result, error) {
		return scan.Result{Status: scan.StatusOK}, nil
	}
	deps, _ := testDeps(fixedNow(refreshedAt.Add(time.Minute)), checkMounts, runScan)
	deps.refreshDB = func(context.Context) error { return nil }
	deps.now = fixedNow(refreshedAt)

	snap := buildSnapshot(context.Background(), deps, "")
	if !snap.Engine.DBRefreshedAt.Equal(refreshedAt) {
		t.Errorf("Engine.DBRefreshedAt = %v, want %v", snap.Engine.DBRefreshedAt, refreshedAt)
	}
	if snap.Engine.DBRefreshError != "" {
		t.Errorf("Engine.DBRefreshError = %q, want empty", snap.Engine.DBRefreshError)
	}
}

// TestBuildSnapshotFailedRefreshStillScansUnderCapAndCarriesError proves
// ADR-0012 decision 10's own core rule: a failed `grype db update` does
// not stop the scan -- it still runs on the last good database (Grype's
// own five-day cap permitting, enforced by Grype itself, not this
// package) -- and the error text reaches both Engine.DBRefreshError and,
// for an ordered run, the db_refreshed stage is still reported.
func TestBuildSnapshotFailedRefreshStillScansUnderCapAndCarriesError(t *testing.T) {
	scanCalled := false
	checkMounts := func() error { return nil }
	runScan := func(context.Context) (scan.Result, error) {
		scanCalled = true
		return scan.Result{Status: scan.StatusOK}, nil
	}
	deps, rec := testDeps(fixedNow(time.Now()), checkMounts, runScan)
	deps.refreshDB = func(context.Context) error { return errors.New("mirror unreachable") }

	snap := buildSnapshot(context.Background(), deps, "run-9")

	if !scanCalled {
		t.Error("runScan was never called -- a failed refresh must not stop the scan (under Grype's own cap)")
	}
	if snap.Status != scan.StatusOK {
		t.Errorf("Status = %q, want %q -- a failed refresh alone is not a failed scan", snap.Status, scan.StatusOK)
	}
	if snap.Engine.DBRefreshError != "mirror unreachable" {
		t.Errorf("Engine.DBRefreshError = %q, want %q", snap.Engine.DBRefreshError, "mirror unreachable")
	}
	got := rec.get()
	if len(got) != 3 || got[1] != stageDBRefreshed {
		t.Errorf("stages = %v, want db_refreshed reported as the second stage even though the refresh failed", got)
	}
}

// TestBuildSnapshotRefreshFailureRecordsFailingSinceOnce proves
// dbTracker.recordFailure's "first failure since the last success" rule
// end to end through buildSnapshot: two consecutive failed cycles keep
// the same FailingSince.
func TestBuildSnapshotRefreshFailureRecordsFailingSinceOnce(t *testing.T) {
	checkMounts := func() error { return nil }
	runScan := func(context.Context) (scan.Result, error) { return scan.Result{Status: scan.StatusOK}, nil }
	deps, _ := testDeps(fixedNow(time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)), checkMounts, runScan)
	deps.refreshDB = func(context.Context) error { return errors.New("down") }

	buildSnapshot(context.Background(), deps, "")
	first := deps.dbTracker.get().FailingSince

	deps.now = fixedNow(time.Date(2026, 9, 24, 9, 0, 0, 0, time.UTC))
	buildSnapshot(context.Background(), deps, "")
	second := deps.dbTracker.get().FailingSince

	if !first.Equal(second) {
		t.Errorf("FailingSince changed across consecutive failures: %v -> %v, want unchanged", first, second)
	}
}

// TestBuildSnapshotRefreshSuccessClearsFailingSince proves a successful
// refresh after a failing span clears it -- decision 11's "the tile may
// clear" for this signal.
func TestBuildSnapshotRefreshSuccessClearsFailingSince(t *testing.T) {
	checkMounts := func() error { return nil }
	runScan := func(context.Context) (scan.Result, error) { return scan.Result{Status: scan.StatusOK}, nil }
	deps, _ := testDeps(fixedNow(time.Now()), checkMounts, runScan)
	deps.refreshDB = func(context.Context) error { return errors.New("down") }
	buildSnapshot(context.Background(), deps, "")
	if deps.dbTracker.get().FailingSince.IsZero() {
		t.Fatal("FailingSince is zero after a failed refresh, want it set")
	}

	deps.refreshDB = func(context.Context) error { return nil }
	buildSnapshot(context.Background(), deps, "")
	status := deps.dbTracker.get()
	if !status.FailingSince.IsZero() {
		t.Errorf("FailingSince = %v after a successful refresh, want zero", status.FailingSince)
	}
	if status.LastError != "" {
		t.Errorf("LastError = %q after a successful refresh, want empty", status.LastError)
	}
}

// TestRunLoopRunsImmediatelyThenStops proves runScanLoop's cadence
// contract at its core, dependency-free: it runs at least one cycle
// without waiting for the first tick, and it stops promptly once ctx is
// canceled rather than blocking for a full interval. The interval is
// deliberately an hour, so only cancellation -- never the ticker --
// could plausibly end this test within its timeout.
func TestRunLoopRunsImmediatelyThenStops(t *testing.T) {
	var calls int
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		runLoop(ctx, time.Hour, func() {
			calls++
			cancel()
		})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runLoop did not stop promptly after cancel")
	}
	if calls == 0 {
		t.Error("runLoop never ran a cycle")
	}
}
