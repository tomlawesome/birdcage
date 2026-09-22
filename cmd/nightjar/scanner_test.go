package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/hostmask"
	"github.com/tomlawesome/birdcage/internal/scan"
)

func fixedNow(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// TestBuildSnapshotMountCheckFailureNeverScans is ADR-0010 decision 8
// and #108's own agent-side enforcement, at the unit level: when
// checkMounts fails, runScan must never be called at all, and the
// resulting snapshot is "failed" with the mount error as its reason and
// zero findings -- never an empty finding set presented as clean.
func TestBuildSnapshotMountCheckFailureNeverScans(t *testing.T) {
	scanCalled := false
	checkMounts := func() error { return errors.New("hostmask: /host/home exists but is not covered by a mount") }
	runScan := func(context.Context) (scan.Result, error) {
		scanCalled = true
		return scan.Result{}, nil
	}

	takenAt := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	snap := buildSnapshot(context.Background(), "v1.2.3", fixedNow(takenAt), checkMounts, runScan)

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
}

// TestBuildSnapshotScanErrorIsFailed proves a runScan Go error (context
// canceled before grype could start, scan.Run's own doc comment) also
// becomes a failed snapshot, never a silent skip.
func TestBuildSnapshotScanErrorIsFailed(t *testing.T) {
	checkMounts := func() error { return nil }
	runScan := func(context.Context) (scan.Result, error) {
		return scan.Result{}, errors.New("context canceled")
	}

	snap := buildSnapshot(context.Background(), "v1", fixedNow(time.Now()), checkMounts, runScan)
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

	snap := buildSnapshot(context.Background(), "v1", fixedNow(time.Now()), checkMounts, runScan)
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
