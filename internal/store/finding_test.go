package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

func listFindings(t *testing.T, database *db.DB, agentID string) []Finding {
	t.Helper()
	findings, err := ListFindings(context.Background(), database, FindingFilter{AgentID: agentID})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	return findings
}

func applySnapshot(t *testing.T, database *db.DB, agentID string, observed []ObservedFinding, at time.Time) {
	t.Helper()
	if err := ApplyFindingSnapshot(context.Background(), database, agentID, observed, at); err != nil {
		t.Fatalf("ApplyFindingSnapshot: %v", err)
	}
}

func findByVuln(t *testing.T, findings []Finding, vulnID string) Finding {
	t.Helper()
	for _, f := range findings {
		if f.VulnerabilityID == vulnID {
			return f
		}
	}
	t.Fatalf("no finding with vulnerability id %q in %+v", vulnID, findings)
	return Finding{}
}

var opensslFinding = ObservedFinding{
	Target: BuildFindingTarget("deb", "openssl"), VulnerabilityID: "CVE-2014-0160",
	Severity: "critical", InstalledVersion: "1.0.1f", FixingVersion: "1.0.1f-1ubuntu2.1",
}

// TestApplyFindingSnapshotNewFindingOpensAsOpen covers the issue's
// baseline: a finding never seen before is recorded as open, with
// first_seen and last_seen both the snapshot's own received-at clock.
func TestApplyFindingSnapshotNewFindingOpensAsOpen(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		t1 := mustParse(t, "2026-01-01T00:00:00Z")
		applySnapshot(t, database, "scanner-a", []ObservedFinding{opensslFinding}, t1)

		findings := listFindings(t, database, "scanner-a")
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
		}
		f := findings[0]
		if f.State != FindingOpen {
			t.Errorf("State = %q, want open", f.State)
		}
		if !f.FirstSeen.Equal(t1) || !f.LastSeen.Equal(t1) {
			t.Errorf("FirstSeen/LastSeen = %v/%v, want both %v", f.FirstSeen, f.LastSeen, t1)
		}
		if f.Severity != "critical" || f.InstalledVersion != "1.0.1f" || f.FixingVersion != "1.0.1f-1ubuntu2.1" {
			t.Errorf("metadata = %+v, want the posted severity/installed/fixing values", f)
		}
	})
}

// TestApplyFindingSnapshotRescanUnchangedOnlyMovesLastSeen is the
// issue's first acceptance bullet: "rescanning unchanged input changes
// last_seen and nothing else."
func TestApplyFindingSnapshotRescanUnchangedOnlyMovesLastSeen(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		t1 := mustParse(t, "2026-01-01T00:00:00Z")
		t2 := mustParse(t, "2026-01-02T00:00:00Z")
		applySnapshot(t, database, "scanner-a", []ObservedFinding{opensslFinding}, t1)
		applySnapshot(t, database, "scanner-a", []ObservedFinding{opensslFinding}, t2)

		findings := listFindings(t, database, "scanner-a")
		if len(findings) != 1 {
			t.Fatalf("got %d findings after rescan, want 1 (same identity, not a second row): %+v", len(findings), findings)
		}
		f := findings[0]
		if f.State != FindingOpen {
			t.Errorf("State = %q, want still open", f.State)
		}
		if !f.FirstSeen.Equal(t1) {
			t.Errorf("FirstSeen = %v, want unchanged at %v", f.FirstSeen, t1)
		}
		if !f.LastSeen.Equal(t2) {
			t.Errorf("LastSeen = %v, want moved to %v", f.LastSeen, t2)
		}
	})
}

// TestApplyFindingSnapshotRemovedPackageResolves is the issue's second
// acceptance bullet: "removing a vulnerable package resolves the
// finding without the agent telling the server anything except its new
// snapshot" -- an empty (or merely smaller) posted set is enough.
func TestApplyFindingSnapshotRemovedPackageResolves(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		t1 := mustParse(t, "2026-01-01T00:00:00Z")
		t2 := mustParse(t, "2026-01-02T00:00:00Z")
		applySnapshot(t, database, "scanner-a", []ObservedFinding{opensslFinding}, t1)
		applySnapshot(t, database, "scanner-a", []ObservedFinding{}, t2) // clean rescan

		findings := listFindings(t, database, "scanner-a")
		f := findByVuln(t, findings, "CVE-2014-0160")
		if f.State != FindingFixed {
			t.Errorf("State = %q, want fixed", f.State)
		}
		// last_seen is left at the last time it was actually observed,
		// never advanced by a scan that no longer reports it.
		if !f.LastSeen.Equal(t1) {
			t.Errorf("LastSeen = %v, want unchanged at %v (the scan that stopped reporting it never \"saw\" it)", f.LastSeen, t1)
		}
	})
}

// TestApplyFindingSnapshotAcceptedSurvivesRescan is the issue's third
// acceptance bullet: "an accepted finding stays accepted across
// rescans."
func TestApplyFindingSnapshotAcceptedSurvivesRescan(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		t1 := mustParse(t, "2026-01-01T00:00:00Z")
		t2 := mustParse(t, "2026-01-02T00:00:00Z")
		t3 := mustParse(t, "2026-01-03T00:00:00Z")
		applySnapshot(t, database, "scanner-a", []ObservedFinding{opensslFinding}, t1)

		if err := AcceptFinding(context.Background(), database, "scanner-a",
			opensslFinding.Target, opensslFinding.VulnerabilityID, "tom", t2); err != nil {
			t.Fatalf("AcceptFinding: %v", err)
		}
		findings := listFindings(t, database, "scanner-a")
		f := findByVuln(t, findings, "CVE-2014-0160")
		if f.State != FindingAccepted || f.AcceptedBy != "tom" || f.AcceptedAt == nil || !f.AcceptedAt.Equal(t2) {
			t.Fatalf("after accept: %+v, want state=accepted accepted_by=tom accepted_at=%v", f, t2)
		}

		// A rescan that still reports the same finding must not revert
		// the acceptance.
		applySnapshot(t, database, "scanner-a", []ObservedFinding{opensslFinding}, t3)
		findings = listFindings(t, database, "scanner-a")
		f = findByVuln(t, findings, "CVE-2014-0160")
		if f.State != FindingAccepted {
			t.Errorf("State after rescan = %q, want still accepted", f.State)
		}
		if f.AcceptedBy != "tom" || f.AcceptedAt == nil || !f.AcceptedAt.Equal(t2) {
			t.Errorf("acceptance after rescan = by=%q at=%v, want unchanged (by=tom at=%v)", f.AcceptedBy, f.AcceptedAt, t2)
		}
		if !f.LastSeen.Equal(t3) {
			t.Errorf("LastSeen after rescan = %v, want moved to %v", f.LastSeen, t3)
		}
	})
}

// TestApplyFindingSnapshotAcceptedThenRemovedStillResolves proves
// acceptance does not make a finding immune to resolution once the
// package genuinely disappears -- only to being re-asked-about while it
// is still present.
func TestApplyFindingSnapshotAcceptedThenRemovedStillResolves(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		t1 := mustParse(t, "2026-01-01T00:00:00Z")
		t2 := mustParse(t, "2026-01-02T00:00:00Z")
		applySnapshot(t, database, "scanner-a", []ObservedFinding{opensslFinding}, t1)
		if err := AcceptFinding(context.Background(), database, "scanner-a",
			opensslFinding.Target, opensslFinding.VulnerabilityID, "tom", t1); err != nil {
			t.Fatalf("AcceptFinding: %v", err)
		}

		applySnapshot(t, database, "scanner-a", []ObservedFinding{}, t2)
		f := findByVuln(t, listFindings(t, database, "scanner-a"), "CVE-2014-0160")
		if f.State != FindingFixed {
			t.Errorf("State = %q, want fixed even though it was accepted", f.State)
		}
	})
}

// The issue's fourth acceptance bullet in its store-layer half -- "a
// dropped or failed scan leaves the previous snapshot in place ... and
// never reports findings as resolved" -- has no store-level test of its
// own: ApplyFindingSnapshot has no "failed" input to give it (it is the
// caller's job never to call it for one, per its own doc comment), so a
// test that calls it once and then asserts nothing changed without
// calling anything else cannot fail and proves nothing.
// TestHandleScanFailedScanNeverResolvesFindings (internal/ingest/
// scans_test.go) is the real coverage: it drives a failed scan through
// the actual handler and proves the findings underneath are untouched.

// TestApplyFindingSnapshotFixedFindingReopensOnReturn covers the one
// transition the issue's own acceptance bullets do not name: a finding
// that resolved and then reappears (package reinstalled, or a fix
// reverted) comes back as open with its acceptance cleared, not silently
// re-accepted -- see ApplyFindingSnapshot's own doc comment for why.
func TestApplyFindingSnapshotFixedFindingReopensOnReturn(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		t1 := mustParse(t, "2026-01-01T00:00:00Z")
		t2 := mustParse(t, "2026-01-02T00:00:00Z")
		t3 := mustParse(t, "2026-01-03T00:00:00Z")
		applySnapshot(t, database, "scanner-a", []ObservedFinding{opensslFinding}, t1)
		if err := AcceptFinding(context.Background(), database, "scanner-a",
			opensslFinding.Target, opensslFinding.VulnerabilityID, "tom", t1); err != nil {
			t.Fatalf("AcceptFinding: %v", err)
		}
		applySnapshot(t, database, "scanner-a", []ObservedFinding{}, t2) // resolved

		applySnapshot(t, database, "scanner-a", []ObservedFinding{opensslFinding}, t3) // back again
		f := findByVuln(t, listFindings(t, database, "scanner-a"), "CVE-2014-0160")
		if f.State != FindingOpen {
			t.Errorf("State on reappearance = %q, want open (not silently re-accepted)", f.State)
		}
		if f.AcceptedBy != "" || f.AcceptedAt != nil {
			t.Errorf("acceptance on reappearance = by=%q at=%v, want cleared", f.AcceptedBy, f.AcceptedAt)
		}
		if !f.FirstSeen.Equal(t1) {
			t.Errorf("FirstSeen on reappearance = %v, want preserved at %v (continuous identity)", f.FirstSeen, t1)
		}
		if !f.LastSeen.Equal(t3) {
			t.Errorf("LastSeen on reappearance = %v, want %v", f.LastSeen, t3)
		}
	})
}

// TestApplyFindingSnapshotScopedPerAgent proves one agent's diff never
// resolves or touches another agent's findings.
func TestApplyFindingSnapshotScopedPerAgent(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		t1 := mustParse(t, "2026-01-01T00:00:00Z")
		applySnapshot(t, database, "scanner-a", []ObservedFinding{opensslFinding}, t1)
		applySnapshot(t, database, "scanner-b", []ObservedFinding{}, t1) // scanner-b reports nothing, ever

		fa := findByVuln(t, listFindings(t, database, "scanner-a"), "CVE-2014-0160")
		if fa.State != FindingOpen {
			t.Errorf("scanner-a's finding = %q, want open (unaffected by scanner-b's empty snapshot)", fa.State)
		}
		if len(listFindings(t, database, "scanner-b")) != 0 {
			t.Errorf("scanner-b has findings, want none")
		}
	})
}

func TestAcceptFindingNotFoundForUnknownOrFixed(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		t1 := mustParse(t, "2026-01-01T00:00:00Z")
		t2 := mustParse(t, "2026-01-02T00:00:00Z")

		err := AcceptFinding(context.Background(), database, "scanner-a", "deb:openssl", "CVE-2014-0160", "tom", t1)
		if !errors.Is(err, ErrFindingNotFound) {
			t.Fatalf("accept on never-seen finding: err = %v, want ErrFindingNotFound", err)
		}

		applySnapshot(t, database, "scanner-a", []ObservedFinding{opensslFinding}, t1)
		applySnapshot(t, database, "scanner-a", []ObservedFinding{}, t2) // now fixed

		err = AcceptFinding(context.Background(), database, "scanner-a",
			opensslFinding.Target, opensslFinding.VulnerabilityID, "tom", t2)
		if !errors.Is(err, ErrFindingNotFound) {
			t.Fatalf("accept on fixed finding: err = %v, want ErrFindingNotFound", err)
		}
	})
}

func TestAcceptFindingValidatesArguments(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		now := mustParse(t, "2026-01-01T00:00:00Z")
		cases := []struct {
			name                                string
			agentID, target, vulnID, acceptedBy string
			now                                 time.Time
		}{
			{"empty agent", "", "deb:openssl", "CVE-1", "tom", now},
			{"empty target", "scanner-a", "", "CVE-1", "tom", now},
			{"empty vuln", "scanner-a", "deb:openssl", "", "tom", now},
			{"empty acceptedBy", "scanner-a", "deb:openssl", "CVE-1", "", now},
			{"zero now", "scanner-a", "deb:openssl", "CVE-1", "tom", time.Time{}},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				if err := AcceptFinding(context.Background(), database, c.agentID, c.target, c.vulnID, c.acceptedBy, c.now); err == nil {
					t.Errorf("AcceptFinding(%+v) = nil error, want a validation error", c)
				}
			})
		}
	})
}

func TestBuildFindingTarget(t *testing.T) {
	if got := BuildFindingTarget("deb", "openssl"); got != "deb:openssl" {
		t.Errorf("BuildFindingTarget(deb, openssl) = %q, want deb:openssl", got)
	}
}

// TestFindingsStalenessFollowsTheMostRecentScan is issue #109's "marked
// stale" bullet: a dropped or failed scan leaves the previous findings
// in place but with nothing fresher behind them. ok -> not stale, then
// failed -> stale with the findings themselves untouched and
// LastOKScan still naming the earlier ok scan, then a fresh ok -> not
// stale again with LastOKScan moved forward.
func TestFindingsStalenessFollowsTheMostRecentScan(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		t1 := mustParse(t, "2026-01-01T00:00:00Z")
		recordScanSnapshot(t, database, ScanSnapshot{
			CanaryID: "scanner-a", TakenAt: t1, ReceivedAt: t1, EngineName: "grype", EngineVersion: "v1",
			Status: ScanStatusOK, FindingCount: 1,
		})
		applySnapshot(t, database, "scanner-a", []ObservedFinding{opensslFinding}, t1)

		status := findingsStaleness(t, database, "scanner-a")
		if status.Stale {
			t.Errorf("Stale = true right after an ok scan, want false")
		}
		if status.LastOKScan == nil || !status.LastOKScan.Equal(t1) {
			t.Errorf("LastOKScan = %v, want %v", status.LastOKScan, t1)
		}

		t2 := mustParse(t, "2026-01-02T00:00:00Z")
		recordScanSnapshot(t, database, ScanSnapshot{
			CanaryID: "scanner-a", TakenAt: t2, ReceivedAt: t2, Status: ScanStatusFailed, Reason: "db stale",
		})
		// No ApplyFindingSnapshot call -- matching internal/ingest's own
		// storeScan, which only calls it for status ok.

		status = findingsStaleness(t, database, "scanner-a")
		if !status.Stale {
			t.Errorf("Stale = false after a failed scan, want true")
		}
		if status.LastOKScan == nil || !status.LastOKScan.Equal(t1) {
			t.Errorf("LastOKScan after a failed scan = %v, want still %v (the last ok one)", status.LastOKScan, t1)
		}
		f := findByVuln(t, listFindings(t, database, "scanner-a"), opensslFinding.VulnerabilityID)
		if f.State != FindingOpen || !f.LastSeen.Equal(t1) {
			t.Errorf("finding mutated by a failed scan: %+v", f)
		}

		t3 := mustParse(t, "2026-01-03T00:00:00Z")
		recordScanSnapshot(t, database, ScanSnapshot{
			CanaryID: "scanner-a", TakenAt: t3, ReceivedAt: t3, EngineName: "grype", EngineVersion: "v1",
			Status: ScanStatusOK, FindingCount: 1,
		})
		applySnapshot(t, database, "scanner-a", []ObservedFinding{opensslFinding}, t3)

		status = findingsStaleness(t, database, "scanner-a")
		if status.Stale {
			t.Errorf("Stale = true after a fresh ok scan, want false")
		}
		if status.LastOKScan == nil || !status.LastOKScan.Equal(t3) {
			t.Errorf("LastOKScan after the fresh ok scan = %v, want %v", status.LastOKScan, t3)
		}
	})
}

// TestFindingsStalenessScopedPerAgent proves one agent's failed scan
// never marks another agent stale.
func TestFindingsStalenessScopedPerAgent(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		t1 := mustParse(t, "2026-01-01T00:00:00Z")
		recordScanSnapshot(t, database, ScanSnapshot{
			CanaryID: "scanner-a", TakenAt: t1, ReceivedAt: t1, Status: ScanStatusFailed, Reason: "x",
		})
		recordScanSnapshot(t, database, ScanSnapshot{
			CanaryID: "scanner-b", TakenAt: t1, ReceivedAt: t1, EngineName: "grype", EngineVersion: "v1",
			Status: ScanStatusOK, FindingCount: 0,
		})

		all, err := FindingsStaleness(context.Background(), database, "")
		if err != nil {
			t.Fatalf("FindingsStaleness: %v", err)
		}
		if !all["scanner-a"].Stale {
			t.Errorf("scanner-a Stale = false, want true")
		}
		if all["scanner-b"].Stale {
			t.Errorf("scanner-b Stale = true, want false (its own scan was ok)")
		}
	})
}

func findingsStaleness(t *testing.T, database *db.DB, agentID string) AgentScanStatus {
	t.Helper()
	all, err := FindingsStaleness(context.Background(), database, agentID)
	if err != nil {
		t.Fatalf("FindingsStaleness: %v", err)
	}
	status, ok := all[agentID]
	if !ok {
		t.Fatalf("FindingsStaleness has no entry for %q: %+v", agentID, all)
	}
	return status
}
