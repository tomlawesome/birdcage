package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
)

// Issue #213 (retention, owner question 39 answered b): fixed findings
// and scan snapshots older than BIRDCAGE_FINDINGS_RETENTION_DAYS are
// removed on snapshot ingest. The seam these tests pin is
//
//	PruneByAge(ctx, conn, agentID, retentionDays, now) (PruneCounts, error)
//
// "now" is passed in (the ingest handler already carries an injectable
// clock, and ApplyFindingSnapshot already takes observedAt), so no store
// clock is needed. retentionDays 0 keeps everything; negative is an
// error. A run that removes anything writes exactly one audit row
// (action AuditActionRetentionPruned, target the agent id) whose reason
// names both counts as "<n> fixed findings" and "<n> scan snapshots".

const retentionNow = "2026-06-01T00:00:00Z"

var (
	retentionOld    = mustParseT("2026-01-01T00:00:00Z") // 151 days before now
	retentionRecent = mustParseT("2026-05-01T00:00:00Z") // 31 days before now
)

func mustParseT(s string) time.Time {
	tm, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return tm
}

func retentionAgent(t *testing.T, database *db.DB, id string) {
	t.Helper()
	insertCanary(t, database, Canary{ID: id, Name: id, Lane: "lan", Kind: agentkind.Scanner,
		EnrolledAt: mustParse(t, "2025-01-01T00:00:00Z")})
}

func pruneByAge(t *testing.T, database *db.DB, agentID string, days int) PruneCounts {
	t.Helper()
	got, err := PruneByAge(context.Background(), database, agentID, days, mustParse(t, retentionNow))
	if err != nil {
		t.Fatalf("PruneByAge(%s, %d): %v", agentID, days, err)
	}
	return got
}

func recordSnapshotAt(t *testing.T, database *db.DB, agentID string, at time.Time) {
	t.Helper()
	recordScanSnapshot(t, database, ScanSnapshot{
		CanaryID: agentID, TakenAt: at, ReceivedAt: at,
		EngineName: "grype", EngineVersion: "v0.119.0", Status: ScanStatusOK,
	})
}

func retentionAuditRows(t *testing.T, database *db.DB) []string {
	t.Helper()
	rs, err := database.Query(`SELECT action, target, reason FROM audit_log WHERE action = ? ORDER BY id`, AuditActionRetentionPruned)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer func() { _ = rs.Close() }()
	var out []string
	for rs.Next() {
		var a, tg, r string
		if err := rs.Scan(&a, &tg, &r); err != nil {
			t.Fatalf("scan audit: %v", err)
		}
		out = append(out, a+"|"+tg+"|"+r)
	}
	return out
}

// Fixed rows older than the window go; fixed rows inside it stay; open
// and accepted rows stay however old; another agent's rows are untouched.
func TestPruneByAgeRemovesOnlyOldFixedFindings(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		retentionAgent(t, database, "scanner-a")
		retentionAgent(t, database, "scanner-b")
		insertFindingRows(t, database, "scanner-a", "OLDFIX", FindingFixed, 4, retentionOld)
		insertFindingRows(t, database, "scanner-a", "NEWFIX", FindingFixed, 3, retentionRecent)
		insertFindingRows(t, database, "scanner-a", "OLDOPEN", FindingOpen, 2, retentionOld)
		insertFindingRows(t, database, "scanner-a", "OLDACC", FindingAccepted, 2, retentionOld)
		insertFindingRows(t, database, "scanner-b", "OLDFIX", FindingFixed, 5, retentionOld)

		got := pruneByAge(t, database, "scanner-a", 90)
		if got.Findings != 4 {
			t.Errorf("PruneCounts.Findings = %d, want 4", got.Findings)
		}
		fs := listFindings(t, database, "scanner-a")
		if n := countState(fs, FindingFixed); n != 3 {
			t.Errorf("fixed rows = %d, want 3 (only the recent ones)", n)
		}
		for _, f := range fs {
			if f.State == FindingFixed && strings.HasPrefix(f.VulnerabilityID, "OLDFIX") {
				t.Errorf("%s (fixed, 151 days old) still present", f.VulnerabilityID)
			}
		}
		if n := countState(fs, FindingOpen); n != 2 {
			t.Errorf("open rows = %d, want 2 (never removed by age)", n)
		}
		if n := countState(fs, FindingAccepted); n != 2 {
			t.Errorf("accepted rows = %d, want 2 (never removed by age)", n)
		}
		if n := len(listFindings(t, database, "scanner-b")); n != 5 {
			t.Errorf("other agent's rows = %d, want 5 untouched", n)
		}
	})
}

// 89 days old stays, 91 days old goes, with a 90-day window.
func TestPruneByAgeWindowEdge(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		retentionAgent(t, database, "scanner-a")
		now := mustParse(t, retentionNow)
		insertFindingRows(t, database, "scanner-a", "D89", FindingFixed, 1, now.AddDate(0, 0, -89))
		insertFindingRows(t, database, "scanner-a", "D91", FindingFixed, 1, now.AddDate(0, 0, -91))
		pruneByAge(t, database, "scanner-a", 90)
		fs := listFindings(t, database, "scanner-a")
		if len(fs) != 1 || !strings.HasPrefix(fs[0].VulnerabilityID, "D89") {
			t.Errorf("findings after prune = %+v, want only the 89-day-old row", fs)
		}
	})
}

// 0 means keep for good: nothing removed, no audit row.
func TestPruneByAgeZeroKeepsEverything(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		retentionAgent(t, database, "scanner-a")
		insertFindingRows(t, database, "scanner-a", "OLDFIX", FindingFixed, 3, retentionOld)
		recordSnapshotAt(t, database, "scanner-a", retentionOld)
		recordSnapshotAt(t, database, "scanner-a", retentionOld.Add(time.Hour))

		got := pruneByAge(t, database, "scanner-a", 0)
		if got != (PruneCounts{}) {
			t.Errorf("PruneCounts = %+v, want zero", got)
		}
		if n := len(listFindings(t, database, "scanner-a")); n != 3 {
			t.Errorf("findings = %d, want 3", n)
		}
		if n := len(listScanSnapshots(t, database)); n != 2 {
			t.Errorf("snapshots = %d, want 2", n)
		}
		if rows := retentionAuditRows(t, database); len(rows) != 0 {
			t.Errorf("audit rows = %v, want none", rows)
		}
	})
}

func TestPruneByAgeRefusesNegativeDays(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		retentionAgent(t, database, "scanner-a")
		insertFindingRows(t, database, "scanner-a", "OLDFIX", FindingFixed, 1, retentionOld)
		_, err := PruneByAge(context.Background(), database, "scanner-a", -1, mustParse(t, retentionNow))
		if err == nil {
			t.Fatal("PruneByAge with -1 days = nil error, want a refusal")
		}
		if n := len(listFindings(t, database, "scanner-a")); n != 1 {
			t.Errorf("findings = %d, want 1 (nothing removed on refusal)", n)
		}
	})
}

// Old snapshots go, recent ones stay, and each agent's newest snapshot
// stays even when it is older than the window.
func TestPruneByAgeSnapshotsKeepNewestPerAgent(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		retentionAgent(t, database, "scanner-a")
		retentionAgent(t, database, "scanner-b")
		retentionAgent(t, database, "scanner-c")
		// a: two old, one recent -> only the two old go.
		recordSnapshotAt(t, database, "scanner-a", retentionOld)
		recordSnapshotAt(t, database, "scanner-a", retentionOld.Add(24*time.Hour))
		recordSnapshotAt(t, database, "scanner-a", retentionRecent)
		// b: all old -> the newest old one stays.
		recordSnapshotAt(t, database, "scanner-b", retentionOld)
		recordSnapshotAt(t, database, "scanner-b", retentionOld.Add(24*time.Hour))
		recordSnapshotAt(t, database, "scanner-b", retentionOld.Add(48*time.Hour))
		// c: not pruned in this run, so untouched even though old.
		recordSnapshotAt(t, database, "scanner-c", retentionOld)
		recordSnapshotAt(t, database, "scanner-c", retentionOld.Add(24*time.Hour))

		a := pruneByAge(t, database, "scanner-a", 90)
		b := pruneByAge(t, database, "scanner-b", 90)
		if a.Snapshots != 2 {
			t.Errorf("scanner-a Snapshots removed = %d, want 2", a.Snapshots)
		}
		if b.Snapshots != 2 {
			t.Errorf("scanner-b Snapshots removed = %d, want 2", b.Snapshots)
		}

		per := map[string][]time.Time{}
		for _, s := range listScanSnapshots(t, database) {
			per[s.CanaryID] = append(per[s.CanaryID], s.ReceivedAt)
		}
		if got := per["scanner-a"]; len(got) != 1 || !got[0].Equal(retentionRecent) {
			t.Errorf("scanner-a snapshots = %v, want just the recent one", got)
		}
		if got := per["scanner-b"]; len(got) != 1 || !got[0].Equal(retentionOld.Add(48*time.Hour)) {
			t.Errorf("scanner-b snapshots = %v, want just the newest (old) one", got)
		}
		if got := per["scanner-c"]; len(got) != 2 {
			t.Errorf("scanner-c snapshots = %d, want 2 untouched", len(got))
		}
	})
}

// One run that removes both kinds writes one audit row with both counts;
// a run that removes nothing writes none.
func TestPruneByAgeWritesOneAuditRowPerRun(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		retentionAgent(t, database, "scanner-a")
		insertFindingRows(t, database, "scanner-a", "OLDFIX", FindingFixed, 7, retentionOld)
		recordSnapshotAt(t, database, "scanner-a", retentionOld)
		recordSnapshotAt(t, database, "scanner-a", retentionOld.Add(time.Hour))
		recordSnapshotAt(t, database, "scanner-a", retentionOld.Add(2*time.Hour))
		recordSnapshotAt(t, database, "scanner-a", retentionRecent)

		pruneByAge(t, database, "scanner-a", 90)
		rows := retentionAuditRows(t, database)
		if len(rows) != 1 {
			t.Fatalf("audit rows = %v, want exactly 1 (not one per finding)", rows)
		}
		for _, want := range []string{AuditActionRetentionPruned + "|scanner-a|", "7 fixed findings", "3 scan snapshots", "90"} {
			if !strings.Contains(rows[0], want) {
				t.Errorf("audit row %q does not contain %q", rows[0], want)
			}
		}

		pruneByAge(t, database, "scanner-a", 90) // nothing left to remove
		if rows := retentionAuditRows(t, database); len(rows) != 1 {
			t.Errorf("audit rows after an empty run = %d, want still 1", len(rows))
		}
	})
}

// The 50,000 cap is unchanged and independent of the window: with the
// window off (0), a snapshot still caps fixed rows at 50,000.
func TestPruneByAgeDoesNotDisturbFixedCap(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		retentionAgent(t, database, "scanner-a")
		insertFindingRows(t, database, "scanner-a", "FIX", FindingFixed, 50003, retentionRecent)
		applySnapshot(t, database, "scanner-a", observedRange("NEW", 1), mustParse(t, retentionNow))
		pruneByAge(t, database, "scanner-a", 0)
		if n := countState(listFindings(t, database, "scanner-a"), FindingFixed); n != 50000 {
			t.Errorf("fixed rows = %d, want 50000", n)
		}
	})
}
