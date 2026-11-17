package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// Issue #213: ListFindings gains States and Limit; ApplyFindingSnapshot
// keeps at most 50,000 fixed rows per agent (write-time retention
// pruning, CWE-770 backstop).

// insertFindingRows inserts n rows for agentID directly, one transaction,
// ids ascending: vulnerability ids are prefix-000000, prefix-000001, ...
func insertFindingRows(t *testing.T, database *db.DB, agentID, prefix string, state FindingState, n int, seen time.Time) {
	t.Helper()
	ctx := context.Background()
	tx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	ts := seen.UTC().Format(receivedAtLayout)
	for i := 0; i < n; i++ {
		var by, at any
		if state == FindingAccepted {
			by, at = "tester", ts
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO findings (agent_id, target, vulnerability_id, severity, installed_version, fixing_version, first_seen, last_seen, state, accepted_by, accepted_at)
			VALUES (?, 'deb:pkg', ?, 'high', '1', '', ?, ?, ?, ?, ?)`,
			agentID, fmt.Sprintf("%s-%06d", prefix, i), ts, ts, string(state), by, at); err != nil {
			t.Fatalf("insert %s %d: %v", prefix, i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func observedRange(prefix string, n int) []ObservedFinding {
	out := make([]ObservedFinding, n)
	for i := range out {
		out[i] = ObservedFinding{Target: "deb:pkg", VulnerabilityID: fmt.Sprintf("%s-%06d", prefix, i), Severity: "high", InstalledVersion: "1"}
	}
	return out
}

func countState(fs []Finding, st FindingState) int {
	n := 0
	for _, f := range fs {
		if f.State == st {
			n++
		}
	}
	return n
}

// TestApplyFindingSnapshotCapsFixedRowsPerAgent: with 50,010 fixed rows
// on file, applying a snapshot leaves exactly 50,000, the 10 oldest
// (lowest ids) removed; open and accepted rows, even ones older than
// every fixed row, stay, and another agent's rows are not touched.
func TestApplyFindingSnapshotCapsFixedRowsPerAgent(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		old := mustParse(t, "2025-01-01T00:00:00Z")
		recent := mustParse(t, "2026-01-01T00:00:00Z")
		insertFindingRows(t, database, "scanner-a", "OPEN", FindingOpen, 3, old)
		insertFindingRows(t, database, "scanner-a", "ACC", FindingAccepted, 3, old)
		insertFindingRows(t, database, "scanner-a", "FIX", FindingFixed, 50010, recent)
		insertFindingRows(t, database, "scanner-b", "FIX", FindingFixed, 5, old)

		// The snapshot still reports the open and accepted rows, plus a new one.
		observed := append(observedRange("OPEN", 3), observedRange("ACC", 3)...)
		observed = append(observed, observedRange("NEW", 1)...)
		applySnapshot(t, database, "scanner-a", observed, mustParse(t, "2026-01-02T00:00:00Z"))

		got := listFindings(t, database, "scanner-a")
		if n := countState(got, FindingFixed); n != 50000 {
			t.Errorf("fixed rows = %d, want 50000", n)
		}
		if n := countState(got, FindingOpen); n != 4 {
			t.Errorf("open rows = %d, want 4 (3 kept + 1 new)", n)
		}
		if n := countState(got, FindingAccepted); n != 3 {
			t.Errorf("accepted rows = %d, want 3 (never pruned)", n)
		}
		have := make(map[string]bool, len(got))
		for _, f := range got {
			have[f.VulnerabilityID] = true
		}
		for i := 0; i < 10; i++ {
			if id := fmt.Sprintf("FIX-%06d", i); have[id] {
				t.Errorf("%s (one of the 10 oldest fixed rows) still present", id)
			}
		}
		for _, id := range []string{"FIX-000010", "FIX-050009"} {
			if !have[id] {
				t.Errorf("%s was removed, want kept (not among the 10 oldest)", id)
			}
		}
		if n := len(listFindings(t, database, "scanner-b")); n != 5 {
			t.Errorf("other agent's rows = %d, want 5 untouched", n)
		}
	})
}

// TestApplyFindingSnapshotKeepsFixedRowsAtTheCeiling: exactly 50,000
// fixed rows is within the limit and nothing is removed.
func TestApplyFindingSnapshotKeepsFixedRowsAtTheCeiling(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertFindingRows(t, database, "scanner-a", "FIX", FindingFixed, 50000, mustParse(t, "2026-01-01T00:00:00Z"))
		applySnapshot(t, database, "scanner-a", observedRange("NEW", 1), mustParse(t, "2026-01-02T00:00:00Z"))
		if n := countState(listFindings(t, database, "scanner-a"), FindingFixed); n != 50000 {
			t.Errorf("fixed rows = %d, want 50000 (at the ceiling, none removed)", n)
		}
	})
}

// TestListFindingsStatesAndLimit: States narrows by state (empty means
// every state, as before), Limit cuts the last_seen-ordered result
// (0 means all).
func TestListFindingsStatesAndLimit(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		t1 := mustParse(t, "2026-01-01T00:00:00Z")
		t2 := mustParse(t, "2026-01-02T00:00:00Z")
		t3 := mustParse(t, "2026-01-03T00:00:00Z")
		mk := func(id string) ObservedFinding {
			return ObservedFinding{Target: "deb:pkg", VulnerabilityID: id, Severity: "high"}
		}
		applySnapshot(t, database, "scanner-a", []ObservedFinding{mk("A"), mk("B"), mk("C")}, t1)
		if err := AcceptFinding(ctx, database, "scanner-a", "deb:pkg", "B", "tester", t1); err != nil {
			t.Fatalf("AcceptFinding: %v", err)
		}
		applySnapshot(t, database, "scanner-a", []ObservedFinding{mk("B"), mk("C")}, t2) // A fixed
		applySnapshot(t, database, "scanner-a", []ObservedFinding{mk("C")}, t3)          // B fixed too

		list := func(f FindingFilter) []Finding {
			t.Helper()
			f.AgentID = "scanner-a"
			out, err := ListFindings(ctx, database, f)
			if err != nil {
				t.Fatalf("ListFindings: %v", err)
			}
			return out
		}
		if n := len(list(FindingFilter{})); n != 3 {
			t.Errorf("no States: %d rows, want all 3", n)
		}
		if got := list(FindingFilter{States: []FindingState{FindingOpen, FindingAccepted}}); len(got) != 1 || got[0].VulnerabilityID != "C" {
			t.Errorf("open+accepted = %+v, want only C", got)
		}
		if n := len(list(FindingFilter{States: []FindingState{FindingFixed}})); n != 2 {
			t.Errorf("fixed: %d rows, want 2 (A, B)", n)
		}
		if n := len(list(FindingFilter{States: []FindingState{FindingFixed, FindingOpen}})); n != 3 {
			t.Errorf("fixed+open: %d rows, want 3", n)
		}
		got := list(FindingFilter{Limit: 2})
		if len(got) != 2 || got[0].VulnerabilityID != "C" {
			t.Errorf("Limit 2 = %+v, want 2 rows, newest last_seen (C) first", got)
		}
		if n := len(list(FindingFilter{Limit: 0})); n != 3 {
			t.Errorf("Limit 0: %d rows, want all 3", n)
		}
		if n := len(list(FindingFilter{States: []FindingState{FindingFixed}, Limit: 1})); n != 1 {
			t.Errorf("fixed with Limit 1: %d rows, want 1", n)
		}
	})
}
