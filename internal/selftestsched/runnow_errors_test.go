package selftestsched

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// The error branches of RunNow and mintForCanary (#251, CI pipeline 5147's
// coverage gate). Each is made to fail the way this package's other error
// branches are: a table dropped, or a row planted so one query errors
// while the ones before it succeed. Nothing may be minted on any of them.

func runNowAt(database *db.DB, now time.Time) *Scheduler {
	return New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())
}

func totalRunCount(t *testing.T, database *db.DB) int {
	t.Helper()
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM self_test_runs`).Scan(&n); err != nil {
		t.Fatalf("count self_test_runs: %v", err)
	}
	return n
}

func TestRunNowCanaryLookupError(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertHoneypotCanary(t, database, "canary-a", "22,80", "192.0.2.10")
		dropTable(t, database, "agents")
		id, created, err := runNowAt(database, time.Now()).RunNow(context.Background(), "canary-a")
		if err == nil || !strings.Contains(err.Error(), "look up canary for run-now self-test") {
			t.Fatalf("RunNow = %v, want the canary lookup error", err)
		}
		if errors.Is(err, store.ErrCanaryNotFound) {
			t.Errorf("a failed lookup must not read as not-found: %v", err)
		}
		if id != "" || created {
			t.Errorf("RunNow = %q, %v, want nothing minted", id, created)
		}
	})
}

func TestRunNowOpenRunLookupError(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertHoneypotCanary(t, database, "canary-a", "22,80", "192.0.2.10")
		dropTable(t, database, "self_test_runs")
		id, created, err := runNowAt(database, time.Now()).RunNow(context.Background(), "canary-a")
		if err == nil || !strings.Contains(err.Error(), "self_test_runs") {
			t.Fatalf("RunNow = %v, want the open-run query error", err)
		}
		if id != "" || created {
			t.Errorf("RunNow = %q, %v, want nothing minted", id, created)
		}
	})
}

func TestRunNowHoneypotNotReady(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertHoneypotCanary(t, database, "canary-a", "22,80", "")
		id, created, err := runNowAt(database, time.Now()).RunNow(context.Background(), "canary-a")
		if !errors.Is(err, store.ErrSelfTestNotReady) {
			t.Fatalf("RunNow = %v, want store.ErrSelfTestNotReady", err)
		}
		if id != "" || created || totalRunCount(t, database) != 0 {
			t.Errorf("RunNow = %q, %v, runs=%d, want nothing minted", id, created, totalRunCount(t, database))
		}
	})
}

func TestRunNowHoneypotNoPorts(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertHoneypotCanary(t, database, "canary-a", "", "192.0.2.10")
		id, created, err := runNowAt(database, time.Now()).RunNow(context.Background(), "canary-a")
		if !errors.Is(err, store.ErrSelfTestNoPorts) {
			t.Fatalf("RunNow = %v, want store.ErrSelfTestNoPorts", err)
		}
		if id != "" || created || totalRunCount(t, database) != 0 {
			t.Errorf("RunNow = %q, %v, runs=%d, want nothing minted", id, created, totalRunCount(t, database))
		}
	})
}

// With the targets table gone the honeypot mint fails inside its
// transaction; RunNow returns that error and the run row is rolled back.
func TestRunNowHoneypotMintError(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertHoneypotCanary(t, database, "canary-a", "22,80", "192.0.2.10")
		dropTable(t, database, "self_test_targets")
		id, created, err := runNowAt(database, time.Now()).RunNow(context.Background(), "canary-a")
		if err == nil || !strings.Contains(err.Error(), "mint self-test command") {
			t.Fatalf("RunNow = %v, want the mint error", err)
		}
		if id != "" || created || totalRunCount(t, database) != 0 {
			t.Errorf("RunNow = %q, %v, runs=%d, want nothing minted", id, created, totalRunCount(t, database))
		}
	})
}

func TestRunNowScannerMintsAScan(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertScannerCanary(t, database, "scan-a", false)
		id, created, err := runNowAt(database, time.Now()).RunNow(context.Background(), "scan-a")
		if err != nil || !created || id == "" {
			t.Fatalf("RunNow = %q, %v, %v, want a new scan command", id, created, err)
		}
		if n := openScanRunCount(t, database, "scan-a"); n != 1 {
			t.Errorf("open scan runs = %d, want 1", n)
		}
	})
}

func TestRunNowScannerMintError(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertScannerCanary(t, database, "scan-a", false)
		dropTable(t, database, "self_test_targets")
		id, created, err := runNowAt(database, time.Now()).RunNow(context.Background(), "scan-a")
		if err == nil || !strings.Contains(err.Error(), "mint scan command") {
			t.Fatalf("RunNow = %v, want the scan mint error", err)
		}
		if id != "" || created || totalRunCount(t, database) != 0 {
			t.Errorf("RunNow = %q, %v, runs=%d, want nothing minted", id, created, totalRunCount(t, database))
		}
	})
}

// A kind other than honeypot or scanner is ErrUnknownKind, nothing minted.
func TestRunNowUnknownKind(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertHoneypotCanary(t, database, "canary-a", "22,80", "192.0.2.10")
		if _, err := database.Exec(`UPDATE agents SET kind = 'bogus' WHERE id = ?`, "canary-a"); err != nil {
			t.Fatalf("plant unknown kind: %v", err)
		}
		id, created, err := runNowAt(database, time.Now()).RunNow(context.Background(), "canary-a")
		if !errors.Is(err, ErrUnknownKind) {
			t.Fatalf("RunNow = %v, want ErrUnknownKind", err)
		}
		if id != "" || created || totalRunCount(t, database) != 0 {
			t.Errorf("RunNow = %q, %v, runs=%d, want nothing minted", id, created, totalRunCount(t, database))
		}
	})
}

// A scan run past its deadline but not completed still blocks a mint
// (MintScanCommand's rule), though the open-run check, which honours the
// deadline, does not see it: mintForCanary treats that as "nothing to do",
// not as an error, and mints nothing.
func TestMintForCanaryScanRunOpenPastDeadlineIsNotAnError(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertScannerCanary(t, database, "scan-a", false)
		t0 := time.Date(2026, 1, 1, 4, 0, 0, 0, time.UTC)
		if _, err := store.MintScanCommand(context.Background(), database, "scan-a", store.TriggerProof, t0, t0.Add(scanRunWindow)); err != nil {
			t.Fatalf("first mint: %v", err)
		}
		now := t0.Add(scanRunWindow + time.Hour)
		c, ok, err := store.SelfTestCanaryByID(context.Background(), database, "scan-a")
		if err != nil || !ok {
			t.Fatalf("SelfTestCanaryByID = %v, %v", ok, err)
		}
		if err := runNowAt(database, now).mintForCanary(context.Background(), c, now, doubleMintGuard); err != nil {
			t.Fatalf("mintForCanary = %v, want nil", err)
		}
		if n := totalRunCount(t, database); n != 1 {
			t.Errorf("self_test_runs = %d, want the original 1", n)
		}
	})
}

// sqliteOnly skips a test that plants a view, which has no Postgres twin.
func sqliteOnly(t *testing.T, database *db.DB) {
	t.Helper()
	if database.Engine != db.SQLite {
		t.Skip("plants a SQLite view; the branch is engine-independent")
	}
}

// replaceRunsWithView swaps self_test_runs for a one-row view whose bad
// column errors only when it is actually read (integer overflow in abs),
// so a query that never reads that column still succeeds.
func replaceRunsWithView(t *testing.T, database *db.DB, row string) {
	t.Helper()
	dropTable(t, database, "self_test_runs")
	if _, err := database.Exec(`CREATE VIEW self_test_runs AS ` + row); err != nil {
		t.Fatalf("create view: %v", err)
	}
}

const sqliteOverflow = `abs(-9223372036854775807 - 1)`

// The recent-run check failing is an error and mints nothing. The view's
// one run is completed (so the open-run check finds nothing) but its
// issued_at cannot be read, which the recent-run check must.
func TestMintForCanaryRecentRunError(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		sqliteOnly(t, database)
		insertHoneypotCanary(t, database, "canary-a", "22,80", "192.0.2.10")
		replaceRunsWithView(t, database, `SELECT 'c1' AS command_id, 'canary-a' AS agent_id,
			'2026-01-01T00:00:00Z' AS completed_at, '2026-01-01T00:00:00Z' AS deadline_at,
			`+sqliteOverflow+` AS issued_at`)
		now := time.Date(2026, 1, 1, 4, 0, 0, 0, time.UTC)
		c, ok, err := store.SelfTestCanaryByID(context.Background(), database, "canary-a")
		if err != nil || !ok {
			t.Fatalf("SelfTestCanaryByID = %v, %v", ok, err)
		}
		err = runNowAt(database, now).mintForCanary(context.Background(), c, now, doubleMintGuard)
		if err == nil || !strings.Contains(err.Error(), "check recent self-test runs") {
			t.Fatalf("mintForCanary = %v, want the recent-run check error", err)
		}
	})
}

// RunNow's scanner path, refused because a scan run is open, then failing
// to look that run's id up: the original ErrScanRunOpen is returned, no
// command id, nothing minted.
func TestRunNowScannerOpenRunIDLookupError(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		sqliteOnly(t, database)
		insertScannerCanary(t, database, "scan-a", false)
		// Not completed, staged, deadline long past: the open-run check
		// (deadline-aware) skips it, MintScanCommand's count refuses on it,
		// and OpenScanCommandID cannot read its command_id.
		replaceRunsWithView(t, database, `SELECT `+sqliteOverflow+` AS command_id, 'scan-a' AS agent_id,
			NULL AS completed_at, 'ordered' AS stage, '2000-01-01T00:00:00Z' AS deadline_at,
			'2000-01-01T00:00:00Z' AS issued_at`)
		id, created, err := runNowAt(database, time.Now()).RunNow(context.Background(), "scan-a")
		if !errors.Is(err, store.ErrScanRunOpen) {
			t.Fatalf("RunNow = %v, want store.ErrScanRunOpen", err)
		}
		if id != "" || created {
			t.Errorf("RunNow = %q, %v, want nothing minted", id, created)
		}
	})
}
