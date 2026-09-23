package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/store"
)

// --- runCanaryAdd -----------------------------------------------------

func TestCanaryAddUsage(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"only-one"},
		{"one", "two", "three"},
		{"one", "two", "three", "four", "five", "six"},
	} {
		if err := runCanaryAdd(args); err == nil {
			t.Errorf("runCanaryAdd(%v) succeeded, want a usage error", args)
		}
	}
}

func TestCanaryAddRejectsNonPositiveInterval(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	for _, interval := range []string{"0", "-5", "not-a-number"} {
		args := []string{"canary-x", "name", "lane", "22,80", interval}
		if err := runCanaryAdd(args); err == nil {
			t.Errorf("runCanaryAdd with interval_s=%q succeeded, want a refusal", interval)
		}
	}
}

// TestCanaryAddInsertsAndPrintsEscapedID is runCanaryAdd's own happy
// path, both with the default heartbeat interval and an explicit one,
// and proves the printed id is escaped the same way runCanaryList's own
// output is (canary_test.go's TestCanaryOutputLeavesOrdinaryAndNonASCIINamesUnchanged).
func TestCanaryAddInsertsAndPrintsEscapedID(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))

	out, err := captureStdout(t, func() error {
		return runCanaryAdd([]string{"canary-add-1", "front desk", "office", "22,80"})
	})
	if err != nil {
		t.Fatalf("runCanaryAdd: %v", err)
	}
	if !strings.Contains(out, "canary-add-1") || !strings.Contains(out, "enrolled") {
		t.Errorf("output = %q, want it to confirm canary-add-1 enrolled", out)
	}

	out, err = captureStdout(t, func() error {
		return runCanaryAdd([]string{"canary-add-2", "back office", "office", "445", "120"})
	})
	if err != nil {
		t.Fatalf("runCanaryAdd with explicit interval: %v", err)
	}
	if !strings.Contains(out, "canary-add-2") {
		t.Errorf("output = %q, want it to confirm canary-add-2 enrolled", out)
	}

	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)
	canaries, err := store.ListCanaries(context.Background(), database, time.Now().UTC(), time.Hour)
	if err != nil {
		t.Fatalf("store.ListCanaries: %v", err)
	}
	got := make(map[string]bool, len(canaries))
	for _, c := range canaries {
		got[c.ID] = true
	}
	for _, id := range []string{"canary-add-1", "canary-add-2"} {
		if !got[id] {
			t.Errorf("canaries table does not contain %q: %+v", id, canaries)
		}
	}
}

// TestCanaryAddRefusesDuplicateID proves the "insert canary" error wrap:
// a second `canary add` with the same id must fail rather than silently
// overwrite the first registration's ports, lane or interval.
func TestCanaryAddRefusesDuplicateID(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))

	if _, err := captureStdout(t, func() error {
		return runCanaryAdd([]string{"dup-canary", "name", "lane", "22"})
	}); err != nil {
		t.Fatalf("first runCanaryAdd: %v", err)
	}

	_, err := captureStdout(t, func() error {
		return runCanaryAdd([]string{"dup-canary", "name", "lane", "22"})
	})
	if err == nil {
		t.Fatal("second runCanaryAdd with a duplicate id succeeded, want a refusal")
	}
}

// --- openCanaryDB / closeCanaryDB --------------------------------------

// TestOpenCanaryDBDefaultsToDefaultDBPath proves openCanaryDB's third
// precedence branch: with neither DATABASE_URL nor BIRDCAGE_DB_PATH set,
// it falls back to defaultDBPath, exactly as the main server does. Run
// from a scratch directory (t.Chdir) so this never touches a real
// birdcage.db on the host running the test.
func TestOpenCanaryDBDefaultsToDefaultDBPath(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv(envDatabaseURL, "")
	t.Setenv(envDBPath, "")

	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	closeCanaryDB(database)
}

// TestOpenCanaryDBMigrateFailure proves openCanaryDB's migrate-failure
// branch (distinct from db.Open itself failing, which neither driver
// birdcage uses does eagerly -- both modernc.org/sqlite and pgx parse
// and connect lazily, so the earliest point either can fail is here, at
// the first real query Migrate issues): BIRDCAGE_DB_PATH pointed at a
// directory that cannot hold a SQLite file returns a wrapped "migrate
// database" error, and never leaves a *db.DB leaked past it.
func TestOpenCanaryDBMigrateFailure(t *testing.T) {
	t.Setenv(envDatabaseURL, "")
	t.Setenv(envDBPath, "/nonexistent-dir-for-birdcage-coverage-test/db.sqlite")

	_, err := openCanaryDB()
	if err == nil {
		t.Fatal("openCanaryDB succeeded against an unopenable path, want a refusal")
	}
	if !strings.Contains(err.Error(), "migrate database") {
		t.Errorf("err = %q, want it to name the migrate-database failure", err)
	}
}
