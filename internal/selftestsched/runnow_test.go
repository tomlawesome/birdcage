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

// TestRunNowQueuesOneSelfTest is #227's run-now entry point: an operator
// asking for a self-test gets one minted like a scheduled one (a run row
// and its marker targets), even with the schedule switched off and outside
// the scheduled minute -- the request is the trigger.
func TestRunNowQueuesOneSelfTest(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "false")
		insertHoneypotCanary(t, database, "canary-a", "22,80", "192.0.2.10")

		now := time.Date(2026, 1, 1, 13, 37, 0, 0, time.UTC)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())
		id, created, err := s.RunNow(context.Background(), "canary-a")
		if err != nil {
			t.Fatalf("RunNow: %v", err)
		}
		if !created || id == "" {
			t.Errorf("RunNow = %q, %v, want a command id and created=true", id, created)
		}
		if n := selfTestRunCount(t, database, "canary-a"); n != 1 {
			t.Fatalf("self_test_runs = %d, want 1", n)
		}
		// "Runs like a scheduled one": the same targets a scheduled mint
		// makes for an identical canary (ports plus the agent's own
		// portscan and poisoner probes), not a count hard-coded here.
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "true")
		mustSetSetting(t, database, store.SettingSelfTestUseRotationSchedule, "false")
		mustSetSetting(t, database, store.SettingSelfTestSchedule, "13:37")
		insertHoneypotCanary(t, database, "canary-b", "22,80", "192.0.2.11")
		s.Tick(context.Background())
		if n := selfTestRunCount(t, database, "canary-b"); n != 1 {
			t.Fatalf("scheduled run for canary-b: self_test_runs = %d, want 1", n)
		}
		got, want := mintedTargetServices(t, database, "canary-a"), mintedTargetServices(t, database, "canary-b")
		if len(got) == 0 || strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("run-now targets = %v, scheduled targets = %v, want the same", got, want)
		}
	})
}

// TestRunNowTwiceWhileQueuedAddsNothing: at most one queued per canary. The
// second request is answered with the queued one's id and created=false,
// and no second run row appears.
func TestRunNowTwiceWhileQueuedAddsNothing(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertHoneypotCanary(t, database, "canary-a", "22,80", "192.0.2.10")
		now := time.Date(2026, 1, 1, 13, 37, 0, 0, time.UTC)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())

		first, created, err := s.RunNow(context.Background(), "canary-a")
		if err != nil || !created {
			t.Fatalf("first RunNow = %q, %v, %v, want created", first, created, err)
		}
		// Well past the double-mint guard: the run is still queued (not yet
		// completed), so it is that one that answers.
		now = now.Add(5 * time.Minute)
		second, created, err := s.RunNow(context.Background(), "canary-a")
		if err != nil {
			t.Fatalf("second RunNow: %v", err)
		}
		if created || second != first {
			t.Errorf("second RunNow = %q, created=%v, want %q, created=false", second, created, first)
		}
		if n := selfTestRunCount(t, database, "canary-a"); n != 1 {
			t.Errorf("self_test_runs after two requests = %d, want 1", n)
		}
	})
}

// TestRunNowUnknownCanary: a canary id nobody enrolled is
// store.ErrCanaryNotFound, and nothing is minted.
func TestRunNowUnknownCanary(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		s := New(database, store.NewSelfTestIndex(), time.Now, discardLogger())
		_, _, err := s.RunNow(context.Background(), "no-such-canary")
		if !errors.Is(err, store.ErrCanaryNotFound) {
			t.Fatalf("RunNow(unknown) = %v, want store.ErrCanaryNotFound", err)
		}
		if n := selfTestRunCount(t, database, "no-such-canary"); n != 0 {
			t.Errorf("self_test_runs = %d, want 0", n)
		}
	})
}

// openCommandID is the command id of canaryID's most recent run.
func openCommandID(t *testing.T, database *db.DB, canaryID string) string {
	t.Helper()
	var id string
	if err := database.QueryRow(`SELECT command_id FROM self_test_runs WHERE agent_id = ? ORDER BY issued_at DESC LIMIT 1`, canaryID).Scan(&id); err != nil {
		t.Fatalf("latest run for %s: %v", canaryID, err)
	}
	return id
}

// TestOtherMintPathsAddNothingWhileARunNowRunIsOpen (#227 amendment): one
// open self-test per canary across every path. With a run-now run open
// (past the 2-minute double-mint guard, so only "a run is open" can stop
// them), a scheduled tick, a rotation mint and a first-contact mint each
// leave exactly one run.
func TestOtherMintPathsAddNothingWhileARunNowRunIsOpen(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "true")
		mustSetSetting(t, database, store.SettingSelfTestUseRotationSchedule, "false")
		mustSetSetting(t, database, store.SettingSelfTestSchedule, "04:12")
		insertHoneypotCanary(t, database, "canary-a", "22,80", "192.0.2.10")

		now := time.Date(2026, 1, 1, 4, 5, 0, 0, time.UTC)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())
		if _, created, err := s.RunNow(context.Background(), "canary-a"); err != nil || !created {
			t.Fatalf("RunNow = %v, %v, want created", created, err)
		}

		now = time.Date(2026, 1, 1, 4, 12, 0, 0, time.UTC) // 7 minutes on, the scheduled minute
		s.Tick(context.Background())
		if n := selfTestRunCount(t, database, "canary-a"); n != 1 {
			t.Errorf("after a scheduled tick: runs = %d, want 1", n)
		}

		mustSetSetting(t, database, store.SettingSelfTestUseRotationSchedule, "true")
		s.RotationSucceeded(context.Background(), "canary-a", now)
		if n := selfTestRunCount(t, database, "canary-a"); n != 1 {
			t.Errorf("after a rotation mint: runs = %d, want 1", n)
		}

		s.FirstContact(context.Background(), "canary-a", now)
		if n := selfTestRunCount(t, database, "canary-a"); n != 1 {
			t.Errorf("after a first-contact mint: runs = %d, want 1", n)
		}
	})
}

// TestRunNowWhileAScheduledRunIsOpenAnswersWithIt: the other way round.
func TestRunNowWhileAScheduledRunIsOpenAnswersWithIt(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "true")
		mustSetSetting(t, database, store.SettingSelfTestUseRotationSchedule, "false")
		mustSetSetting(t, database, store.SettingSelfTestSchedule, "04:12")
		insertHoneypotCanary(t, database, "canary-a", "22,80", "192.0.2.10")

		now := time.Date(2026, 1, 1, 4, 12, 0, 0, time.UTC)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())
		s.Tick(context.Background())
		scheduled := openCommandID(t, database, "canary-a")

		now = now.Add(5 * time.Minute)
		id, created, err := s.RunNow(context.Background(), "canary-a")
		if err != nil {
			t.Fatalf("RunNow: %v", err)
		}
		if created || id != scheduled {
			t.Errorf("RunNow = %q, created=%v, want the scheduled run %q, created=false", id, created, scheduled)
		}
		if n := selfTestRunCount(t, database, "canary-a"); n != 1 {
			t.Errorf("runs = %d, want 1", n)
		}
	})
}

// TestRunNowFindsAScanRunOpenPastThirtyMinutes: a scan run issued more than
// scanRunWindow ago but not yet swept is still open. RunNow answers with its
// command id, created=false, no error -- not a failure.
func TestRunNowFindsAScanRunOpenPastThirtyMinutes(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertScannerCanary(t, database, "scanner-a", false)
		issued := time.Date(2026, 1, 1, 4, 0, 0, 0, time.UTC)
		cmd, err := store.MintScanCommand(context.Background(), database, "scanner-a", store.TriggerProof, issued, issued.Add(scanRunWindow))
		if err != nil {
			t.Fatalf("MintScanCommand: %v", err)
		}

		now := issued.Add(40 * time.Minute)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())
		id, created, err := s.RunNow(context.Background(), "scanner-a")
		if err != nil {
			t.Fatalf("RunNow with a long-open scan run: %v", err)
		}
		if created || id != cmd.ID {
			t.Errorf("RunNow = %q, created=%v, want %q, created=false", id, created, cmd.ID)
		}
		if n := selfTestRunCount(t, database, "scanner-a"); n != 1 {
			t.Errorf("runs = %d, want 1", n)
		}
	})
}
