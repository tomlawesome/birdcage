package selftestsched

import (
	"context"
	"errors"
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
		if got := mintedTargetServices(t, database, "canary-a"); len(got) != 2 {
			t.Errorf("minted targets = %v, want one per port (ssh, http)", got)
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
