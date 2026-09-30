package store

import (
	"context"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// TestPendingCanarySettlesOnSelfTestPass is issue #47 steps 7-9's
// required end-to-end test: a canary provisioned through store.Provision
// starts pending (#45 state 5, never "ok"), and the moment its self-test
// run's every target matches, it registers -- store.SettlePending, fired
// from recordSelfTestMatch's own single added call.
func TestPendingCanarySettlesOnSelfTestPass(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		secret, _ := contactedFixture(t, database, mintedAt)

		result, outcome, err := Provision(context.Background(), database, HashToken(secret), mintedAt.Add(time.Minute), fakeIssue)
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}
		if outcome != Provisioned {
			t.Fatalf("Provision outcome = %v, want Provisioned", outcome)
		}
		canaryID := result.CanaryID

		// The agent needs a last-seen address before a self-test can be
		// minted against it (internal/selftestsched's own eligibility
		// check) -- in production this comes from completeRotation's
		// first-contact write (internal/ingest/auth.go); this test sets
		// it directly, the same way insertHoneypotCanary's fixtures do,
		// to isolate step 9 (the flip) from step 8 (the mint's own
		// address plumbing, exercised at the ingest layer instead).
		if err := SetCanaryLastSeenAddr(context.Background(), database, canaryID, "192.0.2.50"); err != nil {
			t.Fatalf("SetCanaryLastSeenAddr: %v", err)
		}

		now := mintedAt.Add(2 * time.Minute)
		// A heartbeat so applyStatus reads "ok" rather than "silent" --
		// silent outranks pending (healthStateRank), and this test wants
		// to isolate the pending signal, not silence.
		if err := RecordHeartbeat(context.Background(), database, canaryID, now); err != nil {
			t.Fatalf("RecordHeartbeat: %v", err)
		}
		before := listCanaries(t, database, now, 24*time.Hour)
		c := findCanary(t, before, canaryID)
		if c.RegisteredAt != nil {
			t.Fatalf("RegisteredAt = %v, want nil (provisioned, not yet self-tested)", c.RegisteredAt)
		}
		if c.Status != string(StatePending) {
			t.Fatalf("Status = %q, want %q", c.Status, StatePending)
		}

		// Issue #47 step 8's mint, done directly here rather than through
		// selftestsched.Scheduler.FirstContact -- that method's own
		// mint/eligibility logic is covered in internal/selftestsched;
		// this test isolates the store-level flip.
		idx := NewSelfTestIndex()
		cmd := mintSelfTestCommand(t, database, idx, canaryID, now, 10*time.Minute)
		marker := mustDecodeParams(t, cmd).Targets[0].Marker

		alert := AlertInsert{InstanceID: canaryID, DestPort: 22, Service: "ssh", Raw: `{"logdata":{"probe":"` + marker + `"}}`}
		matched, err := MatchSelfTest(context.Background(), database, idx, alert, now.Add(time.Second))
		if err != nil {
			t.Fatalf("MatchSelfTest: %v", err)
		}
		if !matched {
			t.Fatal("MatchSelfTest did not recognise the issued marker")
		}

		after := listCanaries(t, database, now.Add(2*time.Second), 24*time.Hour)
		c2 := findCanary(t, after, canaryID)
		if c2.RegisteredAt == nil {
			t.Fatal("RegisteredAt is still nil after the self-test passed")
		}
		if c2.Status != string(StateOK) {
			t.Fatalf("Status = %q, want %q (registered and heartbeating is never modeled here, but pending must be gone)", c2.Status, StateOK)
		}
	})
}

// TestPendingCanaryStaysPendingWhenSelfTestExpires is issue #47 step 3's
// other required case: a run that expires unmatched leaves the canary
// pending -- never registered by a timer or an operator action -- and
// also self-test-failed, per #46's sweep.
func TestPendingCanaryStaysPendingWhenSelfTestExpires(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		secret, _ := contactedFixture(t, database, mintedAt)

		result, outcome, err := Provision(context.Background(), database, HashToken(secret), mintedAt.Add(time.Minute), fakeIssue)
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}
		if outcome != Provisioned {
			t.Fatalf("Provision outcome = %v, want Provisioned", outcome)
		}
		canaryID := result.CanaryID
		if err := SetCanaryLastSeenAddr(context.Background(), database, canaryID, "192.0.2.51"); err != nil {
			t.Fatalf("SetCanaryLastSeenAddr: %v", err)
		}

		now := mintedAt.Add(2 * time.Minute)
		// A heartbeat so applyStatus reads "ok" rather than "silent" --
		// silent would otherwise outrank both self-test-failed and
		// pending and hide what this test actually checks.
		if err := RecordHeartbeat(context.Background(), database, canaryID, now); err != nil {
			t.Fatalf("RecordHeartbeat: %v", err)
		}
		idx := NewSelfTestIndex()
		mintSelfTestCommand(t, database, idx, canaryID, now, time.Minute) // never matched

		afterDeadline := now.Add(2 * time.Minute)
		n, err := SweepExpiredSelfTestRuns(context.Background(), database, afterDeadline)
		if err != nil {
			t.Fatalf("SweepExpiredSelfTestRuns: %v", err)
		}
		if n != 1 {
			t.Fatalf("swept %d runs, want 1", n)
		}

		canaries := listCanaries(t, database, afterDeadline.Add(time.Second), 24*time.Hour)
		c := findCanary(t, canaries, canaryID)
		if c.RegisteredAt != nil {
			t.Fatalf("RegisteredAt = %v, want nil (the run expired unmatched, never registered)", c.RegisteredAt)
		}
		// self_test_failed outranks pending (health.go's healthStateRank),
		// so that's the headline; pending is still in ActiveStates.
		if c.Status != string(StateTestFailed) {
			t.Fatalf("Status = %q, want %q", c.Status, StateTestFailed)
		}
		foundPending := false
		for _, s := range c.ActiveStates {
			if s == string(StatePending) {
				foundPending = true
			}
		}
		if !foundPending {
			t.Fatalf("ActiveStates = %v, want it to include %q", c.ActiveStates, StatePending)
		}
	})
}
