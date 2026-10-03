package store

import (
	"context"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// TestListSelfTestRunsWindowOrderAndFailures is issue #118's read: the
// canary page draws a tick per run, so it needs every run inside the
// window it is showing, newest first, and the names of the services a
// failed run never reached.
func TestListSelfTestRunsWindowOrderAndFailures(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		base := time.Date(2026, 9, 5, 4, 0, 0, 0, time.UTC)
		insertCanary(t, database, Canary{ID: "canary-a", Name: "a", Lane: "iot", Ports: "ssh 22", EnrolledAt: base.Add(-30 * 24 * time.Hour)})
		idx := NewSelfTestIndex()

		// Three daily runs, plus one a fortnight before the window.
		mintSelfTestCommand(t, database, idx, "canary-a", base.Add(-20*24*time.Hour), 10*time.Minute)
		mintSelfTestCommand(t, database, idx, "canary-a", base.Add(-48*time.Hour), 10*time.Minute)
		mintSelfTestCommand(t, database, idx, "canary-a", base.Add(-24*time.Hour), 10*time.Minute)
		mintSelfTestCommand(t, database, idx, "canary-a", base, 10*time.Minute)

		// Fail every run that has passed its deadline: only the newest
		// is still inside its window at `now`.
		if _, err := SweepExpiredSelfTestRuns(ctx, database, base.Add(5*time.Minute)); err != nil {
			t.Fatalf("SweepExpiredSelfTestRuns: %v", err)
		}

		now := base.Add(5 * time.Minute)
		runs, err := ListSelfTestRuns(ctx, database, "canary-a", now.Add(-14*24*time.Hour), now)
		if err != nil {
			t.Fatalf("ListSelfTestRuns: %v", err)
		}
		if len(runs) != 3 {
			t.Fatalf("got %d runs, want the three inside the fortnight (a fourth was issued 20 days ago)", len(runs))
		}
		for i := 1; i < len(runs); i++ {
			if !runs[i-1].IssuedAt.After(runs[i].IssuedAt) {
				t.Errorf("runs[%d] issued %v is not after runs[%d] issued %v -- want newest first", i-1, runs[i-1].IssuedAt, i, runs[i].IssuedAt)
			}
		}
		if !runs[0].IssuedAt.Equal(base) {
			t.Errorf("runs[0].IssuedAt = %v, want the newest run at %v", runs[0].IssuedAt, base)
		}
		if runs[0].Passed != nil {
			t.Errorf("runs[0].Passed = %v, want nil -- the newest run is still inside its deadline", *runs[0].Passed)
		}
		if runs[0].FailedServices != nil {
			t.Errorf("runs[0].FailedServices = %v, want none for an unresolved run", runs[0].FailedServices)
		}
		swept := runs[1]
		if swept.Passed == nil || *swept.Passed {
			t.Fatalf("runs[1].Passed = %v, want false -- the sweep failed it", swept.Passed)
		}
		if len(swept.FailedServices) != 1 || swept.FailedServices[0] != "ssh 22" {
			t.Errorf("runs[1].FailedServices = %v, want [ssh 22]", swept.FailedServices)
		}
	})
}

// TestListSelfTestRunsIgnoresOtherCanaries: one canary's page must never
// draw another canary's ticks.
func TestListSelfTestRunsIgnoresOtherCanaries(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		at := time.Date(2026, 9, 5, 4, 0, 0, 0, time.UTC)
		insertCanary(t, database, Canary{ID: "canary-a", Name: "a", Lane: "iot", Ports: "ssh 22", EnrolledAt: at.Add(-time.Hour)})
		insertCanary(t, database, Canary{ID: "canary-b", Name: "b", Lane: "lan", Ports: "ssh 22", EnrolledAt: at.Add(-time.Hour)})
		idx := NewSelfTestIndex()
		mintSelfTestCommand(t, database, idx, "canary-a", at, 10*time.Minute)
		mintSelfTestCommand(t, database, idx, "canary-b", at, 10*time.Minute)

		runs, err := ListSelfTestRuns(ctx, database, "canary-a", at.Add(-time.Hour), at.Add(time.Hour))
		if err != nil {
			t.Fatalf("ListSelfTestRuns: %v", err)
		}
		if len(runs) != 1 || runs[0].CanaryID != "canary-a" {
			t.Fatalf("got %+v, want exactly canary-a's one run", runs)
		}
	})
}
