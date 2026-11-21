package history

import (
	"context"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// TestMaintenanceDoesNotCloseOrSplitASilentSpan (#227 amendment):
// maintenance is a flag, so setting it and clearing it on a silent canary
// leaves its one outage span open and unbroken. A recovery that never
// happened must not appear on the timeline.
func TestMaintenanceDoesNotCloseOrSplitASilentSpan(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		t0 := mustParse(t, "2026-01-01T00:00:00Z")
		addCanary(t, database, "canary-1", "one", t0)
		r := New(database, "")

		t1 := t0.Add(10 * time.Minute)
		tick(t, r, t1) // silent opens
		before := periods(t, database, "canary-1")
		if len(before) != 1 || before[0].State != string(store.StateSilent) || before[0].EndedAt != nil {
			t.Fatalf("setup: spans = %+v, want one open silent span", before)
		}

		t2 := t1.Add(time.Minute)
		if err := store.SetCanaryMaintenance(context.Background(), database, "canary-1", t2.Add(2*time.Hour), t2, "erebus-admin"); err != nil {
			t.Fatalf("SetCanaryMaintenance: %v", err)
		}
		tick(t, r, t2)
		tick(t, r, t2.Add(time.Minute))

		// Longer than collapseWindow, so a span wrongly closed by maintenance
		// could not be quietly merged back and hide the bug.
		t3 := t2.Add(collapseWindow + 20*time.Minute)
		if err := store.ClearCanaryMaintenance(context.Background(), database, "canary-1", t3, "erebus-admin"); err != nil {
			t.Fatalf("ClearCanaryMaintenance: %v", err)
		}
		tick(t, r, t3)
		tick(t, r, t3.Add(time.Minute))

		after := periods(t, database, "canary-1")
		if len(after) != 1 {
			t.Fatalf("after set and clear: %d spans, want the one original: %+v", len(after), after)
		}
		if after[0].EndedAt != nil || after[0].EndReason != nil || !after[0].StartedAt.Equal(before[0].StartedAt) {
			t.Errorf("span = %+v, want it still open and unchanged from %+v", after[0], before[0])
		}
	})
}
