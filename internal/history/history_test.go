package history

import (
	"context"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/db/dbtest"
	"github.com/tomlawesome/birdcage/internal/store"
)

// forEachEngine mirrors internal/store's own helper: every test here runs
// against SQLite always, and against Postgres too when
// BIRDCAGE_TEST_DATABASE_URL is set (issue #7), each as its own subtest.
func forEachEngine(t *testing.T, fn func(t *testing.T, database *db.DB)) {
	t.Helper()
	for _, tgt := range dbtest.Targets(t) {
		tgt := tgt
		t.Run(tgt.Name, func(t *testing.T) {
			fn(t, tgt.DB)
		})
	}
}

// windowStart/windowEnd bound every ListStatePeriods call below widely
// enough that the window itself never decides what a test sees.
var (
	windowStart = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	windowEnd   = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
)

func mustParse(t *testing.T, s string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return parsed
}

// addCanary registers a canary and beats it at at, so it reads "ok"
// rather than "silent" -- silence is a state of its own, and a test about
// throttling should not also be a test about heartbeats.
func addCanary(t *testing.T, database *db.DB, id, name string, at time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := store.InsertCanary(ctx, database, store.Canary{
		ID: id, Name: name, Lane: "lan", HeartbeatIntervalS: 60, EnrolledAt: at.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("InsertCanary(%s): %v", id, err)
	}
	beat(t, database, id, at)
}

func beat(t *testing.T, database *db.DB, id string, at time.Time) {
	t.Helper()
	if err := store.RecordHeartbeat(context.Background(), database, id, at); err != nil {
		t.Fatalf("RecordHeartbeat(%s, %v): %v", id, at, err)
	}
}

// signal writes the audit entry one of issue #45's states is derived
// from: "ingest.rate_limited" makes a canary throttled for the next five
// minutes, "ingest.token_conflict" for the next 24 hours.
func signal(t *testing.T, database *db.DB, action, canaryID string, at time.Time) {
	t.Helper()
	if _, err := audit.Append(context.Background(), database, audit.Entry{
		Action: action, Target: canaryID, Reason: "test", TriggeredBy: canaryID, CreatedAt: at,
	}); err != nil {
		t.Fatalf("audit.Append(%s, %s): %v", action, canaryID, err)
	}
}

func periods(t *testing.T, database *db.DB, canaryID string) []store.StatePeriod {
	t.Helper()
	got, err := store.ListStatePeriods(context.Background(), database, windowStart, windowEnd, canaryID)
	if err != nil {
		t.Fatalf("ListStatePeriods(%s): %v", canaryID, err)
	}
	return got
}

func tick(t *testing.T, r *Recorder, at time.Time) {
	t.Helper()
	if err := r.Tick(context.Background(), at); err != nil {
		t.Fatalf("Tick(%v): %v", at, err)
	}
}

// TestTickOpensAndClearsAState is the basic pair: a state that becomes
// active opens a span, and the same state going away closes it as
// "cleared".
func TestTickOpensAndClearsAState(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		t0 := mustParse(t, "2026-01-01T00:00:00Z")
		addCanary(t, database, "canary-1", "one", t0)
		signal(t, database, "ingest.rate_limited", "canary-1", t0)

		r := New(database)
		tick(t, r, t0)

		got := periods(t, database, "canary-1")
		if len(got) != 1 {
			t.Fatalf("after the first tick: %d spans, want 1: %+v", len(got), got)
		}
		if got[0].State != string(store.StateThrottled) {
			t.Fatalf("state = %q, want throttled", got[0].State)
		}
		if got[0].EndedAt != nil || got[0].EndReason != nil {
			t.Errorf("span = %+v, want it still open", got[0])
		}
		if got[0].CanaryName != "one" {
			t.Errorf("CanaryName = %q, want %q", got[0].CanaryName, "one")
		}

		// A tick while nothing has changed must not open a second span.
		tick(t, r, t0.Add(30*time.Second))
		if got := periods(t, database, "canary-1"); len(got) != 1 {
			t.Fatalf("after a second tick in the same state: %d spans, want 1: %+v", len(got), got)
		}

		// Past the 5-minute throttled window the state is gone. The
		// beat keeps the canary from going silent instead, which would
		// be a different state, not the absence of one.
		t1 := t0.Add(6 * time.Minute)
		beat(t, database, "canary-1", t1)
		tick(t, r, t1)

		got = periods(t, database, "canary-1")
		if len(got) != 1 {
			t.Fatalf("after clearing: %d spans, want 1: %+v", len(got), got)
		}
		if got[0].EndedAt == nil || !got[0].EndedAt.Equal(t1) {
			t.Errorf("EndedAt = %v, want %v", got[0].EndedAt, t1)
		}
		if got[0].EndReason == nil || *got[0].EndReason != store.EndReasonCleared {
			t.Errorf("EndReason = %v, want %q", got[0].EndReason, store.EndReasonCleared)
		}
	})
}

// TestTickClosesTokenConflictAsQuietPeriod: token conflict is the one
// state birdcage cannot see resolved -- it ends after a quiet period with
// no new conflicts, and the row must say that rather than "cleared".
func TestTickClosesTokenConflictAsQuietPeriod(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		t0 := mustParse(t, "2026-01-01T00:00:00Z")
		addCanary(t, database, "canary-1", "one", t0)
		signal(t, database, "ingest.token_conflict", "canary-1", t0)

		r := New(database)
		tick(t, r, t0)
		if got := periods(t, database, "canary-1"); len(got) != 1 || got[0].State != string(store.StateTokenConflict) {
			t.Fatalf("after the first tick: %+v, want one token_conflict span", got)
		}

		// The quiet period is 24h; past it the conflict is no longer
		// active.
		t1 := t0.Add(25 * time.Hour)
		beat(t, database, "canary-1", t1)
		tick(t, r, t1)

		got := periods(t, database, "canary-1")
		if len(got) != 1 {
			t.Fatalf("after the quiet period: %d spans, want 1: %+v", len(got), got)
		}
		if got[0].EndReason == nil || *got[0].EndReason != store.EndReasonQuietPeriod {
			t.Errorf("EndReason = %v, want %q", got[0].EndReason, store.EndReasonQuietPeriod)
		}
	})
}

// TestFlapCollapseBoundary is the growth bound at its edge: a re-entry
// exactly collapseWindow after the span closed continues that span, and
// one second later starts a new one. Two canaries, one per side, so the
// two cases cannot influence each other.
func TestFlapCollapseBoundary(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		t0 := mustParse(t, "2026-01-01T00:00:00Z")
		addCanary(t, database, "canary-in", "in", t0)
		addCanary(t, database, "canary-out", "out", t0)
		signal(t, database, "ingest.rate_limited", "canary-in", t0)
		signal(t, database, "ingest.rate_limited", "canary-out", t0)

		r := New(database)
		tick(t, r, t0)

		// Both clear at t1.
		t1 := t0.Add(6 * time.Minute)
		beat(t, database, "canary-in", t1)
		beat(t, database, "canary-out", t1)
		tick(t, r, t1)

		// canary-in re-enters exactly on the boundary; canary-out one
		// second past it.
		inAt := t1.Add(collapseWindow)
		outAt := t1.Add(collapseWindow + time.Second)
		signal(t, database, "ingest.rate_limited", "canary-in", inAt)
		beat(t, database, "canary-in", inAt)
		beat(t, database, "canary-out", inAt)
		tick(t, r, inAt)

		signal(t, database, "ingest.rate_limited", "canary-out", outAt)
		beat(t, database, "canary-in", outAt)
		beat(t, database, "canary-out", outAt)
		tick(t, r, outAt)

		in := periods(t, database, "canary-in")
		if len(in) != 1 {
			t.Fatalf("canary-in has %d spans, want 1 collapsed span: %+v", len(in), in)
		}
		if in[0].FlapCount != 2 {
			t.Errorf("canary-in flap_count = %d, want 2", in[0].FlapCount)
		}
		if !in[0].StartedAt.Equal(t0) {
			t.Errorf("canary-in started_at = %v, want the original %v", in[0].StartedAt, t0)
		}
		if in[0].EndedAt != nil {
			t.Errorf("canary-in span = %+v, want it reopened", in[0])
		}

		out := periods(t, database, "canary-out")
		if len(out) != 2 {
			t.Fatalf("canary-out has %d spans, want 2 (past the window): %+v", len(out), out)
		}
		for _, p := range out {
			if p.FlapCount != 1 {
				t.Errorf("canary-out flap_count = %d on span %+v, want 1", p.FlapCount, p)
			}
		}
	})
}

// TestStartRecordsTheUnobservedGap: after a gap longer than
// unobservedAfter, spans left open are closed at the last tick -- the
// last moment anything was actually seen -- and the gap itself is one
// "unobserved" span per canary.
func TestStartRecordsTheUnobservedGap(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		t0 := mustParse(t, "2026-01-01T00:00:00Z")
		addCanary(t, database, "canary-1", "one", t0)
		signal(t, database, "ingest.rate_limited", "canary-1", t0)

		r := New(database)
		tick(t, r, t0)

		// Six minutes later: past the throttled window, so the state is
		// genuinely gone by the time birdcage is running again.
		t1 := t0.Add(6 * time.Minute)
		beat(t, database, "canary-1", t1)
		if err := r.Start(context.Background(), t1); err != nil {
			t.Fatalf("Start: %v", err)
		}

		got := periods(t, database, "canary-1")
		if len(got) != 2 {
			t.Fatalf("after Start: %d spans, want 2 (throttled + unobserved): %+v", len(got), got)
		}
		var throttled, unobserved *store.StatePeriod
		for i := range got {
			switch got[i].State {
			case string(store.StateThrottled):
				throttled = &got[i]
			case string(store.StateUnobserved):
				unobserved = &got[i]
			}
		}
		if throttled == nil || unobserved == nil {
			t.Fatalf("spans = %+v, want one throttled and one unobserved", got)
		}
		if throttled.EndedAt == nil || !throttled.EndedAt.Equal(t0) {
			t.Errorf("throttled EndedAt = %v, want the last tick %v", throttled.EndedAt, t0)
		}
		if throttled.EndReason == nil || *throttled.EndReason != store.EndReasonUnobserved {
			t.Errorf("throttled EndReason = %v, want %q", throttled.EndReason, store.EndReasonUnobserved)
		}
		if !unobserved.StartedAt.Equal(t0) || unobserved.EndedAt == nil || !unobserved.EndedAt.Equal(t1) {
			t.Errorf("unobserved span = %+v, want %v..%v", unobserved, t0, t1)
		}
		if unobserved.EndReason == nil || *unobserved.EndReason != store.EndReasonUnobserved {
			t.Errorf("unobserved EndReason = %v, want %q", unobserved.EndReason, store.EndReasonUnobserved)
		}
	})
}

// TestStartWithFreshLastTickRecordsNothing: an ordinary restart is not an
// outage. A gap shorter than unobservedAfter writes no unobserved span at
// all.
func TestStartWithFreshLastTickRecordsNothing(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		t0 := mustParse(t, "2026-01-01T00:00:00Z")
		addCanary(t, database, "canary-1", "one", t0)
		signal(t, database, "ingest.rate_limited", "canary-1", t0)

		r := New(database)
		tick(t, r, t0)

		t1 := t0.Add(30 * time.Second)
		if err := r.Start(context.Background(), t1); err != nil {
			t.Fatalf("Start: %v", err)
		}

		got := periods(t, database, "canary-1")
		if len(got) != 1 {
			t.Fatalf("after Start over a fresh tick: %d spans, want 1: %+v", len(got), got)
		}
		if got[0].State == string(store.StateUnobserved) {
			t.Errorf("span = %+v, want no unobserved span for a 30s gap", got[0])
		}
		if got[0].EndedAt != nil {
			t.Errorf("throttled span = %+v, want it still open across the restart", got[0])
		}
	})
}

// TestStartOnAnEmptyDatabaseRecordsNothing: the very first boot has no
// last tick, so there is no gap to describe -- and nothing must be
// invented for one.
func TestStartOnAnEmptyDatabaseRecordsNothing(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		t0 := mustParse(t, "2026-01-01T00:00:00Z")
		addCanary(t, database, "canary-1", "one", t0)

		if err := New(database).Start(context.Background(), t0); err != nil {
			t.Fatalf("Start: %v", err)
		}
		if got := periods(t, database, ""); len(got) != 0 {
			t.Fatalf("first boot wrote %d spans, want none: %+v", len(got), got)
		}
		last, err := store.GetSetting(context.Background(), database, store.SettingHistoryLastTick)
		if err != nil {
			t.Fatalf("GetSetting: %v", err)
		}
		if last != t0.Format(time.RFC3339Nano) {
			t.Errorf("%s = %q, want %q", store.SettingHistoryLastTick, last, t0.Format(time.RFC3339Nano))
		}
	})
}

// TestTickPropagatesDatabaseErrors is the fault injection issue #56 asks
// for: with the table gone, a tick must fail loudly. Nothing here may
// swallow a database error and carry on as though every state had
// cleared -- an error that read as "nothing is wrong" is exactly the
// failure this history exists to make visible.
func TestTickPropagatesDatabaseErrors(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		t0 := mustParse(t, "2026-01-01T00:00:00Z")
		addCanary(t, database, "canary-1", "one", t0)
		signal(t, database, "ingest.rate_limited", "canary-1", t0)

		r := New(database)
		tick(t, r, t0)

		if _, err := database.Exec(`DROP TABLE canary_state_periods`); err != nil {
			t.Fatalf("drop canary_state_periods: %v", err)
		}
		if err := r.Tick(context.Background(), t0.Add(time.Minute)); err == nil {
			t.Fatal("Tick with the table dropped = nil error, want the failure propagated")
		}
	})
}
