package store

import (
	"context"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/db"
)

func boolPtr(b bool) *bool { return &b }

func TestNotDeliveringNilNeverTriggers(t *testing.T) {
	// No self-report has ever arrived: must read as "nothing to say yet",
	// never as a failing log read.
	if notDelivering(Canary{AgentLogReadOK: nil}) {
		t.Error("notDelivering(nil AgentLogReadOK) = true, want false")
	}
}

func TestNotDeliveringBoundary(t *testing.T) {
	if notDelivering(Canary{AgentLogReadOK: boolPtr(true)}) {
		t.Error("notDelivering(log read ok) = true, want false")
	}
	if !notDelivering(Canary{AgentLogReadOK: boolPtr(false)}) {
		t.Error("notDelivering(log read failing) = false, want true")
	}
}

func recordAudit(t *testing.T, database *db.DB, action, target string, at time.Time) {
	t.Helper()
	if _, err := audit.Append(context.Background(), database, audit.Entry{
		Action: action, Target: target, Reason: "test", TriggeredBy: target, CreatedAt: at,
	}); err != nil {
		t.Fatalf("audit.Append(%s, %s, %v): %v", action, target, at, err)
	}
}

func TestLatestAuditSinceBoundary(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		now := mustParse(t, "2026-01-01T00:10:00Z")

		// Just inside the 5-minute throttled window (exactly at the
		// cutoff): the >= comparison must include it.
		recordAudit(t, database, "ingest.rate_limited", "canary-in", now.Add(-throttledWindow))
		got, err := latestAuditSince(context.Background(), database, "ingest.rate_limited", "canary-in", now.Add(-throttledWindow))
		if err != nil {
			t.Fatalf("latestAuditSince: %v", err)
		}
		if got == nil {
			t.Fatal("latestAuditSince at exactly the cutoff = nil, want the entry")
		}

		// Just outside: one second before the cutoff.
		recordAudit(t, database, "ingest.rate_limited", "canary-out", now.Add(-throttledWindow-time.Second))
		got, err = latestAuditSince(context.Background(), database, "ingest.rate_limited", "canary-out", now.Add(-throttledWindow))
		if err != nil {
			t.Fatalf("latestAuditSince: %v", err)
		}
		if got != nil {
			t.Errorf("latestAuditSince one second outside window = %v, want nil", got)
		}
	})
}

func TestLatestAuditSincePicksMostRecent(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		earlier := mustParse(t, "2026-01-01T00:00:00Z")
		later := mustParse(t, "2026-01-01T00:02:00Z")
		recordAudit(t, database, "ingest.token_conflict", "canary-a", earlier)
		recordAudit(t, database, "ingest.token_conflict", "canary-a", later)

		got, err := latestAuditSince(context.Background(), database, "ingest.token_conflict", "canary-a", earlier.Add(-time.Second))
		if err != nil {
			t.Fatalf("latestAuditSince: %v", err)
		}
		if got == nil || !got.Equal(later) {
			t.Errorf("latestAuditSince = %v, want %v (the later entry)", got, later)
		}
	})
}

func mintTokenAt(t *testing.T, database *db.DB, canaryID string, at time.Time) CanaryToken {
	t.Helper()
	_, tok, err := MintCanaryToken(context.Background(), database, canaryID, at)
	if err != nil {
		t.Fatalf("MintCanaryToken(%s, %v): %v", canaryID, at, err)
	}
	return tok
}

func useToken(t *testing.T, database *db.DB, id string, at time.Time) {
	t.Helper()
	if err := RecordCanaryTokenUse(context.Background(), database, id, at); err != nil {
		t.Fatalf("RecordCanaryTokenUse(%s, %v): %v", id, at, err)
	}
}

// TestRotationSignalSingleTokenNeverStalls: a canary's first-ever token,
// still unused, is enrollment/pending territory (#47), never
// rotation-stalled -- regardless of how long it's been sitting there.
func TestRotationSignalSingleTokenNeverStalls(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintAt := mustParse(t, "2026-01-01T00:00:00Z")
		mintTokenAt(t, database, "canary-a", mintAt)

		stalled, _, _, err := rotationSignal(context.Background(), database, "canary-a", mintAt.Add(48*time.Hour))
		if err != nil {
			t.Fatalf("rotationSignal: %v", err)
		}
		if stalled {
			t.Error("rotationSignal(single unused token, 48h later) = stalled, want not stalled")
		}
	})
}

// TestRotationSignalIssuedUnusedBoundary exercises the 15-minute
// issued-but-unused trigger's boundary, and its 24h escalation boundary.
func TestRotationSignalIssuedUnusedBoundary(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		first := mustParse(t, "2026-01-01T00:00:00Z")
		firstTok := mintTokenAt(t, database, "canary-a", first)
		useToken(t, database, firstTok.ID, first)

		rotatedAt := first.Add(time.Hour)
		mintTokenAt(t, database, "canary-a", rotatedAt) // issued, never used

		// Just inside 15 minutes: not yet stalled.
		stalled, _, _, err := rotationSignal(context.Background(), database, "canary-a", rotatedAt.Add(rotationStalledThreshold-time.Second))
		if err != nil {
			t.Fatalf("rotationSignal: %v", err)
		}
		if stalled {
			t.Error("rotationSignal one second before 15m = stalled, want not stalled")
		}

		// Exactly at 15 minutes: stalled, not yet escalated.
		stalled, escalated, sinceS, err := rotationSignal(context.Background(), database, "canary-a", rotatedAt.Add(rotationStalledThreshold))
		if err != nil {
			t.Fatalf("rotationSignal: %v", err)
		}
		if !stalled {
			t.Fatal("rotationSignal at exactly 15m = not stalled, want stalled")
		}
		if escalated {
			t.Error("rotationSignal at exactly 15m = escalated, want not yet escalated")
		}
		if sinceS != int64(rotationStalledThreshold.Seconds()) {
			t.Errorf("sinceS = %d, want %d", sinceS, int64(rotationStalledThreshold.Seconds()))
		}

		// Just before 24h: stalled, not escalated.
		stalled, escalated, _, err = rotationSignal(context.Background(), database, "canary-a", rotatedAt.Add(rotationStalledEscalateThreshold-time.Second))
		if err != nil {
			t.Fatalf("rotationSignal: %v", err)
		}
		if !stalled || escalated {
			t.Errorf("rotationSignal one second before 24h = stalled=%v escalated=%v, want stalled=true escalated=false", stalled, escalated)
		}

		// Exactly at 24h: escalated.
		stalled, escalated, _, err = rotationSignal(context.Background(), database, "canary-a", rotatedAt.Add(rotationStalledEscalateThreshold))
		if err != nil {
			t.Fatalf("rotationSignal: %v", err)
		}
		if !stalled || !escalated {
			t.Errorf("rotationSignal at exactly 24h = stalled=%v escalated=%v, want both true", stalled, escalated)
		}
	})
}

// TestRotationSignalSupersededIssueDoesNotFireSpuriously: an
// issued-but-never-used token from an earlier, superseded rotation
// attempt must not keep signaling stalled once a later rotation has been
// issued (and is itself still fresh) -- issue #45: "tracks the latest
// issuance per canary so a superseded earlier issue does not fire
// spuriously."
func TestRotationSignalSupersededIssueDoesNotFireSpuriously(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		first := mustParse(t, "2026-01-01T00:00:00Z")
		firstTok := mintTokenAt(t, database, "canary-a", first)
		useToken(t, database, firstTok.ID, first)

		// An earlier rotation attempt, issued 20 minutes in and never
		// used -- already past the 15m threshold on its own, so a naive
		// "any unused token past threshold" check would fire on it.
		staleIssue := mintTokenAt(t, database, "canary-a", first.Add(20*time.Minute))
		_ = staleIssue

		// A fresh reissue, superseding the stale one, minted a minute
		// later and itself still only 1 minute old at "now" below.
		freshIssue := mintTokenAt(t, database, "canary-a", first.Add(21*time.Minute))
		_ = freshIssue

		// 1 minute after the latest issuance, and only 22 minutes after
		// firstTok became active -- nowhere near the independent 25h
		// no-completed-rotation trigger, so only the issued-unused
		// signal is in play here.
		now := first.Add(22 * time.Minute)
		stalled, _, _, err := rotationSignal(context.Background(), database, "canary-a", now)
		if err != nil {
			t.Fatalf("rotationSignal: %v", err)
		}
		if stalled {
			t.Error("rotationSignal with a fresh (1m old) latest issuance = stalled, want not stalled (superseded stale issue must not fire)")
		}
	})
}

// TestRotationSignalNoCompletedRotationBoundary exercises the second,
// independent ~25h trigger: an agent that never asks to rotate again
// after its token first became active.
func TestRotationSignalNoCompletedRotationBoundary(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintAt := mustParse(t, "2026-01-01T00:00:00Z")
		tok := mintTokenAt(t, database, "canary-a", mintAt)
		useToken(t, database, tok.ID, mintAt.Add(time.Second)) // activated shortly after mint

		// Just before 25h since mint: not stalled.
		stalled, _, _, err := rotationSignal(context.Background(), database, "canary-a", mintAt.Add(rotationStaleThreshold-time.Second))
		if err != nil {
			t.Fatalf("rotationSignal: %v", err)
		}
		if stalled {
			t.Error("rotationSignal one second before 25h = stalled, want not stalled")
		}

		// Exactly at 25h: stalled and escalated (this trigger has no
		// separate escalation step -- it's already past its own bar).
		stalled, escalated, _, err := rotationSignal(context.Background(), database, "canary-a", mintAt.Add(rotationStaleThreshold))
		if err != nil {
			t.Fatalf("rotationSignal: %v", err)
		}
		if !stalled || !escalated {
			t.Errorf("rotationSignal at exactly 25h = stalled=%v escalated=%v, want both true", stalled, escalated)
		}
	})
}

// TestApplyHealthStatePrecedence exercises issue #45's proposed ranking
// across every pairing this slice builds: the worse state always wins,
// regardless of the order signals are passed in.
func TestApplyHealthStatePrecedence(t *testing.T) {
	now := mustParse(t, "2026-01-01T00:00:00Z")

	cases := []struct {
		name             string
		status           string // pre-applyStatus value ("ok" or "silent")
		notDeliveringNow bool
		throttled        bool
		rotationStalled  bool
		tokenConflict    bool
		want             HealthState
	}{
		{"ok alone", "ok", false, false, false, false, StateOK},
		{"throttled alone", "ok", false, true, false, false, StateThrottled},
		{"rotation stalled alone", "ok", false, false, true, false, StateRotationStalled},
		{"throttled beats rotation stalled", "ok", false, true, true, false, StateThrottled},
		{"not delivering beats throttled", "ok", true, true, false, false, StateNotDelivering},
		{"silent beats not delivering", "silent", true, false, false, false, StateSilent},
		{"silent beats rotation stalled", "silent", false, false, true, false, StateSilent},
		{"token conflict beats silent", "silent", false, false, false, true, StateTokenConflict},
		{"token conflict beats everything", "silent", true, true, true, true, StateTokenConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Canary{Status: tc.status}
			var throttledSince, tokenConflictSince *time.Time
			if tc.throttled {
				t0 := now.Add(-time.Minute)
				throttledSince = &t0
			}
			if tc.tokenConflict {
				t0 := now.Add(-time.Minute)
				tokenConflictSince = &t0
			}
			applyHealthState(&c, tc.notDeliveringNow, throttledSince, tc.rotationStalled, false, 60, tokenConflictSince, now)
			if c.Status != string(tc.want) {
				t.Errorf("Status = %q, want %q", c.Status, tc.want)
			}
		})
	}
}

// TestApplyHealthStateKeepsDetailForNonWinningStates: "one state on the
// tile, the worst; the rest in its detail" -- a losing signal's own
// detail field must still be populated even though it didn't win Status.
func TestApplyHealthStateKeepsDetailForNonWinningStates(t *testing.T) {
	now := mustParse(t, "2026-01-01T00:00:00Z")
	c := Canary{Status: "ok"}
	throttledSince := now.Add(-2 * time.Minute)
	applyHealthState(&c, true /* not delivering wins */, &throttledSince, true, false, 900, nil, now)

	if c.Status != string(StateNotDelivering) {
		t.Fatalf("Status = %q, want %q", c.Status, StateNotDelivering)
	}
	if !c.NotDelivering {
		t.Error("NotDelivering = false, want true")
	}
	if c.ThrottledForS == nil || *c.ThrottledForS != 120 {
		t.Errorf("ThrottledForS = %v, want 120", c.ThrottledForS)
	}
	if !c.RotationStalled || c.RotationStalledForS == nil || *c.RotationStalledForS != 900 {
		t.Errorf("RotationStalled detail = %v/%v, want true/900", c.RotationStalled, c.RotationStalledForS)
	}
}

// TestListCanariesSurfacesThrottledAndTokenConflict is an end-to-end
// check through ListCanaries itself (not just the derivation helpers),
// on both engines: a rate-limit crossing and a token-conflict entry
// recorded via the real audit.Append path are read back as the
// corresponding ordered health state.
func TestListCanariesSurfacesThrottledAndTokenConflict(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrolledAt := mustParse(t, "2026-01-01T00:00:00Z")
		insertCanary(t, database, Canary{
			ID: "canary-throttled", Name: "canary-throttled", Lane: "lan",
			HeartbeatIntervalS: 60, EnrolledAt: enrolledAt,
		})
		insertCanary(t, database, Canary{
			ID: "canary-conflict", Name: "canary-conflict", Lane: "lan",
			HeartbeatIntervalS: 60, EnrolledAt: enrolledAt,
		})
		now := enrolledAt.Add(time.Minute)
		if err := RecordHeartbeat(context.Background(), database, "canary-throttled", now); err != nil {
			t.Fatalf("RecordHeartbeat: %v", err)
		}
		if err := RecordHeartbeat(context.Background(), database, "canary-conflict", now); err != nil {
			t.Fatalf("RecordHeartbeat: %v", err)
		}
		recordAudit(t, database, "ingest.rate_limited", "canary-throttled", now.Add(-time.Minute))
		recordAudit(t, database, "ingest.token_conflict", "canary-conflict", now.Add(-time.Minute))

		canaries := listCanaries(t, database, now, rangeDurations[DefaultRange])
		throttled := findCanary(t, canaries, "canary-throttled")
		conflict := findCanary(t, canaries, "canary-conflict")

		if throttled.Status != string(StateThrottled) {
			t.Errorf("throttled canary Status = %q, want %q", throttled.Status, StateThrottled)
		}
		if throttled.ThrottledForS == nil {
			t.Error("throttled canary ThrottledForS = nil, want set")
		}
		if conflict.Status != string(StateTokenConflict) {
			t.Errorf("conflict canary Status = %q, want %q", conflict.Status, StateTokenConflict)
		}
		if conflict.TokenConflictForS == nil {
			t.Error("conflict canary TokenConflictForS = nil, want set")
		}
	})
}

// TestListCanariesSurfacesNotDelivering checks the agent_log_read_ok
// self-report path end-to-end through RecordCanaryAgentHeartbeat and
// ListCanaries.
func TestListCanariesSurfacesNotDelivering(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrolledAt := mustParse(t, "2026-01-01T00:00:00Z")
		insertCanary(t, database, Canary{
			ID: "canary-a", Name: "canary-a", Lane: "lan",
			HeartbeatIntervalS: 60, EnrolledAt: enrolledAt,
		})
		now := enrolledAt.Add(time.Minute)
		if err := RecordCanaryAgentHeartbeat(context.Background(), database, "canary-a", now, AgentHeartbeat{
			QueueDepth: 3, LogReadOK: false, LastEventID: "abc",
		}); err != nil {
			t.Fatalf("RecordCanaryAgentHeartbeat: %v", err)
		}

		c := findCanary(t, listCanaries(t, database, now, rangeDurations[DefaultRange]), "canary-a")
		if c.Status != string(StateNotDelivering) {
			t.Errorf("Status = %q, want %q", c.Status, StateNotDelivering)
		}
		if !c.NotDelivering {
			t.Error("NotDelivering = false, want true")
		}
	})
}
