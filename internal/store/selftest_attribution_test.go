package store

import (
	"context"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// mintNTPSelfTestCommand mints a single ntp:123 target -- attributed
// grade, #46 slice 2 -- for canaryID.
func mintNTPSelfTestCommand(t *testing.T, database *db.DB, idx *SelfTestIndex, canaryID string, issuedAt time.Time, ttl time.Duration) CanaryCommand {
	t.Helper()
	cmd, err := MintSelfTestCommand(context.Background(), database, idx, canaryID, "192.0.2.10",
		[]SelfTestTarget{{Service: "ntp", DestPort: 123}}, issuedAt, issuedAt.Add(ttl))
	if err != nil {
		t.Fatalf("MintSelfTestCommand(ntp): %v", err)
	}
	return cmd
}

// TestResolveAttributedTargetsExactlyOneCandidateMatches is #46 slice
// 2's attributed grade, the match half (notes 19855/19897/20740): a
// single real alert of the run's service, from the canary's own
// reported address, inside the run's window, is retroactively claimed
// once the deadline sweep runs -- marked synthetic, and the run passes.
func TestResolveAttributedTargetsExactlyOneCandidateMatches(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{ID: "canary-a", Name: "a", Lane: "l", Ports: "123", EnrolledAt: time.Now()})
		if err := SetCanaryLastSeenAddr(context.Background(), database, "canary-a", "192.0.2.10"); err != nil {
			t.Fatalf("SetCanaryLastSeenAddr: %v", err)
		}
		idx := NewSelfTestIndex()
		now := time.Now().UTC()
		cmd := mintNTPSelfTestCommand(t, database, idx, "canary-a", now, 10*time.Minute)

		// The self-test's own ntp probe, arriving mid-window from the
		// canary's own address -- exactly one candidate.
		stored, err := InsertAlertIfNew(context.Background(), database, AlertInsert{
			InstanceID: "canary-a", Service: "ntp", SourceIP: "192.0.2.10", DestPort: 123,
			Raw: `{"logdata":{"NTP CMD":"monlist"}}`, ReceivedAt: now.Add(time.Minute),
		})
		if err != nil || !stored {
			t.Fatalf("InsertAlertIfNew: stored=%v err=%v", stored, err)
		}

		afterDeadline := now.Add(11 * time.Minute)
		swept, err := SweepExpiredSelfTestRuns(context.Background(), database, afterDeadline)
		if err != nil {
			t.Fatalf("SweepExpiredSelfTestRuns: %v", err)
		}
		if swept != 0 {
			// The run should already be completed (passed) by
			// resolveAttributedTargets' own call to recordSelfTestMatch,
			// so the deadline UPDATE's "WHERE completed_at IS NULL"
			// finds nothing left to fail.
			t.Fatalf("swept (failed) = %d, want 0 -- the run should have passed via attribution", swept)
		}

		run, ok, err := LatestCompletedSelfTestRun(context.Background(), database, "canary-a")
		if err != nil {
			t.Fatalf("LatestCompletedSelfTestRun: %v", err)
		}
		if !ok {
			t.Fatal("no completed run found")
		}
		if run.CommandID != cmd.ID {
			t.Fatalf("completed run = %s, want %s", run.CommandID, cmd.ID)
		}
		if run.Passed == nil || !*run.Passed {
			t.Fatalf("Passed = %v, want true", run.Passed)
		}

		alerts, err := ListAlerts(context.Background(), database, AlertFilter{InstanceID: "canary-a"})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		if len(alerts) != 1 || !alerts[0].Synthetic {
			t.Fatalf("alerts = %+v, want exactly one, synthetic=true", alerts)
		}
	})
}

// TestResolveAttributedTargetsTwoCandidatesBothStayReal is the slice 2
// brief's required negative test: two candidate events of the run's
// service, both from the canary's own address inside the window, means
// neither is distinguishable from the other -- the exactly-one rule
// claims nothing, and both stay real alerts. The run then fails (the
// ntp target never matched), which is the fail-closed direction: an
// intruder sharing the self-test's window with a genuine hit must never
// be the one left hidden.
func TestResolveAttributedTargetsTwoCandidatesBothStayReal(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{ID: "canary-a", Name: "a", Lane: "l", Ports: "123", EnrolledAt: time.Now()})
		if err := SetCanaryLastSeenAddr(context.Background(), database, "canary-a", "192.0.2.10"); err != nil {
			t.Fatalf("SetCanaryLastSeenAddr: %v", err)
		}
		idx := NewSelfTestIndex()
		now := time.Now().UTC()
		mintNTPSelfTestCommand(t, database, idx, "canary-a", now, 10*time.Minute)

		for i := 0; i < 2; i++ {
			stored, err := InsertAlertIfNew(context.Background(), database, AlertInsert{
				InstanceID: "canary-a", Service: "ntp", SourceIP: "192.0.2.10", DestPort: 123,
				Raw: `{"logdata":{"NTP CMD":"monlist"}}`, ReceivedAt: now.Add(time.Duration(i+1) * time.Minute),
			})
			if err != nil || !stored {
				t.Fatalf("InsertAlertIfNew(%d): stored=%v err=%v", i, stored, err)
			}
		}

		afterDeadline := now.Add(11 * time.Minute)
		swept, err := SweepExpiredSelfTestRuns(context.Background(), database, afterDeadline)
		if err != nil {
			t.Fatalf("SweepExpiredSelfTestRuns: %v", err)
		}
		if swept != 1 {
			t.Fatalf("swept (failed) = %d, want 1 -- two candidates must resolve to nothing claimed", swept)
		}

		run, ok, err := LatestCompletedSelfTestRun(context.Background(), database, "canary-a")
		if err != nil {
			t.Fatalf("LatestCompletedSelfTestRun: %v", err)
		}
		if !ok {
			t.Fatal("no completed run found")
		}
		if run.Passed == nil || *run.Passed {
			t.Fatalf("Passed = %v, want false", run.Passed)
		}

		alerts, err := ListAlerts(context.Background(), database, AlertFilter{InstanceID: "canary-a"})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		if len(alerts) != 2 {
			t.Fatalf("got %d alerts, want 2", len(alerts))
		}
		for _, a := range alerts {
			if a.Synthetic {
				t.Errorf("alert %d marked synthetic; want every candidate to stay real when there are two", a.ID)
			}
		}
	})
}

// TestResolveAttributedTargetsNoCandidateStaysUnmatched: zero candidates
// leaves the target unmatched and the run fails, the same fail-closed
// direction as two.
func TestResolveAttributedTargetsNoCandidateStaysUnmatched(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{ID: "canary-a", Name: "a", Lane: "l", Ports: "123", EnrolledAt: time.Now()})
		if err := SetCanaryLastSeenAddr(context.Background(), database, "canary-a", "192.0.2.10"); err != nil {
			t.Fatalf("SetCanaryLastSeenAddr: %v", err)
		}
		idx := NewSelfTestIndex()
		now := time.Now().UTC()
		mintNTPSelfTestCommand(t, database, idx, "canary-a", now, 10*time.Minute)

		afterDeadline := now.Add(11 * time.Minute)
		swept, err := SweepExpiredSelfTestRuns(context.Background(), database, afterDeadline)
		if err != nil {
			t.Fatalf("SweepExpiredSelfTestRuns: %v", err)
		}
		if swept != 1 {
			t.Fatalf("swept (failed) = %d, want 1", swept)
		}
		run, ok, err := LatestCompletedSelfTestRun(context.Background(), database, "canary-a")
		if err != nil {
			t.Fatalf("LatestCompletedSelfTestRun: %v", err)
		}
		if !ok {
			t.Fatal("no completed run found")
		}
		if run.Passed == nil || *run.Passed {
			t.Fatalf("Passed = %v, want false", run.Passed)
		}
	})
}

// TestResolveAttributedTargetsNoLastSeenAddrLeavesTargetUnmatched: a
// canary with no LastSeenAddr on record has nothing to attribute
// against -- fail closed, the same answer MatchSelfTest gives an
// unknown canary.
func TestResolveAttributedTargetsNoLastSeenAddrLeavesTargetUnmatched(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{ID: "canary-a", Name: "a", Lane: "l", Ports: "123", EnrolledAt: time.Now()})
		idx := NewSelfTestIndex()
		now := time.Now().UTC()
		cmd := mintNTPSelfTestCommand(t, database, idx, "canary-a", now, 10*time.Minute)

		afterDeadline := now.Add(11 * time.Minute)
		if err := resolveAttributedTargets(context.Background(), database, cmd.ID, "canary-a", now, now.Add(10*time.Minute), afterDeadline); err != nil {
			t.Fatalf("resolveAttributedTargets: %v", err)
		}
		swept, err := SweepExpiredSelfTestRuns(context.Background(), database, afterDeadline)
		if err != nil {
			t.Fatalf("SweepExpiredSelfTestRuns: %v", err)
		}
		if swept != 1 {
			t.Fatalf("swept (failed) = %d, want 1", swept)
		}
	})
}
