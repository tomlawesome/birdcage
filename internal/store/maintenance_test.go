package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// maintenanceCanary inserts a honeypot that heartbeats every 60 s and last
// did so at beatAt.
func maintenanceCanary(t *testing.T, database *db.DB, id string, beatAt time.Time) {
	t.Helper()
	insertCanary(t, database, Canary{ID: id, Name: id, Lane: "lan", Ports: "22", HeartbeatIntervalS: 60, EnrolledAt: beatAt.Add(-time.Hour)})
	if err := RecordHeartbeat(context.Background(), database, id, beatAt); err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}
}

func hasState(c Canary, state HealthState) bool {
	for _, s := range c.ActiveStates {
		if s == string(state) {
			return true
		}
	}
	return false
}

// TestMaintenanceKeepsSilentReportedAsAFlag: maintenance is a flag, not a
// rewrite of state (#227 amendment). A canary that has missed its
// heartbeats is still reported silent while now < until, with
// MaintenanceUntil set; once until has passed MaintenanceUntil is nil and
// it is still silent. A neighbour is untouched.
func TestMaintenanceKeepsSilentReportedAsAFlag(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		beat := mustParse(t, "2026-01-01T01:00:00Z")
		maintenanceCanary(t, database, "canary-a", beat)
		maintenanceCanary(t, database, "canary-b", beat)

		now := beat.Add(10 * time.Minute) // 600 s: well past 3 x 60 s
		before := findCanary(t, listCanaries(t, database, now, rangeDurations[DefaultRange]), "canary-a")
		if before.Status != "silent" || before.MaintenanceUntil != nil {
			t.Fatalf("before maintenance: Status %q MaintenanceUntil %v, want silent / nil", before.Status, before.MaintenanceUntil)
		}

		until := now.Add(2 * time.Hour)
		if err := SetCanaryMaintenance(context.Background(), database, "canary-a", until, now, "erebus-admin"); err != nil {
			t.Fatalf("SetCanaryMaintenance: %v", err)
		}

		during := listCanaries(t, database, now.Add(time.Hour), rangeDurations[DefaultRange])
		a := findCanary(t, during, "canary-a")
		if a.Status != "silent" || !hasState(a, StateSilent) {
			t.Errorf("in maintenance: Status %q ActiveStates %v, want silent still reported", a.Status, a.ActiveStates)
		}
		if a.MaintenanceUntil == nil || !a.MaintenanceUntil.Equal(until) {
			t.Errorf("MaintenanceUntil = %v, want %v", a.MaintenanceUntil, until)
		}
		if b := findCanary(t, during, "canary-b"); b.Status != "silent" || b.MaintenanceUntil != nil {
			t.Errorf("neighbour: Status %q MaintenanceUntil %v, want silent / nil (maintenance is per canary)", b.Status, b.MaintenanceUntil)
		}

		// The very instant of until the window is over: now < until is the rule.
		for _, at := range []time.Time{until, until.Add(time.Second)} {
			after := findCanary(t, listCanaries(t, database, at, rangeDurations[DefaultRange]), "canary-a")
			if after.Status != "silent" || !hasState(after, StateSilent) {
				t.Errorf("at %v (until passed): Status %q ActiveStates %v, want silent", at, after.Status, after.ActiveStates)
			}
			if after.MaintenanceUntil != nil {
				t.Errorf("at %v (until passed): MaintenanceUntil = %v, want nil", at, after.MaintenanceUntil)
			}
		}
	})
}

// TestMaintenanceKeepsAFailedSelfTestReported: a failed self-test is still
// reported in maintenance, with MaintenanceUntil set, and nil after.
func TestMaintenanceKeepsAFailedSelfTestReported(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{ID: "canary-a", Name: "a", Lane: "l", Ports: "22,80", HeartbeatIntervalS: 60, EnrolledAt: time.Now().UTC().Add(-time.Hour)})
		idx := NewSelfTestIndex()
		now := time.Now().UTC()
		if _, err := MintSelfTestCommand(context.Background(), database, idx, "canary-a", "192.0.2.10",
			[]SelfTestTarget{{Service: "ssh", DestPort: 22}}, now, now.Add(10*time.Minute)); err != nil {
			t.Fatalf("MintSelfTestCommand: %v", err)
		}
		afterDeadline := now.Add(11 * time.Minute)
		if _, err := SweepExpiredSelfTestRuns(context.Background(), database, afterDeadline); err != nil {
			t.Fatalf("SweepExpiredSelfTestRuns: %v", err)
		}
		if err := RecordHeartbeat(context.Background(), database, "canary-a", afterDeadline); err != nil {
			t.Fatalf("RecordHeartbeat: %v", err)
		}
		if c := findCanary(t, listCanaries(t, database, afterDeadline, 24*time.Hour), "canary-a"); !hasState(c, StateTestFailed) {
			t.Fatalf("setup: ActiveStates %v, want self_test_failed", c.ActiveStates)
		}

		until := afterDeadline.Add(time.Hour)
		if err := SetCanaryMaintenance(context.Background(), database, "canary-a", until, afterDeadline, "erebus-admin"); err != nil {
			t.Fatalf("SetCanaryMaintenance: %v", err)
		}
		if c := findCanary(t, listCanaries(t, database, afterDeadline, 24*time.Hour), "canary-a"); !hasState(c, StateTestFailed) || c.MaintenanceUntil == nil || !c.MaintenanceUntil.Equal(until) {
			t.Errorf("in maintenance: ActiveStates %v MaintenanceUntil %v, want self_test_failed still reported and until %v", c.ActiveStates, c.MaintenanceUntil, until)
		}
		later := until.Add(time.Second)
		if err := RecordHeartbeat(context.Background(), database, "canary-a", later); err != nil {
			t.Fatalf("RecordHeartbeat: %v", err)
		}
		if c := findCanary(t, listCanaries(t, database, later, 24*time.Hour), "canary-a"); !hasState(c, StateTestFailed) || c.MaintenanceUntil != nil {
			t.Errorf("after until: ActiveStates %v MaintenanceUntil %v, want self_test_failed and nil", c.ActiveStates, c.MaintenanceUntil)
		}
	})
}

// TestHitDuringMaintenanceIsStillStoredAndListed: maintenance quiets health
// warnings only. A hit on the canary is stored, listed by the alerts
// query, and after until passes the silent warning is back.
func TestHitDuringMaintenanceIsStillStoredAndListed(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		beat := mustParse(t, "2026-01-01T01:00:00Z")
		maintenanceCanary(t, database, "canary-a", beat)
		now := beat.Add(10 * time.Minute)
		until := now.Add(time.Hour)
		if err := SetCanaryMaintenance(context.Background(), database, "canary-a", until, now, "erebus-admin"); err != nil {
			t.Fatalf("SetCanaryMaintenance: %v", err)
		}

		stored, err := InsertAlertIfNew(context.Background(), database, AlertInsert{
			InstanceID: "canary-a", SourceIP: "203.0.113.9", DestPort: 22, Service: "ssh", Raw: "raw", ReceivedAt: now.Add(time.Minute), EventID: "evt-during-maintenance",
		})
		if err != nil || !stored {
			t.Fatalf("InsertAlertIfNew during maintenance = %v, %v, want true, nil", stored, err)
		}
		alerts, err := ListAlerts(context.Background(), database, AlertFilter{InstanceID: "canary-a"})
		if err != nil || len(alerts) != 1 || alerts[0].SourceIP != "203.0.113.9" {
			t.Fatalf("ListAlerts = %+v, %v, want the one hit", alerts, err)
		}

		after := until.Add(time.Minute)
		c := findCanary(t, listCanaries(t, database, after, rangeDurations[DefaultRange]), "canary-a")
		if c.Status != "silent" {
			t.Errorf("after until passed: Status %q, want silent (the warning is back)", c.Status)
		}
		alerts, err = ListAlerts(context.Background(), database, AlertFilter{InstanceID: "canary-a"})
		if err != nil || len(alerts) != 1 {
			t.Errorf("ListAlerts after until = %+v, %v, want the hit still there", alerts, err)
		}
	})
}

// TestClearCanaryMaintenanceEndsItNow: clearing brings the warnings back on
// the next health check and MaintenanceUntil goes nil.
func TestClearCanaryMaintenanceEndsItNow(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		beat := mustParse(t, "2026-01-01T01:00:00Z")
		maintenanceCanary(t, database, "canary-a", beat)
		now := beat.Add(10 * time.Minute)
		if err := SetCanaryMaintenance(context.Background(), database, "canary-a", now.Add(24*time.Hour), now, "erebus-admin"); err != nil {
			t.Fatalf("SetCanaryMaintenance: %v", err)
		}
		if err := ClearCanaryMaintenance(context.Background(), database, "canary-a", now.Add(time.Minute), "erebus-admin"); err != nil {
			t.Fatalf("ClearCanaryMaintenance: %v", err)
		}
		c := findCanary(t, listCanaries(t, database, now.Add(2*time.Minute), rangeDurations[DefaultRange]), "canary-a")
		if c.Status != "silent" || c.MaintenanceUntil != nil {
			t.Errorf("after clear: Status %q MaintenanceUntil %v, want silent / nil", c.Status, c.MaintenanceUntil)
		}
	})
}

// TestMaintenanceUnknownCanary: both writes answer ErrCanaryNotFound and
// leave no audit row.
func TestMaintenanceUnknownCanary(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		now := mustParse(t, "2026-01-01T01:00:00Z")
		err := SetCanaryMaintenance(context.Background(), database, "nope", now.Add(time.Hour), now, "erebus-admin")
		if !errors.Is(err, ErrCanaryNotFound) {
			t.Errorf("SetCanaryMaintenance(unknown) = %v, want ErrCanaryNotFound", err)
		}
		err = ClearCanaryMaintenance(context.Background(), database, "nope", now, "erebus-admin")
		if !errors.Is(err, ErrCanaryNotFound) {
			t.Errorf("ClearCanaryMaintenance(unknown) = %v, want ErrCanaryNotFound", err)
		}
		var n int
		if err := database.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action LIKE 'canary.maintenance.%'`).Scan(&n); err != nil || n != 0 {
			t.Errorf("maintenance audit rows for an unknown canary = %d, %v, want 0", n, err)
		}
	})
}

// TestMaintenanceWritesAudit: set and clear each append their row, target
// the canary id, triggered_by the caller.
func TestMaintenanceWritesAudit(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		beat := mustParse(t, "2026-01-01T01:00:00Z")
		maintenanceCanary(t, database, "canary-a", beat)
		now := beat.Add(time.Minute)
		if err := SetCanaryMaintenance(context.Background(), database, "canary-a", now.Add(time.Hour), now, "erebus-admin"); err != nil {
			t.Fatalf("SetCanaryMaintenance: %v", err)
		}
		if err := ClearCanaryMaintenance(context.Background(), database, "canary-a", now.Add(time.Minute), "erebus-admin"); err != nil {
			t.Fatalf("ClearCanaryMaintenance: %v", err)
		}
		for _, action := range []string{"canary.maintenance.set", "canary.maintenance.cleared"} {
			var target, by string
			row := database.QueryRow(`SELECT target, triggered_by FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1`, action)
			if err := row.Scan(&target, &by); err != nil {
				t.Fatalf("no %s audit row: %v", action, err)
			}
			if target != "canary-a" || by != "erebus-admin" {
				t.Errorf("%s row: target %q triggered_by %q, want canary-a / erebus-admin", action, target, by)
			}
		}
	})
}

// TestMaintenanceIsNotAnAgentSetting: maintenance is birdcage-side state.
// It never shows up as an agent setting, so it can never change the
// settings hash the agent confirms or be pushed to it.
func TestMaintenanceIsNotAnAgentSetting(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		beat := mustParse(t, "2026-01-01T01:00:00Z")
		maintenanceCanary(t, database, "canary-a", beat)
		hashBefore, _, err := GetCanarySettingsHash(context.Background(), database, "canary-a")
		if err != nil {
			t.Fatalf("GetCanarySettingsHash: %v", err)
		}
		if err := SetCanaryMaintenance(context.Background(), database, "canary-a", beat.Add(time.Hour), beat, "erebus-admin"); err != nil {
			t.Fatalf("SetCanaryMaintenance: %v", err)
		}
		settings, err := ListCanarySettings(context.Background(), database, "canary-a")
		if err != nil || len(settings) != 0 {
			t.Errorf("ListCanarySettings after maintenance = %+v, %v, want none", settings, err)
		}
		if hashAfter, _, err := GetCanarySettingsHash(context.Background(), database, "canary-a"); err != nil || hashAfter != hashBefore {
			t.Errorf("settings hash changed %q -> %q, %v", hashBefore, hashAfter, err)
		}
	})
}
