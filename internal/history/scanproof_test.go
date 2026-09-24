package history

import (
	"context"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// TestScannerProofStatesAreRecorded (issue #116, ADR-0012 decision 11):
// a scanner's self_test_failed and db_stale are #56 state periods like
// every other #45 state, opened while active and closed when the tile
// clears -- the tile may clear, the record does not.
func TestScannerProofStatesAreRecorded(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		t0 := mustParse(t, "2026-01-01T00:00:00Z")
		if err := store.InsertCanary(ctx, database, store.Canary{
			ID: "scan-1", Name: "scan", Lane: "lan", Kind: agentkind.Scanner, HeartbeatIntervalS: 60,
			EnrolledAt: t0.Add(-time.Hour), Pending: true,
		}); err != nil {
			t.Fatalf("InsertCanary: %v", err)
		}
		// A proof run that expires unanswered, and a refresh failing from t0.
		if _, err := store.MintScanCommand(ctx, database, "scan-1", store.TriggerProof, t0, t0.Add(30*time.Minute)); err != nil {
			t.Fatalf("MintScanCommand: %v", err)
		}
		if _, err := store.SweepExpiredSelfTestRuns(ctx, database, t0.Add(31*time.Minute)); err != nil {
			t.Fatalf("sweep: %v", err)
		}
		if err := store.SetCanaryDBRefresh(ctx, database, "scan-1", true, "mirror unreachable", t0); err != nil {
			t.Fatalf("SetCanaryDBRefresh: %v", err)
		}

		r := New(database)
		at := t0.Add(25 * time.Hour)
		beat(t, database, "scan-1", at)
		tick(t, r, at)
		open := map[string]bool{}
		for _, p := range periods(t, database, "scan-1") {
			if p.EndedAt == nil {
				open[p.State] = true
			}
		}
		if !open["self_test_failed"] || !open["db_stale"] {
			t.Fatalf("open periods = %v, want self_test_failed and db_stale", open)
		}

		// A later ok snapshot and a clean refresh clear both tiles; the
		// spans close and stay on record.
		built, refreshed := at.Add(-time.Hour), at
		if err := store.RecordScanSnapshot(ctx, database, store.ScanSnapshot{
			CanaryID: "scan-1", TakenAt: at, ReceivedAt: at.Add(time.Minute), EngineName: "grype", EngineVersion: "v0.119.0",
			DBBuiltAt: &built, DBRefreshedAt: &refreshed, Status: store.ScanStatusOK,
		}); err != nil {
			t.Fatalf("RecordScanSnapshot: %v", err)
		}
		if err := store.SetCanaryDBRefresh(ctx, database, "scan-1", false, "", at); err != nil {
			t.Fatalf("SetCanaryDBRefresh: %v", err)
		}
		later := at.Add(2 * time.Minute)
		beat(t, database, "scan-1", later)
		tick(t, r, later)
		closed := map[string]bool{}
		for _, p := range periods(t, database, "scan-1") {
			if p.EndedAt != nil && (p.State == "self_test_failed" || p.State == "db_stale") {
				closed[p.State] = true
			}
			if p.EndedAt == nil && (p.State == "self_test_failed" || p.State == "db_stale") {
				t.Errorf("%s still open after it cleared", p.State)
			}
		}
		if !closed["self_test_failed"] || !closed["db_stale"] {
			t.Errorf("closed periods = %v, want both kept on record", closed)
		}
	})
}
