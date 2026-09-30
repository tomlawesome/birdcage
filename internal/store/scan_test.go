package store

import (
	"context"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

func recordScanSnapshot(t *testing.T, database *db.DB, s ScanSnapshot) {
	t.Helper()
	if err := RecordScanSnapshot(context.Background(), database, s); err != nil {
		t.Fatalf("RecordScanSnapshot(%+v): %v", s, err)
	}
}

func listScanSnapshots(t *testing.T, database *db.DB) []ScanSnapshot {
	t.Helper()
	snapshots, err := ListScanSnapshots(context.Background(), database)
	if err != nil {
		t.Fatalf("ListScanSnapshots: %v", err)
	}
	return snapshots
}

// TestRecordScanSnapshotAndListFieldsOK proves the full round trip for a
// successful scan: every column, including the nested engine metadata
// and the masked-path list, comes back exactly as written.
func TestRecordScanSnapshotAndListFieldsOK(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{
			ID: "scanner-a", Name: "scanner-a", Lane: "lan",
			EnrolledAt: mustParse(t, "2026-01-01T00:00:00Z"),
		})
		takenAt := mustParse(t, "2026-01-02T00:00:00Z")
		receivedAt := mustParse(t, "2026-01-02T00:00:05Z")
		dbBuiltAt := mustParse(t, "2026-01-01T12:00:00Z")

		recordScanSnapshot(t, database, ScanSnapshot{
			CanaryID: "scanner-a", TakenAt: takenAt, ReceivedAt: receivedAt,
			EngineName: "grype", EngineVersion: "v0.119.0", DBBuiltAt: &dbBuiltAt,
			Status: ScanStatusOK, FindingCount: 1,
			MaskedPaths: []string{"/etc/shadow", "/root"},
		})

		snapshots := listScanSnapshots(t, database)
		if len(snapshots) != 1 {
			t.Fatalf("got %d snapshots, want 1: %+v", len(snapshots), snapshots)
		}
		s := snapshots[0]
		if s.CanaryID != "scanner-a" || s.EngineName != "grype" || s.EngineVersion != "v0.119.0" {
			t.Errorf("snapshot = %+v, want canary/engine scanner-a/grype/v0.119.0", s)
		}
		if !s.TakenAt.Equal(takenAt) || !s.ReceivedAt.Equal(receivedAt) {
			t.Errorf("TakenAt/ReceivedAt = %v/%v, want %v/%v", s.TakenAt, s.ReceivedAt, takenAt, receivedAt)
		}
		if s.DBBuiltAt == nil || !s.DBBuiltAt.Equal(dbBuiltAt) {
			t.Errorf("DBBuiltAt = %v, want %v", s.DBBuiltAt, dbBuiltAt)
		}
		if s.Status != ScanStatusOK || s.Reason != "" || s.FindingCount != 1 {
			t.Errorf("status/reason/count = %q/%q/%d, want ok/\"\"/1", s.Status, s.Reason, s.FindingCount)
		}
		if len(s.MaskedPaths) != 2 || s.MaskedPaths[0] != "/etc/shadow" || s.MaskedPaths[1] != "/root" {
			t.Errorf("MaskedPaths = %v, want [/etc/shadow /root]", s.MaskedPaths)
		}
	})
}

// TestRecordScanSnapshotFailedLeavesEngineAndDBBuiltAtEmpty proves a
// failed scan's Engine fields round-trip as empty/nil exactly as
// internal/scan.Result's own doc comment describes: a run that never
// loaded a database has nothing honest to report there.
func TestRecordScanSnapshotFailedLeavesEngineAndDBBuiltAtEmpty(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{
			ID: "scanner-a", Name: "scanner-a", Lane: "lan",
			EnrolledAt: mustParse(t, "2026-01-01T00:00:00Z"),
		})
		recordScanSnapshot(t, database, ScanSnapshot{
			CanaryID: "scanner-a",
			TakenAt:  mustParse(t, "2026-01-02T00:00:00Z"), ReceivedAt: mustParse(t, "2026-01-02T00:00:05Z"),
			Status: ScanStatusFailed, Reason: "grype did not run: exec: \"grype\": executable file not found in $PATH",
		})

		s := listScanSnapshots(t, database)[0]
		if s.EngineName != "" || s.EngineVersion != "" {
			t.Errorf("EngineName/EngineVersion = %q/%q, want both empty", s.EngineName, s.EngineVersion)
		}
		if s.DBBuiltAt != nil {
			t.Errorf("DBBuiltAt = %v, want nil", s.DBBuiltAt)
		}
		if s.FindingCount != 0 {
			t.Errorf("FindingCount = %d, want 0", s.FindingCount)
		}
		if s.Reason == "" {
			t.Error("Reason is empty for a failed snapshot, want the stored reason")
		}
	})
}

// TestScanSnapshotMaskedPathsEmptyRoundTripsAsEmptySlice proves an empty
// mask list comes back as a non-nil, zero-length slice -- so the JSON
// API encodes it as [], never null (masked_paths is present on every
// snapshot, per the owner's 2026-09-22 decision, even one that masked
// nothing).
func TestScanSnapshotMaskedPathsEmptyRoundTripsAsEmptySlice(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{
			ID: "scanner-a", Name: "scanner-a", Lane: "lan",
			EnrolledAt: mustParse(t, "2026-01-01T00:00:00Z"),
		})
		recordScanSnapshot(t, database, ScanSnapshot{
			CanaryID: "scanner-a",
			TakenAt:  mustParse(t, "2026-01-02T00:00:00Z"), ReceivedAt: mustParse(t, "2026-01-02T00:00:05Z"),
			Status: ScanStatusFailed, Reason: "db stale",
		})

		s := listScanSnapshots(t, database)[0]
		if s.MaskedPaths == nil {
			t.Fatal("MaskedPaths is nil, want a non-nil empty slice")
		}
		if len(s.MaskedPaths) != 0 {
			t.Errorf("MaskedPaths = %v, want empty", s.MaskedPaths)
		}
	})
}

func TestRecordScanSnapshotRequiresCanaryID(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		err := RecordScanSnapshot(context.Background(), database, ScanSnapshot{
			TakenAt: mustParse(t, "2026-01-01T00:00:00Z"), ReceivedAt: mustParse(t, "2026-01-01T00:00:00Z"),
			Status: ScanStatusOK,
		})
		if err == nil {
			t.Fatal("RecordScanSnapshot with empty CanaryID succeeded, want an error")
		}
	})
}

func TestRecordScanSnapshotRejectsUnknownStatus(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		err := RecordScanSnapshot(context.Background(), database, ScanSnapshot{
			CanaryID: "scanner-a",
			TakenAt:  mustParse(t, "2026-01-01T00:00:00Z"), ReceivedAt: mustParse(t, "2026-01-01T00:00:00Z"),
			Status: "clean",
		})
		if err == nil {
			t.Fatal("RecordScanSnapshot with status \"clean\" succeeded, want an error")
		}
	})
}

func TestRecordScanSnapshotFailedRequiresReason(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		err := RecordScanSnapshot(context.Background(), database, ScanSnapshot{
			CanaryID: "scanner-a",
			TakenAt:  mustParse(t, "2026-01-01T00:00:00Z"), ReceivedAt: mustParse(t, "2026-01-01T00:00:00Z"),
			Status: ScanStatusFailed,
		})
		if err == nil {
			t.Fatal("RecordScanSnapshot(failed, no reason) succeeded, want an error")
		}
	})
}

func TestRecordScanSnapshotOkReasonMustBeEmpty(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		err := RecordScanSnapshot(context.Background(), database, ScanSnapshot{
			CanaryID: "scanner-a",
			TakenAt:  mustParse(t, "2026-01-01T00:00:00Z"), ReceivedAt: mustParse(t, "2026-01-01T00:00:00Z"),
			Status: ScanStatusOK, Reason: "should not be here",
		})
		if err == nil {
			t.Fatal("RecordScanSnapshot(ok, non-empty reason) succeeded, want an error")
		}
	})
}

func TestRecordScanSnapshotFailedFindingCountMustBeZero(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		err := RecordScanSnapshot(context.Background(), database, ScanSnapshot{
			CanaryID: "scanner-a",
			TakenAt:  mustParse(t, "2026-01-01T00:00:00Z"), ReceivedAt: mustParse(t, "2026-01-01T00:00:00Z"),
			Status: ScanStatusFailed, Reason: "db stale", FindingCount: 3,
		})
		if err == nil {
			t.Fatal("RecordScanSnapshot(failed, FindingCount>0) succeeded, want an error")
		}
	})
}

func TestRecordScanSnapshotRejectsNonAbsoluteMaskedPath(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		err := RecordScanSnapshot(context.Background(), database, ScanSnapshot{
			CanaryID: "scanner-a",
			TakenAt:  mustParse(t, "2026-01-01T00:00:00Z"), ReceivedAt: mustParse(t, "2026-01-01T00:00:00Z"),
			Status: ScanStatusOK, MaskedPaths: []string{"etc/shadow"},
		})
		if err == nil {
			t.Fatal("RecordScanSnapshot with a relative masked path succeeded, want an error")
		}
	})
}

// TestListScanSnapshotsNewestFirst proves the ordering ListScanSnapshots
// promises: insertion order reversed, mirroring ListAlerts' own
// "ORDER BY id DESC" convention.
func TestListScanSnapshotsNewestFirst(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{
			ID: "scanner-a", Name: "scanner-a", Lane: "lan",
			EnrolledAt: mustParse(t, "2026-01-01T00:00:00Z"),
		})
		for i := 0; i < 3; i++ {
			recordScanSnapshot(t, database, ScanSnapshot{
				CanaryID:   "scanner-a",
				TakenAt:    mustParse(t, "2026-01-01T00:00:00Z").Add(time.Duration(i) * time.Hour),
				ReceivedAt: mustParse(t, "2026-01-01T00:00:00Z").Add(time.Duration(i) * time.Hour),
				Status:     ScanStatusOK,
			})
		}

		snapshots := listScanSnapshots(t, database)
		if len(snapshots) != 3 {
			t.Fatalf("got %d snapshots, want 3", len(snapshots))
		}
		if snapshots[0].ID <= snapshots[1].ID || snapshots[1].ID <= snapshots[2].ID {
			t.Errorf("ids = %d, %d, %d, want strictly descending", snapshots[0].ID, snapshots[1].ID, snapshots[2].ID)
		}
	})
}
