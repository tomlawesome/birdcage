package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// TestSendScanStoresOKSnapshot proves the snapshot this package sends
// decodes into internal/ingest's real handler correctly, field for
// field, by reading it back from the database exactly like
// internal/ingest/scans_test.go's own equivalent test.
func TestSendScanStoresOKSnapshot(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		c, _ := newIngestServer(t, database, agentkind.Scanner)
		token := mintToken(t, database, "canary-a")

		dbBuiltAt := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
		err := c.SendScan(ctx(), token, Snapshot{
			TakenAt:      time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			AgentVersion: "1.0.0",
			Engine:       Engine{Name: "grype", Version: "v0.119.0", DBBuiltAt: dbBuiltAt},
			Status:       "ok",
			Findings: []Finding{
				{Target: "dir:/host", Package: "openssl", Version: "1.0.1f-1ubuntu2", Type: "deb",
					Vulnerability: "CVE-2014-0160", Severity: "critical", FixVersion: "1.0.1f-1ubuntu2.1"},
			},
			MaskedPaths: []string{"/etc/shadow", "/root"},
		})
		if err != nil {
			t.Fatalf("SendScan: %v", err)
		}

		snapshots, err := store.ListScanSnapshots(ctx(), database)
		if err != nil {
			t.Fatalf("ListScanSnapshots: %v", err)
		}
		if len(snapshots) != 1 {
			t.Fatalf("got %d scan snapshots, want 1: %+v", len(snapshots), snapshots)
		}
		s := snapshots[0]
		if s.CanaryID != "canary-a" || s.Status != store.ScanStatusOK || s.FindingCount != 1 {
			t.Errorf("snapshot = %+v, want canary/status/count canary-a/ok/1", s)
		}
		if s.EngineName != "grype" || s.EngineVersion != "v0.119.0" {
			t.Errorf("EngineName/EngineVersion = %q/%q, want grype/v0.119.0", s.EngineName, s.EngineVersion)
		}
		if s.DBBuiltAt == nil || !s.DBBuiltAt.Equal(dbBuiltAt) {
			t.Errorf("DBBuiltAt = %v, want %v", s.DBBuiltAt, dbBuiltAt)
		}
		if len(s.MaskedPaths) != 2 || s.MaskedPaths[0] != "/etc/shadow" || s.MaskedPaths[1] != "/root" {
			t.Errorf("MaskedPaths = %v, want [/etc/shadow /root]", s.MaskedPaths)
		}
	})
}

// TestSendScanStoresFailedSnapshotWithNoEngineData proves a Snapshot
// whose Engine is entirely zero-valued (internal/scan.Result's own case
// for a run that never loaded a database) is sent, and stored, with no
// engine metadata at all rather than a fabricated zero time.
func TestSendScanStoresFailedSnapshotWithNoEngineData(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		c, _ := newIngestServer(t, database, agentkind.Scanner)
		token := mintToken(t, database, "canary-a")

		err := c.SendScan(ctx(), token, Snapshot{
			TakenAt:     time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			Status:      "failed",
			Reason:      "grype did not run: exec: \"grype\": executable file not found in $PATH",
			MaskedPaths: []string{"/etc/ssh"},
		})
		if err != nil {
			t.Fatalf("SendScan: %v", err)
		}

		snapshots, err := store.ListScanSnapshots(ctx(), database)
		if err != nil {
			t.Fatalf("ListScanSnapshots: %v", err)
		}
		s := snapshots[0]
		if s.Status != store.ScanStatusFailed || s.FindingCount != 0 {
			t.Errorf("Status/FindingCount = %q/%d, want failed/0", s.Status, s.FindingCount)
		}
		if s.EngineName != "" || s.EngineVersion != "" || s.DBBuiltAt != nil {
			t.Errorf("EngineName/EngineVersion/DBBuiltAt = %q/%q/%v, want all empty/nil", s.EngineName, s.EngineVersion, s.DBBuiltAt)
		}
		if len(s.MaskedPaths) != 1 || s.MaskedPaths[0] != "/etc/ssh" {
			t.Errorf("MaskedPaths = %v, want [/etc/ssh]", s.MaskedPaths)
		}
	})
}

// TestSendScanEmptyMaskedPathsSentAsEmptyArray proves a nil
// Snapshot.MaskedPaths still round-trips as an accepted, empty list --
// the wire always carries the field (owner decision, 2026-09-22: present
// on every snapshot), never omits it because the caller left it nil.
func TestSendScanEmptyMaskedPathsSentAsEmptyArray(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		c, _ := newIngestServer(t, database, agentkind.Scanner)
		token := mintToken(t, database, "canary-a")

		err := c.SendScan(ctx(), token, Snapshot{
			TakenAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			Status:  "failed",
			Reason:  "x",
		})
		if err != nil {
			t.Fatalf("SendScan: %v", err)
		}

		snapshots, err := store.ListScanSnapshots(ctx(), database)
		if err != nil {
			t.Fatalf("ListScanSnapshots: %v", err)
		}
		if snapshots[0].MaskedPaths == nil || len(snapshots[0].MaskedPaths) != 0 {
			t.Errorf("MaskedPaths = %v, want a non-nil empty slice", snapshots[0].MaskedPaths)
		}
	})
}

// TestSendScanUnauthorized proves a dead token surfaces as
// ErrUnauthorized, mirroring TestSendHeartbeatUnauthorized.
func TestSendScanUnauthorized(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		c, _ := newIngestServer(t, database, agentkind.Scanner)

		err := c.SendScan(ctx(), "not-a-real-token", Snapshot{
			TakenAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			Status:  "failed", Reason: "x",
		})
		if !IsUnauthorized(err) {
			t.Fatalf("err = %v, want ErrUnauthorized", err)
		}
	})
}

// TestSendScanRetryableOn429 mirrors TestSendHeartbeatRetryableOn429.
func TestSendScanRetryableOn429(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate limit exceeded"}`))
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	err := c.SendScan(ctx(), "tok", Snapshot{TakenAt: time.Now(), Status: "failed", Reason: "x"})
	if !IsRetryable(err) {
		t.Fatalf("err = %v, want a *RetryableError", err)
	}
}

// TestSendScanRejectedBodyIsRetryable proves a body birdcage's own
// handler rejects (here: an ok status with no engine metadata) is
// reported to this package's caller as retryable rather than as
// ErrUnauthorized or a silent success -- SendScan does no client-side
// validation of its own, so the server's 400 is what the caller sees.
func TestSendScanRejectedBodyIsRetryable(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		c, _ := newIngestServer(t, database, agentkind.Scanner)
		token := mintToken(t, database, "canary-a")

		err := c.SendScan(ctx(), token, Snapshot{
			TakenAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			Status:  "ok", // no Engine set: birdcage requires it for status ok
		})
		if !IsRetryable(err) {
			t.Fatalf("err = %v, want a *RetryableError (birdcage's own 400)", err)
		}
	})
}

// TestSendScanWireCarriesRunIDAndDBRefresh proves the wire body
// SendScan posts carries ADR-0012's new fields -- run_id at the top
// level, db_refreshed_at and db_refresh_error under engine -- against a
// plain test server rather than internal/ingest's real handler: that
// handler's own MR (server side of #116) lands separately, so this
// proves the client's own encoding, not the round trip through it.
func TestSendScanWireCarriesRunIDAndDBRefresh(t *testing.T) {
	var gotBody map[string]any
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	refreshedAt := time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)
	err := c.SendScan(ctx(), "tok", Snapshot{
		TakenAt: time.Date(2026, 9, 24, 8, 5, 0, 0, time.UTC),
		Status:  "ok",
		Engine: Engine{
			Name: "grype", Version: "v0.119.0",
			DBRefreshedAt:  refreshedAt,
			DBRefreshError: "mirror unreachable",
		},
		RunID: "run-123",
	})
	if err != nil {
		t.Fatalf("SendScan: %v", err)
	}

	if gotBody["run_id"] != "run-123" {
		t.Errorf("run_id = %v, want run-123", gotBody["run_id"])
	}
	engine, _ := gotBody["engine"].(map[string]any)
	if engine == nil {
		t.Fatal("engine missing from body")
	}
	if engine["db_refreshed_at"] != "2026-09-24T08:00:00Z" {
		t.Errorf("engine.db_refreshed_at = %v, want 2026-09-24T08:00:00Z", engine["db_refreshed_at"])
	}
	if engine["db_refresh_error"] != "mirror unreachable" {
		t.Errorf("engine.db_refresh_error = %v, want %q", engine["db_refresh_error"], "mirror unreachable")
	}
}

// TestSendScanWireOmitsRunIDAndDBRefreshWhenUnset proves a timer scan's
// ordinary body -- no run_id, database refresh healthy -- carries
// neither field, exactly as today.
func TestSendScanWireOmitsRunIDAndDBRefreshWhenUnset(t *testing.T) {
	var gotBody map[string]any
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	err := c.SendScan(ctx(), "tok", Snapshot{
		TakenAt: time.Now(),
		Status:  "ok",
		Engine:  Engine{Name: "grype", Version: "v0.119.0"},
	})
	if err != nil {
		t.Fatalf("SendScan: %v", err)
	}

	if _, present := gotBody["run_id"]; present {
		t.Errorf("run_id present in body, want omitted: %v", gotBody["run_id"])
	}
	engine, _ := gotBody["engine"].(map[string]any)
	if _, present := engine["db_refreshed_at"]; present {
		t.Errorf("engine.db_refreshed_at present, want omitted: %v", engine["db_refreshed_at"])
	}
	if _, present := engine["db_refresh_error"]; present {
		t.Errorf("engine.db_refresh_error present, want omitted: %v", engine["db_refresh_error"])
	}
}
