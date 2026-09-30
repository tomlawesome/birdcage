package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/store"
)

// TestHandleScansEmpty proves GET /api/scans answers an empty list, not
// an error, before any snapshot has ever arrived.
func TestHandleScansEmpty(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, time.Now, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/scans", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp scansResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Scans) != 0 {
		t.Fatalf("got %d scans, want 0: %+v", len(resp.Scans), resp.Scans)
	}
}

// TestHandleScansFields proves a recorded receipt round-trips through
// GET /api/scans with its finding count and masked-path list intact,
// newest first -- the read-back the "Scanner agent, slice 1" plan (#108)
// names as this slice's acceptance: "GET /api/scans shows it with the
// finding counted."
func TestHandleScansFields(t *testing.T) {
	database := openTempDB(t)
	insertCanary(t, database, store.Canary{
		ID: "scanner-a", Name: "scanner-a", Lane: "lan",
		EnrolledAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	dbBuiltAt := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	if err := store.RecordScanSnapshot(context.Background(), database, store.ScanSnapshot{
		CanaryID: "scanner-a",
		TakenAt:  time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), ReceivedAt: time.Date(2026, 1, 2, 0, 0, 5, 0, time.UTC),
		EngineName: "grype", EngineVersion: "v0.119.0", DBBuiltAt: &dbBuiltAt,
		Status: store.ScanStatusOK, FindingCount: 1, MaskedPaths: []string{"/etc/shadow", "/root"},
	}); err != nil {
		t.Fatalf("RecordScanSnapshot: %v", err)
	}

	h := newHandler(database, time.Now, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/scans", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp scansResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Scans) != 1 {
		t.Fatalf("got %d scans, want 1: %+v", len(resp.Scans), resp.Scans)
	}
	s := resp.Scans[0]
	if s.CanaryID != "scanner-a" || s.Status != store.ScanStatusOK || s.FindingCount != 1 {
		t.Errorf("scan = %+v, want canary/status/count scanner-a/ok/1", s)
	}
	if s.EngineName != "grype" || s.EngineVersion != "v0.119.0" {
		t.Errorf("EngineName/EngineVersion = %q/%q, want grype/v0.119.0", s.EngineName, s.EngineVersion)
	}
	if len(s.MaskedPaths) != 2 || s.MaskedPaths[0] != "/etc/shadow" || s.MaskedPaths[1] != "/root" {
		t.Errorf("MaskedPaths = %v, want [/etc/shadow /root]", s.MaskedPaths)
	}
}

// TestHandleScansNewestFirst mirrors TestListScanSnapshotsNewestFirst
// (internal/store), proving the API handler preserves that ordering
// rather than re-sorting or losing it.
func TestHandleScansNewestFirst(t *testing.T) {
	database := openTempDB(t)
	insertCanary(t, database, store.Canary{
		ID: "scanner-a", Name: "scanner-a", Lane: "lan",
		EnrolledAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	for i := 0; i < 3; i++ {
		at := time.Date(2026, 1, 1, i, 0, 0, 0, time.UTC)
		if err := store.RecordScanSnapshot(context.Background(), database, store.ScanSnapshot{
			CanaryID: "scanner-a", TakenAt: at, ReceivedAt: at, Status: store.ScanStatusFailed, Reason: "x",
		}); err != nil {
			t.Fatalf("RecordScanSnapshot %d: %v", i, err)
		}
	}

	h := newHandler(database, time.Now, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/scans", nil))
	var resp scansResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Scans) != 3 {
		t.Fatalf("got %d scans, want 3", len(resp.Scans))
	}
	if resp.Scans[0].ID <= resp.Scans[1].ID || resp.Scans[1].ID <= resp.Scans[2].ID {
		t.Errorf("ids = %d, %d, %d, want strictly descending", resp.Scans[0].ID, resp.Scans[1].ID, resp.Scans[2].ID)
	}
}

func TestHandleScansRejectsPost(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, time.Now, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/scans", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405; body=%s", rec.Code, rec.Body.String())
	}
}
