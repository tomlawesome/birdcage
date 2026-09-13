package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// openTempDB mirrors internal/db's openTempDB helper (migrate_test.go),
// migrated so the alerts table exists -- the same extension
// internal/store's own openTempDB makes, for the same reason.
func openTempDB(t *testing.T) *db.DB {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "birdcage-test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := db.Migrate(context.Background(), database); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return database
}

func insertAlert(t *testing.T, database *db.DB, instanceID, sourceIP string, destPort int, service, receivedAt string) {
	t.Helper()
	_, err := database.Exec(
		`INSERT INTO alerts (instance_id, source_ip, dest_port, service, raw, received_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		instanceID, sourceIP, destPort, service, "raw", receivedAt,
	)
	if err != nil {
		t.Fatalf("insert alert: %v", err)
	}
}

func fixedNow(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestHandleAlertsFilters(t *testing.T) {
	database := openTempDB(t)
	insertAlert(t, database, "node-1", "203.0.113.9", 22, "ssh", "2026-01-01T00:00:00Z")
	insertAlert(t, database, "node-2", "198.51.100.8", 80, "http", "2026-01-02T00:00:00Z")

	h := newHandler(database, time.Now)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/alerts?instance=node-2", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp alertsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Alerts) != 1 || resp.Alerts[0].InstanceID != "node-2" {
		t.Errorf("alerts = %+v, want exactly the node-2 alert", resp.Alerts)
	}
	if resp.NextBefore != nil {
		t.Errorf("next_before = %v, want nil (page shorter than limit)", *resp.NextBefore)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestHandleAlertsNextBeforeSetOnFullPage(t *testing.T) {
	database := openTempDB(t)
	for i := 0; i < 3; i++ {
		insertAlert(t, database, "node-1", "203.0.113.9", 22, "ssh", "2026-01-01T00:00:00Z")
	}

	h := newHandler(database, time.Now)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/alerts?limit=2", nil)
	h.ServeHTTP(rec, req)

	var resp alertsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Alerts) != 2 {
		t.Fatalf("got %d alerts, want 2", len(resp.Alerts))
	}
	if resp.NextBefore == nil {
		t.Fatal("next_before = nil, want the last row's id (page filled the limit)")
	}
	if *resp.NextBefore != resp.Alerts[1].ID {
		t.Errorf("next_before = %d, want %d (last row on this page)", *resp.NextBefore, resp.Alerts[1].ID)
	}
}

func TestHandleAlertsBadQueryParams(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, time.Now)

	cases := []string{
		"/api/alerts?since=not-a-time",
		"/api/alerts?until=not-a-time",
		"/api/alerts?limit=abc",
		"/api/alerts?before=abc",
	}
	for _, target := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, target, nil)
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400; body=%s", target, rec.Code, rec.Body.String())
			continue
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Errorf("%s: decode body: %v", target, err)
			continue
		}
		if body["error"] == "" {
			t.Errorf("%s: body = %v, want a non-empty \"error\"", target, body)
		}
	}
}

func TestHandleInstances(t *testing.T) {
	database := openTempDB(t)
	insertAlert(t, database, "node-1", "203.0.113.9", 22, "ssh", "2026-01-01T00:00:00Z")
	insertAlert(t, database, "node-1", "203.0.113.9", 22, "ssh", "2026-01-02T00:00:00Z")

	h := newHandler(database, time.Now)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/instances", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp instancesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Instances) != 1 || resp.Instances[0].InstanceID != "node-1" || resp.Instances[0].Count != 2 {
		t.Errorf("instances = %+v, want one node-1 entry with count 2", resp.Instances)
	}
}

func TestHandleStatsUsesInjectedNow(t *testing.T) {
	database := openTempDB(t)
	insertAlert(t, database, "node-1", "203.0.113.9", 22, "ssh", "2026-01-01T00:00:00Z")

	pinned := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	h := newHandler(database, fixedNow(pinned))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var stats store.Stats
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	want := store.Stats{Total: 1, Last24h: 1, DistinctSources: 1, Instances: 1}
	if stats != want {
		t.Errorf("stats = %+v, want %+v", stats, want)
	}
}

func TestReadOnlyRoutesRejectMutatingMethods(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, time.Now)

	for _, path := range []string{"/api/alerts", "/api/instances", "/api/stats"} {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(method, path, nil)
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: status = %d, want 405", method, path, rec.Code)
			}
		}
	}
}

func TestUnknownAPIPathReturnsJSON404(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, time.Now)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/nope", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v; body=%s", err, rec.Body.String())
	}
	if body["error"] != "not found" {
		t.Errorf(`body = %v, want {"error":"not found"}`, body)
	}
}

func TestNewHandlerServesThroughPublicConstructor(t *testing.T) {
	database := openTempDB(t)
	h := NewHandler(database)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}
