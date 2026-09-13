package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

func insertCanary(t *testing.T, database *db.DB, c store.Canary) {
	t.Helper()
	if err := store.InsertCanary(context.Background(), database, c); err != nil {
		t.Fatalf("InsertCanary(%+v): %v", c, err)
	}
}

func TestHandleCanariesFields(t *testing.T) {
	database := openTempDB(t)
	enrolledAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	insertCanary(t, database, store.Canary{
		ID: "canary-lan", Name: "canary-lan", Lane: "lan",
		Ports: "22,80,445", HeartbeatIntervalS: 60, EnrolledAt: enrolledAt,
	})
	beatAt := enrolledAt.Add(time.Hour)
	if err := store.RecordHeartbeat(context.Background(), database, "canary-lan", beatAt); err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}
	insertAlert(t, database, "canary-lan", "203.0.113.9", 22, "ssh", beatAt.Format(time.RFC3339))

	// now just past the beat: still "ok".
	h := newHandler(database, fixedNow(beatAt.Add(30*time.Second)))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/canaries", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp canariesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Canaries) != 1 {
		t.Fatalf("got %d canaries, want 1: %+v", len(resp.Canaries), resp.Canaries)
	}
	c := resp.Canaries[0]
	if c.ID != "canary-lan" || c.Status != "ok" || c.Ports != "ssh 22 · http 80 · smb 445" {
		t.Errorf("canary = %+v, want id/status/ports canary-lan/ok/\"ssh 22 · http 80 · smb 445\"", c)
	}
	if c.Hits != 1 {
		t.Errorf("Hits = %d, want 1", c.Hits)
	}
	if c.SilentForS != nil || c.BeatsMissed != nil {
		t.Errorf("SilentForS/BeatsMissed = %v/%v, want both absent while ok", c.SilentForS, c.BeatsMissed)
	}

	// silent_for_s / beats_missed must be entirely absent from the JSON
	// (not just null), matching frontend/src/lib/types.ts's optional
	// fields.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode raw response: %v", err)
	}
	var canariesRaw []map[string]json.RawMessage
	if err := json.Unmarshal(raw["canaries"], &canariesRaw); err != nil {
		t.Fatalf("decode raw canaries: %v", err)
	}
	if _, ok := canariesRaw[0]["silent_for_s"]; ok {
		t.Error(`"silent_for_s" key present in JSON while status is "ok", want it omitted entirely`)
	}
}

func TestHandleCanariesRejectsUnknownRange(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, time.Now)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/canaries?range=7d", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleHeartbeatRecordsAndUpdatesCanary(t *testing.T) {
	database := openTempDB(t)
	enrolledAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	insertCanary(t, database, store.Canary{
		ID: "canary-lan", Name: "canary-lan", Lane: "lan",
		HeartbeatIntervalS: 60, EnrolledAt: enrolledAt,
	})

	beatAt := enrolledAt.Add(5 * time.Minute)
	h := newHandler(database, fixedNow(beatAt))
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"canary": "canary-lan"})
	req := httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(body))
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	canaries, err := store.ListCanaries(context.Background(), database, beatAt, 14*24*time.Hour)
	if err != nil {
		t.Fatalf("ListCanaries: %v", err)
	}
	if len(canaries) != 1 || canaries[0].LastHeartbeatAt == nil || !canaries[0].LastHeartbeatAt.Equal(beatAt) {
		t.Errorf("canaries = %+v, want canary-lan with LastHeartbeatAt %v", canaries, beatAt)
	}
}

func TestHandleHeartbeatUnknownCanaryReturns404(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, time.Now)

	rec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"canary": "no-such-canary"})
	req := httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(body))
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleHeartbeatBadRequests(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, time.Now)

	cases := []string{`not json`, `{}`, `{"canary": ""}`, `{"canary": "  "}`}
	for _, body := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader([]byte(body)))
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body=%q: status = %d, want 400; resp=%s", body, rec.Code, rec.Body.String())
		}
	}
}

func TestHandleHeartbeatRejectsGet(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, time.Now)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/heartbeat", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405; body=%s", rec.Code, rec.Body.String())
	}
}
