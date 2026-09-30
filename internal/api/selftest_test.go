package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/selftest"
	"github.com/tomlawesome/birdcage/internal/store"
)

// TestHandleCanariesIncludesPerServiceSelfTestGrade is #46 slice 2 item
// 4: GET /api/canaries' self_test array names each probed service's
// grade and whether it passed, alongside the existing run-level
// LastSelfTestAt/LastSelfTestPassed summary store.Canary already
// carries.
func TestHandleCanariesIncludesPerServiceSelfTestGrade(t *testing.T) {
	database := openTempDB(t)
	enrolledAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	insertCanary(t, database, store.Canary{
		ID: "canary-a", Name: "canary-a", Lane: "lan",
		Ports: "22", HeartbeatIntervalS: 60, EnrolledAt: enrolledAt,
	})
	now := enrolledAt.Add(time.Hour)
	if err := store.RecordHeartbeat(context.Background(), database, "canary-a", now); err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}

	idx := store.NewSelfTestIndex()
	cmd, err := store.MintSelfTestCommand(context.Background(), database, idx, "canary-a", "192.0.2.10",
		[]store.SelfTestTarget{{Service: "ssh", DestPort: 22}}, now, now.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("MintSelfTestCommand: %v", err)
	}
	params, err := selftest.DecodeParams([]byte(cmd.Params))
	if err != nil {
		t.Fatalf("decode minted params: %v", err)
	}

	alert := store.AlertInsert{InstanceID: "canary-a", Service: "ssh", DestPort: 22, Raw: `{"probe":"` + params.Targets[0].Marker + `"}`}
	if matched, err := store.MatchSelfTest(context.Background(), database, idx, alert, now); err != nil || !matched {
		t.Fatalf("MatchSelfTest = %v, %v, want true, nil", matched, err)
	}

	afterDeadline := now.Add(11 * time.Minute)
	if _, err := store.SweepExpiredSelfTestRuns(context.Background(), database, afterDeadline); err != nil {
		t.Fatalf("SweepExpiredSelfTestRuns: %v", err)
	}
	if err := store.RecordHeartbeat(context.Background(), database, "canary-a", afterDeadline); err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}

	h := newHandler(database, fixedNow(afterDeadline), nil)
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
		t.Fatalf("got %d canaries, want 1", len(resp.Canaries))
	}
	c := resp.Canaries[0]
	if len(c.SelfTest) != 1 {
		t.Fatalf("SelfTest = %+v, want exactly one service", c.SelfTest)
	}
	got := c.SelfTest[0]
	if got.Service != "ssh" || got.Grade != store.GradeMarked || !got.Passed {
		t.Errorf("SelfTest[0] = %+v, want {ssh marked true}", got)
	}
}

// TestHandleCanariesOmitsSelfTestWhenNeverRun matches
// TestHandleCanariesFields' own check for silent_for_s/beats_missed:
// self_test must be entirely absent from the JSON, not present as null
// or an empty array, for a canary that has never had a self-test run.
func TestHandleCanariesOmitsSelfTestWhenNeverRun(t *testing.T) {
	database := openTempDB(t)
	enrolledAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	insertCanary(t, database, store.Canary{
		ID: "canary-b", Name: "canary-b", Lane: "lan",
		Ports: "22", HeartbeatIntervalS: 60, EnrolledAt: enrolledAt,
	})
	beatAt := enrolledAt.Add(time.Hour)
	if err := store.RecordHeartbeat(context.Background(), database, "canary-b", beatAt); err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}

	h := newHandler(database, fixedNow(beatAt.Add(30*time.Second)), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/canaries", nil)
	h.ServeHTTP(rec, req)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode raw response: %v", err)
	}
	var canariesRaw []map[string]json.RawMessage
	if err := json.Unmarshal(raw["canaries"], &canariesRaw); err != nil {
		t.Fatalf("decode raw canaries: %v", err)
	}
	if len(canariesRaw) != 1 {
		t.Fatalf("got %d canaries, want 1", len(canariesRaw))
	}
	if _, ok := canariesRaw[0]["self_test"]; ok {
		t.Error(`"self_test" key present in JSON for a canary that never ran a self-test, want it omitted entirely`)
	}
}
