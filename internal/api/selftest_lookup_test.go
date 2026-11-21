package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/selftest"
	"github.com/tomlawesome/birdcage/internal/store"
)

// completedSelfTestDB returns a database holding one canary whose latest
// self-test run is complete, so the per-service lookup has rows to read,
// plus the time the handler should treat as now.
func completedSelfTestDB(t *testing.T) (*db.DB, time.Time) {
	t.Helper()
	database := openTempDB(t)
	enrolledAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	insertCanary(t, database, store.Canary{
		ID: "canary-a", Name: "canary-a", Lane: "lan",
		Ports: "22", HeartbeatIntervalS: 60, EnrolledAt: enrolledAt,
	})
	now := enrolledAt.Add(time.Hour)
	ctx := context.Background()
	if err := store.RecordHeartbeat(ctx, database, "canary-a", now); err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}
	idx := store.NewSelfTestIndex()
	cmd, err := store.MintSelfTestCommand(ctx, database, idx, "canary-a", "192.0.2.10",
		[]store.SelfTestTarget{{Service: "ssh", DestPort: 22}}, now, now.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("MintSelfTestCommand: %v", err)
	}
	params, err := selftest.DecodeParams([]byte(cmd.Params))
	if err != nil {
		t.Fatalf("decode params: %v", err)
	}
	alert := store.AlertInsert{InstanceID: "canary-a", Service: "ssh", DestPort: 22, Raw: `{"probe":"` + params.Targets[0].Marker + `"}`}
	if matched, err := store.MatchSelfTest(ctx, database, idx, alert, now); err != nil || !matched {
		t.Fatalf("MatchSelfTest = %v, %v, want true, nil", matched, err)
	}
	after := now.Add(11 * time.Minute)
	if _, err := store.SweepExpiredSelfTestRuns(ctx, database, after); err != nil {
		t.Fatalf("SweepExpiredSelfTestRuns: %v", err)
	}
	if err := store.RecordHeartbeat(ctx, database, "canary-a", after); err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}
	return database, after
}

// captureLog redirects the standard logger for the test and returns the buffer.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(log.Writer()) })
	return &buf
}

// TestSelfTestLookupFailureIs500 (#224): when the per-service self-test
// lookup fails (self_test_targets unreadable, as in a database fault),
// both canary endpoints return 500 with the generic body and log the
// error, instead of a 200 that silently lacks self_test.
func TestSelfTestLookupFailureIs500(t *testing.T) {
	for _, path := range []string{"/api/canaries", "/api/canary?id=canary-a"} {
		t.Run(path, func(t *testing.T) {
			database, now := completedSelfTestDB(t)
			if _, err := database.Exec(`DROP TABLE self_test_targets`); err != nil {
				t.Fatalf("drop: %v", err)
			}
			logs := captureLog(t)
			h := newHandler(database, fixedNow(now), nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode body: %v; body=%s", err, rec.Body.String())
			}
			if body["error"] != "internal error" {
				t.Errorf("body = %s, want the generic {\"error\":\"internal error\"}", rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "self_test") {
				t.Errorf("body leaks lookup detail: %s", rec.Body.String())
			}
			if !strings.Contains(logs.String(), "self_test_targets") {
				t.Errorf("log = %q, want the lookup error logged", logs.String())
			}
		})
	}
}

// TestSelfTestLookupWorkingStill200WithSelfTest (#224): the unchanged
// path -- both endpoints return 200 and carry self_test.
func TestSelfTestLookupWorkingStill200WithSelfTest(t *testing.T) {
	for _, path := range []string{"/api/canaries", "/api/canary?id=canary-a"} {
		t.Run(path, func(t *testing.T) {
			database, now := completedSelfTestDB(t)
			h := newHandler(database, fixedNow(now), nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), `"self_test":[`) {
				t.Errorf("body lacks self_test: %s", rec.Body.String())
			}
		})
	}
}
