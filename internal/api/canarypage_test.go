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

// TestHandleCanaryReturnsCanaryFactsAndRuns is issue #118's read: one
// canary's own page needs the standing facts the fleet reads never carry
// (address, heartbeat interval, enrolment, agent version, token
// rotation) and every self-test run in the window, not just the latest.
func TestHandleCanaryReturnsCanaryFactsAndRuns(t *testing.T) {
	database := openTempDB(t)
	ctx := context.Background()
	enrolledAt := time.Date(2026, 9, 1, 9, 41, 0, 0, time.UTC)
	insertCanary(t, database, store.Canary{
		ID: "canary-iot", Name: "canary-iot", Lane: "iot",
		Ports: "22", HeartbeatIntervalS: 60, EnrolledAt: enrolledAt,
	})
	if err := store.SetCanaryLastSeenAddr(ctx, database, "canary-iot", "10.0.30.9"); err != nil {
		t.Fatalf("SetCanaryLastSeenAddr: %v", err)
	}
	if err := store.RecordCanaryCommonHeartbeat(ctx, database, "canary-iot", enrolledAt, "0.4.1"); err != nil {
		t.Fatalf("RecordCanaryCommonHeartbeat: %v", err)
	}
	tokenAt := enrolledAt.Add(time.Hour)
	if _, _, err := store.MintCanaryToken(ctx, database, "canary-iot", tokenAt); err != nil {
		t.Fatalf("MintCanaryToken: %v", err)
	}

	// A run that failed (swept past its deadline unmatched) yesterday,
	// and a run that passed today.
	idx := store.NewSelfTestIndex()
	failedAt := enrolledAt.Add(24 * time.Hour)
	if _, err := store.MintSelfTestCommand(ctx, database, idx, "canary-iot", "10.0.30.9",
		[]store.SelfTestTarget{{Service: "telnet", DestPort: 23}}, failedAt, failedAt.Add(10*time.Minute)); err != nil {
		t.Fatalf("MintSelfTestCommand (failing run): %v", err)
	}
	if _, err := store.SweepExpiredSelfTestRuns(ctx, database, failedAt.Add(11*time.Minute)); err != nil {
		t.Fatalf("SweepExpiredSelfTestRuns: %v", err)
	}

	passedAt := enrolledAt.Add(48 * time.Hour)
	cmd, err := store.MintSelfTestCommand(ctx, database, idx, "canary-iot", "10.0.30.9",
		[]store.SelfTestTarget{{Service: "ssh", DestPort: 22}}, passedAt, passedAt.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("MintSelfTestCommand (passing run): %v", err)
	}
	params, err := selftest.DecodeParams([]byte(cmd.Params))
	if err != nil {
		t.Fatalf("DecodeParams: %v", err)
	}
	alert := store.AlertInsert{InstanceID: "canary-iot", Service: "ssh", DestPort: 22, Raw: `{"probe":"` + params.Targets[0].Marker + `"}`}
	if matched, err := store.MatchSelfTest(ctx, database, idx, alert, passedAt); err != nil || !matched {
		t.Fatalf("MatchSelfTest = %v, %v, want true, nil", matched, err)
	}

	now := passedAt.Add(time.Minute)
	if err := store.RecordHeartbeat(ctx, database, "canary-iot", now); err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}

	h := newHandler(database, fixedNow(now), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/canary?id=canary-iot&range=14d", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var resp canaryPageResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}

	if resp.Canary.ID != "canary-iot" {
		t.Errorf("canary.id = %q, want canary-iot", resp.Canary.ID)
	}
	if resp.Facts.Address == nil || *resp.Facts.Address != "10.0.30.9" {
		t.Errorf("facts.address = %v, want 10.0.30.9", resp.Facts.Address)
	}
	if resp.Facts.HeartbeatIntervalS != 60 {
		t.Errorf("facts.heartbeat_interval_s = %d, want 60", resp.Facts.HeartbeatIntervalS)
	}
	if !resp.Facts.EnrolledAt.Equal(enrolledAt) {
		t.Errorf("facts.enrolled_at = %v, want %v", resp.Facts.EnrolledAt, enrolledAt)
	}
	if resp.Facts.AgentVersion == nil || *resp.Facts.AgentVersion != "0.4.1" {
		t.Errorf("facts.agent_version = %v, want 0.4.1", resp.Facts.AgentVersion)
	}
	if resp.Facts.Kind != "honeypot" {
		t.Errorf("facts.kind = %q, want honeypot", resp.Facts.Kind)
	}
	if resp.Facts.TokenRotatedAt == nil || !resp.Facts.TokenRotatedAt.Equal(tokenAt) {
		t.Errorf("facts.token_rotated_at = %v, want %v", resp.Facts.TokenRotatedAt, tokenAt)
	}
	// The default schedule is the rotation one (selftest_use_rotation_schedule
	// defaults to true), whose own default is midnight UTC.
	if resp.Facts.SelfTestSchedule != "00:00" || !resp.Facts.SelfTestEnabled {
		t.Errorf("facts self-test schedule = %q enabled = %v, want 00:00 true", resp.Facts.SelfTestSchedule, resp.Facts.SelfTestEnabled)
	}
	if resp.Facts.TokenRotatesAt == nil || !resp.Facts.TokenRotatesAt.After(now) {
		t.Errorf("facts.token_rotates_at = %v, want an instant after %v", resp.Facts.TokenRotatesAt, now)
	}

	if len(resp.SelfTestRuns) != 2 {
		t.Fatalf("self_test_runs = %+v, want two runs", resp.SelfTestRuns)
	}
	newest, oldest := resp.SelfTestRuns[0], resp.SelfTestRuns[1]
	if !newest.IssuedAt.Equal(passedAt) {
		t.Errorf("self_test_runs[0].issued_at = %v, want the newest run %v", newest.IssuedAt, passedAt)
	}
	if newest.Passed == nil || !*newest.Passed {
		t.Errorf("self_test_runs[0].passed = %v, want true", newest.Passed)
	}
	if oldest.Passed == nil || *oldest.Passed {
		t.Errorf("self_test_runs[1].passed = %v, want false", oldest.Passed)
	}
	if len(oldest.FailedServices) != 1 || oldest.FailedServices[0] != "telnet 23" {
		t.Errorf("self_test_runs[1].failed_services = %v, want [telnet 23]", oldest.FailedServices)
	}
}

// TestHandleCanaryRejectsBadRequests: no id is a 400 (there is no
// default canary), an unknown id is a 404 (a page about a canary that
// does not exist has nothing to draw), and an unrecognized range is the
// same 400 every other dashboard read gives.
func TestHandleCanaryRejectsBadRequests(t *testing.T) {
	database := openTempDB(t)
	enrolledAt := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	insertCanary(t, database, store.Canary{
		ID: "canary-a", Name: "canary-a", Lane: "lan",
		Ports: "22", HeartbeatIntervalS: 60, EnrolledAt: enrolledAt,
	})
	h := newHandler(database, fixedNow(enrolledAt.Add(time.Minute)), nil)

	for _, tc := range []struct {
		name string
		url  string
		want int
	}{
		{"no id", "/api/canary", http.StatusBadRequest},
		{"unknown id", "/api/canary?id=canary-nope", http.StatusNotFound},
		{"bad range", "/api/canary?id=canary-a&range=7d", http.StatusBadRequest},
		{"known id", "/api/canary?id=canary-a", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.url, nil))
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d; body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestHandleCanaryFactsFollowSettingsAndLiveTokens: when the self-test
// runs on its own schedule rather than the rotation's, the facts column
// shows that schedule; and "token rotated" is the newest token still in
// force -- a revoked one, however recent, is not the token the canary is
// using.
func TestHandleCanaryFactsFollowSettingsAndLiveTokens(t *testing.T) {
	database := openTempDB(t)
	ctx := context.Background()
	enrolledAt := time.Date(2026, 9, 1, 9, 41, 0, 0, time.UTC)
	insertCanary(t, database, store.Canary{
		ID: "canary-iot", Name: "canary-iot", Lane: "iot",
		Ports: "22", HeartbeatIntervalS: 60, EnrolledAt: enrolledAt,
	})
	if err := store.SetSetting(ctx, database, store.SettingSelfTestUseRotationSchedule, "false", enrolledAt); err != nil {
		t.Fatalf("SetSetting(use rotation schedule): %v", err)
	}
	if err := store.SetSetting(ctx, database, store.SettingSelfTestSchedule, "04:00", enrolledAt); err != nil {
		t.Fatalf("SetSetting(self-test schedule): %v", err)
	}

	liveAt := enrolledAt.Add(time.Hour)
	if _, _, err := store.MintCanaryToken(ctx, database, "canary-iot", liveAt); err != nil {
		t.Fatalf("MintCanaryToken (live): %v", err)
	}
	revokedAt := enrolledAt.Add(2 * time.Hour)
	_, revoked, err := store.MintCanaryToken(ctx, database, "canary-iot", revokedAt)
	if err != nil {
		t.Fatalf("MintCanaryToken (to revoke): %v", err)
	}
	if err := store.RevokeCanaryToken(ctx, database, revoked.ID, revokedAt.Add(time.Minute)); err != nil {
		t.Fatalf("RevokeCanaryToken: %v", err)
	}

	now := enrolledAt.Add(3 * time.Hour)
	h := newHandler(database, fixedNow(now), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/canary?id=canary-iot&range=14d", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp canaryPageResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if resp.Facts.SelfTestSchedule != "04:00" {
		t.Errorf("facts.self_test_schedule = %q, want the self-test's own 04:00", resp.Facts.SelfTestSchedule)
	}
	if resp.Facts.TokenRotatedAt == nil || !resp.Facts.TokenRotatedAt.Equal(liveAt) {
		t.Errorf("facts.token_rotated_at = %v, want the live token's %v, not the revoked one's", resp.Facts.TokenRotatedAt, liveAt)
	}
}

// TestNextScheduleTime: a schedule later today is today; one already
// past is tomorrow; a value that is not a clock time (only reachable by
// hand-editing the settings row) yields no instant rather than a zero
// time the page would print as year one.
func TestNextScheduleTime(t *testing.T) {
	now := time.Date(2026, 9, 12, 22, 4, 31, 0, time.UTC)
	if next, ok := nextScheduleTime("23:30", now); !ok || !next.Equal(time.Date(2026, 9, 12, 23, 30, 0, 0, time.UTC)) {
		t.Errorf("nextScheduleTime(23:30) = %v, %v; want tonight 23:30", next, ok)
	}
	if next, ok := nextScheduleTime("04:00", now); !ok || !next.Equal(time.Date(2026, 9, 13, 4, 0, 0, 0, time.UTC)) {
		t.Errorf("nextScheduleTime(04:00) = %v, %v; want tomorrow 04:00", next, ok)
	}
	if _, ok := nextScheduleTime("sometime", now); ok {
		t.Error("nextScheduleTime(sometime) ok = true, want false")
	}
}
