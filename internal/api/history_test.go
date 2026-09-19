package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

func addStatePeriod(t *testing.T, database *db.DB, p store.StatePeriod) {
	t.Helper()
	if err := store.OpenStatePeriod(context.Background(), database, p); err != nil {
		t.Fatalf("OpenStatePeriod(%+v): %v", p, err)
	}
}

func getHistory(t *testing.T, h http.Handler, query string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/history"+query, nil))
	return rec
}

// TestHandleHistoryReturnsPeriodsAndSummary covers the whole response
// shape in one pass: the window echoed back, one closed span and one
// still open, and the summary those two add up to.
func TestHandleHistoryReturnsPeriodsAndSummary(t *testing.T) {
	database := openTempDB(t)
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	enrolledAt := now.Add(-48 * time.Hour)
	insertCanary(t, database, store.Canary{
		ID: "canary-lan", Name: "canary-lan", Lane: "lan", HeartbeatIntervalS: 60, EnrolledAt: enrolledAt,
	})

	// Closed: eleven minutes throttled, an hour ago.
	closedStart := now.Add(-time.Hour)
	closedEnd := closedStart.Add(11 * time.Minute)
	reason := store.EndReasonCleared
	addStatePeriod(t, database, store.StatePeriod{
		CanaryID: "canary-lan", State: string(store.StateThrottled),
		StartedAt: closedStart, EndedAt: &closedEnd, FlapCount: 3, EndReason: &reason,
	})
	// Open: silent since ten minutes ago, still running now.
	addStatePeriod(t, database, store.StatePeriod{
		CanaryID: "canary-lan", State: string(store.StateSilent), StartedAt: now.Add(-10 * time.Minute),
	})

	h := newHandler(database, fixedNow(now), nil)
	rec := getHistory(t, h, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var resp historyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if resp.Range != "24h" {
		t.Errorf("range = %q, want the 24h default", resp.Range)
	}
	if !resp.Until.Equal(now) || !resp.Since.Equal(now.Add(-24*time.Hour)) {
		t.Errorf("window = %v..%v, want %v..%v", resp.Since, resp.Until, now.Add(-24*time.Hour), now)
	}
	if len(resp.Periods) != 2 {
		t.Fatalf("got %d periods, want 2: %+v", len(resp.Periods), resp.Periods)
	}
	// Same canary, so start time orders them: the closed span first.
	closed, open := resp.Periods[0], resp.Periods[1]
	if closed.State != string(store.StateThrottled) || closed.EndedAt == nil || !closed.EndedAt.Equal(closedEnd) {
		t.Errorf("first period = %+v, want the closed throttled span", closed)
	}
	if closed.FlapCount != 3 || closed.EndReason == nil || *closed.EndReason != store.EndReasonCleared {
		t.Errorf("first period = %+v, want flap_count 3 and end_reason cleared", closed)
	}
	if closed.CanaryName != "canary-lan" {
		t.Errorf("canary_name = %q, want %q", closed.CanaryName, "canary-lan")
	}
	if open.EndedAt != nil || open.EndReason != nil {
		t.Errorf("second period = %+v, want it still open", open)
	}

	// ended_at and end_reason must be present as JSON null on an open
	// period, not omitted: the frontend distinguishes "still running"
	// from "this field was not sent".
	var raw struct {
		Periods []map[string]json.RawMessage `json:"periods"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode raw response: %v", err)
	}
	for _, key := range []string{"ended_at", "end_reason"} {
		value, ok := raw.Periods[1][key]
		if !ok {
			t.Errorf("%q missing from an open period, want it present as null", key)
			continue
		}
		if string(value) != "null" {
			t.Errorf("%q on an open period = %s, want null", key, value)
		}
	}

	if len(resp.Summary) != 2 {
		t.Fatalf("got %d summary rows, want 2: %+v", len(resp.Summary), resp.Summary)
	}
	// Worst state first within one canary: silent outranks throttled.
	if resp.Summary[0].State != string(store.StateSilent) {
		t.Errorf("summary order = %+v, want silent first", resp.Summary)
	}
	if resp.Summary[0].TotalS != 600 || resp.Summary[0].Count != 1 {
		t.Errorf("silent summary = %+v, want one span of 600s clipped at now", resp.Summary[0])
	}
	if resp.Summary[1].TotalS != 660 || resp.Summary[1].LongestS != 660 {
		t.Errorf("throttled summary = %+v, want 660s", resp.Summary[1])
	}
}

func TestHandleHistoryRejectsUnknownRange(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, time.Now, nil)

	for _, bad := range []string{"14d", "15m", "forever"} {
		rec := getHistory(t, h, "?range="+bad)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("range=%s: status = %d, want 400; body=%s", bad, rec.Code, rec.Body.String())
		}
	}
	for _, good := range []string{"24h", "7d", "30d"} {
		rec := getHistory(t, h, "?range="+good)
		if rec.Code != http.StatusOK {
			t.Errorf("range=%s: status = %d, want 200; body=%s", good, rec.Code, rec.Body.String())
		}
	}
}

// TestHandleHistoryFiltersByCanary: ?canary= narrows to one canary, and
// an id that matches nothing is an empty history rather than an error.
func TestHandleHistoryFiltersByCanary(t *testing.T) {
	database := openTempDB(t)
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	for _, id := range []string{"canary-a", "canary-b"} {
		insertCanary(t, database, store.Canary{
			ID: id, Name: id, Lane: "lan", HeartbeatIntervalS: 60, EnrolledAt: now.Add(-48 * time.Hour),
		})
		addStatePeriod(t, database, store.StatePeriod{
			CanaryID: id, State: string(store.StateSilent), StartedAt: now.Add(-time.Hour),
		})
	}

	h := newHandler(database, fixedNow(now), nil)

	rec := getHistory(t, h, "?canary=canary-b")
	var resp historyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Periods) != 1 || resp.Periods[0].CanaryID != "canary-b" {
		t.Errorf("periods = %+v, want only canary-b's", resp.Periods)
	}

	rec = getHistory(t, h, "?canary=no-such-canary")
	if rec.Code != http.StatusOK {
		t.Fatalf("unknown canary: status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Periods) != 0 || len(resp.Summary) != 0 {
		t.Errorf("unknown canary returned %+v, want empty periods and summary", resp)
	}
}

// TestHandleHistoryPassesCanaryNamesThrough: a canary name is
// attacker-influenced text. It is JSON-encoded, not stripped or
// rewritten -- the frontend escapes it where it is displayed
// (SECURITY.md, "Output escaping"), and a name mangled here would just
// hide what the operator actually typed.
func TestHandleHistoryPassesCanaryNamesThrough(t *testing.T) {
	database := openTempDB(t)
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	const name = `<img src=x onerror="alert(1)">`
	insertCanary(t, database, store.Canary{
		ID: "canary-x", Name: name, Lane: "lan", HeartbeatIntervalS: 60, EnrolledAt: now.Add(-48 * time.Hour),
	})
	addStatePeriod(t, database, store.StatePeriod{
		CanaryID: "canary-x", State: string(store.StateSilent), StartedAt: now.Add(-time.Hour),
	})

	h := newHandler(database, fixedNow(now), nil)
	rec := getHistory(t, h, "")
	var resp historyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Periods) != 1 || resp.Periods[0].CanaryName != name {
		t.Fatalf("canary_name = %+v, want it carried through verbatim (%q)", resp.Periods, name)
	}
	if resp.Summary[0].CanaryName != name {
		t.Errorf("summary canary_name = %q, want %q", resp.Summary[0].CanaryName, name)
	}
}
