package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/store"
)

func TestHandleVisitorsGroupsAndClassifies(t *testing.T) {
	database := openTempDB(t)
	// Chronological insertion order -- see internal/store/visitor_test.go
	// for why that matters to id-ordered queries.
	insertAlert(t, database, "canary-srv", "192.0.2.88", 21, "ftp", "2026-09-11T03:18:40Z")
	insertAlert(t, database, "canary-lan", "203.0.113.42", 22, "ssh", "2026-09-12T21:55:40Z")
	insertAlert(t, database, "canary-srv", "203.0.113.42", 3306, "mysql", "2026-09-12T21:57:22Z")

	now := time.Date(2026, 9, 12, 22, 4, 31, 0, time.UTC)
	h := newHandler(database, fixedNow(now), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/visitors?range=14d", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var resp visitorsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Visitors) != 2 {
		t.Fatalf("got %d visitors, want 2: %+v", len(resp.Visitors), resp.Visitors)
	}
	// Newest last_at first.
	if resp.Visitors[0].SourceIP != "203.0.113.42" || resp.Visitors[0].Kind != store.KindSweep {
		t.Errorf("visitors[0] = %+v, want 203.0.113.42/sweep", resp.Visitors[0])
	}
	if resp.Visitors[1].SourceIP != "192.0.2.88" || resp.Visitors[1].Kind != store.KindTouch {
		t.Errorf("visitors[1] = %+v, want 192.0.2.88/touch", resp.Visitors[1])
	}
	if resp.NextBefore != nil {
		t.Errorf("next_before = %v, want nil (page shorter than the default limit)", *resp.NextBefore)
	}
}

func TestHandleVisitorsRejectsUnknownRange(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, time.Now, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/visitors?range=7d", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleVisitorsBadQueryParams(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, time.Now, nil)

	cases := []string{
		"/api/visitors?before=not-a-time",
		"/api/visitors?limit=abc",
	}
	for _, target := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, target, nil)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400; body=%s", target, rec.Code, rec.Body.String())
		}
	}
}

func TestHandleVisitorsCursorPaging(t *testing.T) {
	database := openTempDB(t)
	ips := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}
	times := []string{"2026-09-12T10:00:00Z", "2026-09-12T11:00:00Z", "2026-09-12T12:00:00Z"}
	for i, ip := range ips {
		insertAlert(t, database, "canary-lan", ip, 22, "ssh", times[i])
	}

	now := time.Date(2026, 9, 12, 13, 0, 0, 0, time.UTC)
	h := newHandler(database, fixedNow(now), nil)

	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/api/visitors?range=14d&limit=2", nil)
	h.ServeHTTP(rec1, req1)
	var page1 visitorsResponse
	if err := json.Unmarshal(rec1.Body.Bytes(), &page1); err != nil {
		t.Fatalf("decode page1: %v; body=%s", err, rec1.Body.String())
	}
	if len(page1.Visitors) != 2 {
		t.Fatalf("page1: got %d visitors, want 2: %+v", len(page1.Visitors), page1.Visitors)
	}
	if page1.NextBefore == nil {
		t.Fatal("page1: next_before = nil, want the last visitor's last_at (page filled the limit)")
	}

	rec2 := httptest.NewRecorder()
	target := "/api/visitors?range=14d&limit=2&before=" + url.QueryEscape(*page1.NextBefore)
	req2 := httptest.NewRequest(http.MethodGet, target, nil)
	h.ServeHTTP(rec2, req2)
	var page2 visitorsResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &page2); err != nil {
		t.Fatalf("decode page2: %v; body=%s", err, rec2.Body.String())
	}
	if len(page2.Visitors) != 1 || page2.Visitors[0].SourceIP != "203.0.113.1" {
		t.Fatalf("page2 = %+v, want exactly [203.0.113.1]", page2.Visitors)
	}
	if page2.NextBefore != nil {
		t.Errorf("page2: next_before = %v, want nil (short page)", *page2.NextBefore)
	}
}

func TestHandleTraceShape(t *testing.T) {
	database := openTempDB(t)
	insertCanary(t, database, store.Canary{
		ID: "canary-lan", Name: "canary-lan", Lane: "lan",
		HeartbeatIntervalS: 60, EnrolledAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
	})
	beatAt := time.Date(2026, 9, 12, 22, 4, 22, 0, time.UTC)
	if err := store.RecordHeartbeat(context.Background(), database, "canary-lan", beatAt); err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}
	insertAlert(t, database, "canary-lan", "203.0.113.42", 22, "ssh", "2026-09-12T21:55:40Z")

	now := beatAt.Add(9 * time.Second)
	h := newHandler(database, fixedNow(now), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/trace?range=14d", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var trace store.Trace
	if err := json.Unmarshal(rec.Body.Bytes(), &trace); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if trace.Range != "14d" {
		t.Errorf("Range = %q, want 14d", trace.Range)
	}
	if !trace.Now.Equal(now) {
		t.Errorf("Now = %v, want %v", trace.Now, now)
	}
	if len(trace.Canaries) != 1 {
		t.Fatalf("got %d canaries, want 1: %+v", len(trace.Canaries), trace.Canaries)
	}
	c := trace.Canaries[0]
	if c.ID != "canary-lan" || c.Status != "ok" {
		t.Errorf("canary = %+v, want id/status canary-lan/ok", c)
	}
	if len(c.Hits) != 1 || c.Hits[0].Visitor != "203.0.113.42" || c.Hits[0].Kind != store.KindTouch {
		t.Fatalf("Hits = %+v, want one touch hit from 203.0.113.42", c.Hits)
	}
	if trace.LastHit == nil || trace.LastHit.Visitor != "203.0.113.42" || trace.LastHit.Canary != "canary-lan" {
		t.Errorf("LastHit = %+v, want the 203.0.113.42 hit on canary-lan", trace.LastHit)
	}
}

func TestHandleTraceRejectsUnknownRange(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, time.Now, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/trace?range=nope", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleTraceDefaultRangeAndNoAlerts(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, time.Now, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/trace", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var trace store.Trace
	if err := json.Unmarshal(rec.Body.Bytes(), &trace); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if trace.Range != store.DefaultRange {
		t.Errorf("Range = %q, want default %q", trace.Range, store.DefaultRange)
	}
	if trace.LastHit != nil {
		t.Errorf("LastHit = %+v, want nil (no alerts at all)", trace.LastHit)
	}
	if len(trace.Canaries) != 0 {
		t.Errorf("Canaries = %+v, want none (no canaries enrolled)", trace.Canaries)
	}
}
