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

// TestHandleFindingsEmpty mirrors TestHandleScansEmpty: an empty list,
// not an error, before any finding has ever been recorded.
func TestHandleFindingsEmpty(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, time.Now, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/findings", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp findingsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Findings) != 0 {
		t.Fatalf("got %d findings, want 0: %+v", len(resp.Findings), resp.Findings)
	}
}

// TestHandleFindingsFields proves a recorded finding round-trips through
// GET /api/findings with its identity, state and metadata intact.
func TestHandleFindingsFields(t *testing.T) {
	database := openTempDB(t)
	insertCanary(t, database, store.Canary{
		ID: "scanner-a", Name: "scanner-a", Lane: "lan",
		EnrolledAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	at := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	observed := []store.ObservedFinding{{
		Target: store.BuildFindingTarget("deb", "openssl"), VulnerabilityID: "CVE-2014-0160",
		Severity: "critical", InstalledVersion: "1.0.1f", FixingVersion: "1.0.1f-1ubuntu2.1",
	}}
	if err := store.ApplyFindingSnapshot(context.Background(), database, "scanner-a", observed, at); err != nil {
		t.Fatalf("ApplyFindingSnapshot: %v", err)
	}

	h := newHandler(database, time.Now, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/findings", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp findingsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(resp.Findings), resp.Findings)
	}
	f := resp.Findings[0]
	if f.AgentID != "scanner-a" || f.Target != "deb:openssl" || f.VulnerabilityID != "CVE-2014-0160" {
		t.Errorf("identity = %+v, want scanner-a/deb:openssl/CVE-2014-0160", f)
	}
	if f.State != store.FindingOpen {
		t.Errorf("State = %q, want open", f.State)
	}
}

// TestHandleFindingsFiltersByAgentID proves ?agent_id= narrows the
// result -- the same shape handleAlerts' own filter query params use.
func TestHandleFindingsFiltersByAgentID(t *testing.T) {
	database := openTempDB(t)
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	observed := []store.ObservedFinding{{Target: "deb:openssl", VulnerabilityID: "CVE-1", Severity: "high"}}
	if err := store.ApplyFindingSnapshot(context.Background(), database, "scanner-a", observed, at); err != nil {
		t.Fatalf("ApplyFindingSnapshot scanner-a: %v", err)
	}
	if err := store.ApplyFindingSnapshot(context.Background(), database, "scanner-b", observed, at); err != nil {
		t.Fatalf("ApplyFindingSnapshot scanner-b: %v", err)
	}

	h := newHandler(database, time.Now, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/findings?agent_id=scanner-a", nil))
	var resp findingsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Findings) != 1 || resp.Findings[0].AgentID != "scanner-a" {
		t.Fatalf("filtered findings = %+v, want exactly scanner-a's one row", resp.Findings)
	}
}

// TestHandleFindingsAgentsStaleness proves GET /api/findings' Agents map
// (issue #109's "marked stale" bullet): not stale after an ok scan,
// stale after a failed one (with the findings underneath untouched and
// last_ok_scan still naming the earlier ok scan), not stale again once
// a fresh ok scan lands.
func TestHandleFindingsAgentsStaleness(t *testing.T) {
	database := openTempDB(t)
	observed := []store.ObservedFinding{{Target: "deb:openssl", VulnerabilityID: "CVE-2014-0160", Severity: "critical"}}

	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := store.RecordScanSnapshot(context.Background(), database, store.ScanSnapshot{
		CanaryID: "scanner-a", TakenAt: t1, ReceivedAt: t1, EngineName: "grype", EngineVersion: "v1",
		Status: store.ScanStatusOK, FindingCount: 1,
	}); err != nil {
		t.Fatalf("RecordScanSnapshot ok: %v", err)
	}
	if err := store.ApplyFindingSnapshot(context.Background(), database, "scanner-a", observed, t1); err != nil {
		t.Fatalf("ApplyFindingSnapshot: %v", err)
	}

	h := newHandler(database, time.Now, nil)
	getFindings := func() findingsResponse {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/findings?agent_id=scanner-a", nil))
		var resp findingsResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
		}
		return resp
	}

	resp := getFindings()
	status, ok := resp.Agents["scanner-a"]
	if !ok {
		t.Fatalf("Agents has no entry for scanner-a: %+v", resp.Agents)
	}
	if status.Stale {
		t.Errorf("Stale = true right after an ok scan, want false")
	}
	if status.LastOKScan == nil || !status.LastOKScan.Equal(t1) {
		t.Errorf("LastOKScan = %v, want %v", status.LastOKScan, t1)
	}

	t2 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	if err := store.RecordScanSnapshot(context.Background(), database, store.ScanSnapshot{
		CanaryID: "scanner-a", TakenAt: t2, ReceivedAt: t2, Status: store.ScanStatusFailed, Reason: "db stale",
	}); err != nil {
		t.Fatalf("RecordScanSnapshot failed: %v", err)
	}
	// No ApplyFindingSnapshot call for the failed scan -- matching
	// internal/ingest's own storeScan, which only calls it for status ok.

	resp = getFindings()
	status = resp.Agents["scanner-a"]
	if !status.Stale {
		t.Errorf("Stale = false after a failed scan, want true")
	}
	if status.LastOKScan == nil || !status.LastOKScan.Equal(t1) {
		t.Errorf("LastOKScan after a failed scan = %v, want still %v (the last ok one)", status.LastOKScan, t1)
	}
	if len(resp.Findings) != 1 || resp.Findings[0].State != store.FindingOpen {
		t.Fatalf("findings changed by a failed scan: %+v", resp.Findings)
	}

	t3 := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	if err := store.RecordScanSnapshot(context.Background(), database, store.ScanSnapshot{
		CanaryID: "scanner-a", TakenAt: t3, ReceivedAt: t3, EngineName: "grype", EngineVersion: "v1",
		Status: store.ScanStatusOK, FindingCount: 1,
	}); err != nil {
		t.Fatalf("RecordScanSnapshot ok 2: %v", err)
	}
	if err := store.ApplyFindingSnapshot(context.Background(), database, "scanner-a", observed, t3); err != nil {
		t.Fatalf("ApplyFindingSnapshot 2: %v", err)
	}

	resp = getFindings()
	status = resp.Agents["scanner-a"]
	if status.Stale {
		t.Errorf("Stale = true after a fresh ok scan, want false")
	}
	if status.LastOKScan == nil || !status.LastOKScan.Equal(t3) {
		t.Errorf("LastOKScan after the fresh ok scan = %v, want %v", status.LastOKScan, t3)
	}
}

func TestHandleFindingsRejectsPost(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, time.Now, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/findings", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405; body=%s", rec.Code, rec.Body.String())
	}
}
