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

func TestHandleFindingsRejectsPost(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, time.Now, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/findings", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405; body=%s", rec.Code, rec.Body.String())
	}
}
