package ingest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// validScanOKBody is a well-formed POST /ingest/scans body reporting one
// finding -- the "Scanner agent, slice 1" plan's own example (#108,
// section 2).
const validScanOKBody = `{
	"taken_at": "2026-01-02T00:00:00Z",
	"agent_version": "1.0.0",
	"engine": {"name": "grype", "version": "v0.119.0", "db_built_at": "2026-01-01T12:00:00Z"},
	"status": "ok",
	"findings": [
		{"target": "dir:/host", "package": "openssl", "version": "1.0.1f-1ubuntu2", "type": "deb",
		 "vulnerability": "CVE-2014-0160", "severity": "critical", "fix_version": "1.0.1f-1ubuntu2.1"}
	],
	"masked_paths": ["/etc/shadow", "/root"]
}`

func listScans(t *testing.T, database *db.DB) []store.ScanSnapshot {
	t.Helper()
	snapshots, err := store.ListScanSnapshots(context.Background(), database)
	if err != nil {
		t.Fatalf("ListScanSnapshots: %v", err)
	}
	return snapshots
}

// TestHandleScanRequiresCanaryToken mirrors handleHeartbeat's own first
// required behavior: no token, no write.
func TestHandleScanRequiresCanaryToken(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", "", validScanOKBody))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})
}

// TestHandleScanRejectsIdentityField proves ingestScan's own doc
// comment: unlike ingestBatch.NodeID or ingestHeartbeat.CanaryID, the
// wire contract names no identity field at all, so a body that tries to
// carry one is simply an unknown field -- DisallowUnknownFields refuses
// it outright rather than birdcage having anything to compare and
// ignore.
func TestHandleScanRejectsIdentityField(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		body := `{"canary_id": "canary-b", "taken_at": "2026-01-02T00:00:00Z", "status": "failed", "reason": "x", "findings": [], "masked_paths": []}`
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	})
}

// TestHandleScanStoresOKSnapshot proves a well-formed ok snapshot is
// stored under the token's own canary id, with the finding count and
// masked-path list intact -- never the findings' own contents.
func TestHandleScanStoresOKSnapshot(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		enrollCanaryKind(t, database, "canary-b", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, validScanOKBody))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		snapshots := listScans(t, database)
		if len(snapshots) != 1 {
			t.Fatalf("got %d scan snapshots, want 1: %+v", len(snapshots), snapshots)
		}
		s := snapshots[0]
		if s.CanaryID != "canary-a" {
			t.Errorf("CanaryID = %q, want canary-a (the token's canary, not canary-b)", s.CanaryID)
		}
		if s.Status != store.ScanStatusOK || s.FindingCount != 1 {
			t.Errorf("Status/FindingCount = %q/%d, want ok/1", s.Status, s.FindingCount)
		}
		if s.EngineName != "grype" || s.EngineVersion != "v0.119.0" {
			t.Errorf("EngineName/EngineVersion = %q/%q, want grype/v0.119.0", s.EngineName, s.EngineVersion)
		}
		if s.DBBuiltAt == nil || !s.DBBuiltAt.Equal(mustParseTime(t, "2026-01-01T12:00:00Z")) {
			t.Errorf("DBBuiltAt = %v, want 2026-01-01T12:00:00Z", s.DBBuiltAt)
		}
		if len(s.MaskedPaths) != 2 || s.MaskedPaths[0] != "/etc/shadow" || s.MaskedPaths[1] != "/root" {
			t.Errorf("MaskedPaths = %v, want [/etc/shadow /root]", s.MaskedPaths)
		}
	})
}

// TestHandleScanStoresFailedSnapshotWithNoEngineData proves the
// fail-closed shape: a failed scan is stored with its reason, zero
// findings and no engine/database metadata at all -- ADR-0010 decision
// 8, "never an empty finding set presented as clean", starts with the
// server accepting exactly this shape rather than requiring data a
// failed run never had.
func TestHandleScanStoresFailedSnapshotWithNoEngineData(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		body := `{"taken_at": "2026-01-02T00:00:00Z", "status": "failed",
			"reason": "db could not be loaded: the vulnerability database was built 6 days ago (max allowed age is 5 days)",
			"findings": [], "masked_paths": ["/etc/ssh"]}`
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		s := listScans(t, database)[0]
		if s.Status != store.ScanStatusFailed || s.FindingCount != 0 {
			t.Errorf("Status/FindingCount = %q/%d, want failed/0", s.Status, s.FindingCount)
		}
		if s.Reason == "" {
			t.Error("Reason is empty, want the posted reason stored")
		}
		if s.EngineName != "" || s.EngineVersion != "" || s.DBBuiltAt != nil {
			t.Errorf("EngineName/EngineVersion/DBBuiltAt = %q/%q/%v, want all empty/nil for a failed scan", s.EngineName, s.EngineVersion, s.DBBuiltAt)
		}
		if len(s.MaskedPaths) != 1 || s.MaskedPaths[0] != "/etc/ssh" {
			t.Errorf("MaskedPaths = %v, want [/etc/ssh] (masked_paths is present on a failed snapshot too)", s.MaskedPaths)
		}
	})
}

// TestHandleScanFailedRequiresReason proves ADR-0010 decision 8's own
// requirement in the negative: a failed status with no reason is a
// malformed body, not a storable one.
func TestHandleScanFailedRequiresReason(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		body := `{"taken_at": "2026-01-02T00:00:00Z", "status": "failed", "findings": [], "masked_paths": []}`
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
		if len(listScans(t, database)) != 0 {
			t.Error("a rejected scan body was stored")
		}
	})
}

// TestHandleScanFailedFindingsMustBeEmpty is the plan's own named trap:
// "non-empty findings with status: failed is a rejected body, not a
// stored one."
func TestHandleScanFailedFindingsMustBeEmpty(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		body := `{"taken_at": "2026-01-02T00:00:00Z", "status": "failed", "reason": "db stale",
			"findings": [{"target": "dir:/host", "package": "openssl", "version": "1.0.1f", "type": "deb",
				"vulnerability": "CVE-2014-0160", "severity": "critical"}], "masked_paths": []}`
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
		if len(listScans(t, database)) != 0 {
			t.Error("a rejected scan body was stored")
		}
	})
}

func TestHandleScanOkReasonMustBeEmpty(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		body := `{"taken_at": "2026-01-02T00:00:00Z",
			"engine": {"name": "grype", "version": "v0.119.0", "db_built_at": "2026-01-01T12:00:00Z"},
			"status": "ok", "reason": "should not be here", "findings": [], "masked_paths": []}`
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	})
}

func TestHandleScanOkRequiresEngineMetadata(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		body := `{"taken_at": "2026-01-02T00:00:00Z", "status": "ok", "findings": [], "masked_paths": []}`
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	})
}

func TestHandleScanRejectsUnknownStatus(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		body := `{"taken_at": "2026-01-02T00:00:00Z", "status": "clean", "findings": [], "masked_paths": []}`
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	})
}

// TestHandleScanRejectsMalformedFinding proves each required finding
// field (every one but fix_version) is enforced individually.
func TestHandleScanRejectsMalformedFinding(t *testing.T) {
	base := map[string]string{
		"target": "dir:/host", "package": "openssl", "version": "1.0.1f",
		"type": "deb", "vulnerability": "CVE-2014-0160", "severity": "critical",
	}
	for _, field := range []string{"target", "package", "version", "type", "vulnerability", "severity"} {
		t.Run(field, func(t *testing.T) {
			forEachEngine(t, func(t *testing.T, database *db.DB) {
				enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
				raw := mintToken(t, database, "canary-a")
				h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

				finding := "{"
				for k, v := range base {
					val := v
					if k == field {
						val = ""
					}
					finding += `"` + k + `": "` + val + `",`
				}
				finding = strings.TrimSuffix(finding, ",") + "}"

				body := `{"taken_at": "2026-01-02T00:00:00Z",
					"engine": {"name": "grype", "version": "v0.119.0", "db_built_at": "2026-01-01T12:00:00Z"},
					"status": "ok", "findings": [` + finding + `], "masked_paths": []}`
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, body))
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("field %s empty: status = %d, want %d (body %q)", field, rec.Code, http.StatusBadRequest, rec.Body.String())
				}
				if len(listScans(t, database)) != 0 {
					t.Error("a rejected scan body was stored")
				}
			})
		})
	}
}

// TestHandleScanRejectsTrailingData proves the dec.More() guard every
// other route on this mux already carries (e.g.
// TestHandleHeartbeatUnknownFieldRejected's sibling in heartbeat_test.go).
func TestHandleScanRejectsTrailingData(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		body := `{"taken_at": "2026-01-02T00:00:00Z", "status": "failed", "reason": "x", "findings": [], "masked_paths": []}{}`
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	})
}

func TestHandleScanRejectsMalformedTakenAt(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		body := `{"taken_at": "not-a-timestamp", "status": "failed", "reason": "x", "findings": [], "masked_paths": []}`
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	})
}

func TestHandleScanRejectsMalformedDBBuiltAt(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		body := `{"taken_at": "2026-01-02T00:00:00Z",
			"engine": {"name": "grype", "version": "v0.119.0", "db_built_at": "not-a-timestamp"},
			"status": "ok", "findings": [], "masked_paths": []}`
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	})
}

// TestHandleScanStorageFailureReturns503 mirrors
// TestRotateAuditFailureReturns503LeavesPresentedTokenWorkingAndNoUsableNewToken's
// own technique (rotate_test.go): scan_snapshots is dropped, not the
// whole database, which would fail auth itself before handleScan's own
// store call is ever reached -- so this isolates RecordScanSnapshot's own
// error path, reported as retryable (503), never a rejection.
func TestHandleScanStorageFailureReturns503(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		if _, err := database.Exec(`DROP TABLE scan_snapshots`); err != nil {
			t.Fatalf("drop scan_snapshots: %v", err)
		}

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, validScanOKBody))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
		}
	})
}

func TestHandleScanRejectsNonAbsoluteMaskedPath(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		body := `{"taken_at": "2026-01-02T00:00:00Z", "status": "failed", "reason": "x",
			"findings": [], "masked_paths": ["etc/shadow"]}`
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	})
}

// TestHandleScanMaskedPathsEmptyAccepted proves an empty mask list is a
// legitimate value, not a validation failure -- a scanner whose run
// command masks nothing still reports the field, just empty.
func TestHandleScanMaskedPathsEmptyAccepted(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		body := `{"taken_at": "2026-01-02T00:00:00Z", "status": "failed", "reason": "x",
			"findings": [], "masked_paths": []}`
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}
		s := listScans(t, database)[0]
		if s.MaskedPaths == nil || len(s.MaskedPaths) != 0 {
			t.Errorf("MaskedPaths = %v, want a non-nil empty slice", s.MaskedPaths)
		}
	})
}

// TestHandleScanOverLimitReturns413 proves scanMaxBodyBytes' own cap,
// distinct from maxBodyBytes' (batch.go): a real host's finding set
// (up to 4 MiB) must not bounce as a 413 that would look like an auth
// failure, but anything past the cap does.
func TestHandleScanOverLimitReturns413(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		oversized := `{"taken_at": "2026-01-02T00:00:00Z", "status": "failed", "reason": "` +
			strings.Repeat("x", scanMaxBodyBytes) + `", "findings": [], "masked_paths": []}`
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, oversized))
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
		}
	})
}

func TestHandleScanUnknownFieldRejected(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, `{"unexpected_field":true}`))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	})
}

// TestHandleScanOverLimitReturns429AndIsRecorded mirrors
// TestHandleHeartbeatOverLimitReturns429AndIsRecorded: this route is
// covered by the same per-canary requests/min limiter every route on
// this mux shares (requireBearerToken), not a limiter of its own.
func TestHandleScanOverLimitReturns429AndIsRecorded(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		tiny := limiterLimits{RequestsPerMinute: 2, EventsPerMinute: 60000}
		h := newHandler(database, nil, time.Now, tiny, store.NewSelfTestIndex(), nil)

		var last *httptest.ResponseRecorder
		for i := 0; i < 3; i++ {
			last = httptest.NewRecorder()
			h.ServeHTTP(last, ingestRequest(http.MethodPost, "/ingest/scans", raw, validScanOKBody))
		}
		if last.Code != http.StatusTooManyRequests {
			t.Fatalf("3rd scan status = %d, want %d (body %q)", last.Code, http.StatusTooManyRequests, last.Body.String())
		}
		if got := countAuditRows(t, database, "ingest.rate_limited", "canary-a"); got == 0 {
			t.Fatal("no audit_log row recorded for the rate limit crossing on scans")
		}
	})
}

func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return tm
}

// stepClock returns a now func that advances by a minute on every call,
// starting at start -- for tests below that need several posts to land
// at distinct, ordered ReceivedAt values without relying on real wall-
// clock granularity between two calls in the same test.
func stepClock(start time.Time) func() time.Time {
	t := start
	return func() time.Time {
		t = t.Add(time.Minute)
		return t
	}
}

func listFindingsFor(t *testing.T, database *db.DB, agentID string) []store.Finding {
	t.Helper()
	findings, err := store.ListFindings(context.Background(), database, store.FindingFilter{AgentID: agentID})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	return findings
}

// TestHandleScanPersistsFindings proves issue #109's own wiring claim:
// a posted ok snapshot's findings land in the findings store (open,
// first_seen == last_seen == the snapshot's own received-at clock), not
// just counted onto scan_snapshots the way #108 left it.
func TestHandleScanPersistsFindings(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		clock := stepClock(mustParseTime(t, "2026-01-01T00:00:00Z"))
		h := newHandler(database, nil, clock, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, validScanOKBody))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		findings := listFindingsFor(t, database, "canary-a")
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
		}
		f := findings[0]
		if f.State != store.FindingOpen {
			t.Errorf("State = %q, want open", f.State)
		}
		if f.Target != store.BuildFindingTarget("deb", "openssl") || f.VulnerabilityID != "CVE-2014-0160" {
			t.Errorf("Target/VulnerabilityID = %q/%q, want deb:openssl/CVE-2014-0160", f.Target, f.VulnerabilityID)
		}
		if f.Severity != "critical" || f.InstalledVersion != "1.0.1f-1ubuntu2" || f.FixingVersion != "1.0.1f-1ubuntu2.1" {
			t.Errorf("Severity/InstalledVersion/FixingVersion = %q/%q/%q, want critical/1.0.1f-1ubuntu2/1.0.1f-1ubuntu2.1",
				f.Severity, f.InstalledVersion, f.FixingVersion)
		}
		if !f.FirstSeen.Equal(f.LastSeen) {
			t.Errorf("FirstSeen != LastSeen on a brand new finding: %v != %v", f.FirstSeen, f.LastSeen)
		}
	})
}

// TestHandleScanRescanUnchangedOnlyMovesLastSeen is the issue's first
// acceptance bullet, proven through the real ingest path rather than the
// store function directly: two identical ok snapshots for the same
// agent leave exactly one finding row, with last_seen moved to the
// second snapshot's received time and first_seen untouched.
func TestHandleScanRescanUnchangedOnlyMovesLastSeen(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		clock := stepClock(mustParseTime(t, "2026-01-01T00:00:00Z"))
		h := newHandler(database, nil, clock, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		for i := 0; i < 2; i++ {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, validScanOKBody))
			if rec.Code != http.StatusOK {
				t.Fatalf("scan %d: status = %d, want %d (body %q)", i, rec.Code, http.StatusOK, rec.Body.String())
			}
		}

		findings := listFindingsFor(t, database, "canary-a")
		if len(findings) != 1 {
			t.Fatalf("got %d findings after an identical rescan, want 1 (same identity, not a second row): %+v", len(findings), findings)
		}
		f := findings[0]
		if f.State != store.FindingOpen {
			t.Errorf("State = %q, want still open", f.State)
		}
		if f.FirstSeen.Equal(f.LastSeen) {
			t.Errorf("FirstSeen == LastSeen (%v) after a second scan -- last_seen should have moved", f.FirstSeen)
		}
		if !f.LastSeen.After(f.FirstSeen) {
			t.Errorf("LastSeen (%v) is not after FirstSeen (%v)", f.LastSeen, f.FirstSeen)
		}
	})
}

// TestHandleScanRemovedPackageResolvesFinding is the issue's second
// acceptance bullet through the real ingest path: a second ok snapshot
// that no longer reports the package resolves the finding without the
// agent saying anything beyond its new (empty) finding set.
func TestHandleScanRemovedPackageResolvesFinding(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		clock := stepClock(mustParseTime(t, "2026-01-01T00:00:00Z"))
		h := newHandler(database, nil, clock, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, validScanOKBody))
		if rec.Code != http.StatusOK {
			t.Fatalf("first scan status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		cleanBody := `{"taken_at": "2026-01-02T00:00:00Z", "engine": {"name": "grype", "version": "v0.119.0", "db_built_at": "2026-01-01T12:00:00Z"},
			"status": "ok", "findings": [], "masked_paths": []}`
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, cleanBody))
		if rec.Code != http.StatusOK {
			t.Fatalf("clean rescan status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		findings := listFindingsFor(t, database, "canary-a")
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1 (resolved, not deleted): %+v", len(findings), findings)
		}
		if findings[0].State != store.FindingFixed {
			t.Errorf("State = %q, want fixed", findings[0].State)
		}
	})
}

// TestHandleScanFailedScanNeverResolvesFindings is the issue's fourth
// acceptance bullet through the real ingest path: a dropped/failed scan
// leaves every existing finding exactly as it was -- it is never even
// consulted, because internal/ingest only calls ApplyFindingSnapshot for
// status == ok (see storeScan).
func TestHandleScanFailedScanNeverResolvesFindings(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		clock := stepClock(mustParseTime(t, "2026-01-01T00:00:00Z"))
		h := newHandler(database, nil, clock, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, validScanOKBody))
		if rec.Code != http.StatusOK {
			t.Fatalf("ok scan status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}
		before := listFindingsFor(t, database, "canary-a")

		failedBody := `{"taken_at": "2026-01-02T00:00:00Z", "status": "failed", "reason": "db stale", "findings": [], "masked_paths": []}`
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, failedBody))
		if rec.Code != http.StatusOK {
			t.Fatalf("failed scan status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		after := listFindingsFor(t, database, "canary-a")
		if len(after) != 1 || after[0].State != store.FindingOpen || !after[0].LastSeen.Equal(before[0].LastSeen) {
			t.Errorf("findings after a failed scan = %+v, want unchanged from %+v", after, before)
		}
	})
}
