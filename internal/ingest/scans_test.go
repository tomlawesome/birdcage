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
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

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
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

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
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

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
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

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
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

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
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

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
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

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
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

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
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

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
				h := newHandler(database, nil, time.Now, defaultLimiterLimits)

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
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

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
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

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
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

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
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

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
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

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
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

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
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

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
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

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
		h := newHandler(database, nil, time.Now, tiny)

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
