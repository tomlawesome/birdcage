package ingest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// Issue #213: POST /ingest/scans bounds the finding count, each finding
// field's length and the masked_paths list (positive input validation
// with per-field length bounds and a per-request item cap, OWASP ASVS
// V5.1.3/V5.1.4, CWE-770). Over-limit is a 400 naming the count or
// field, never a truncation, and nothing is stored.

const (
	boundsMaxFindings  = 10000
	boundsMaxMasked    = 256
	boundsMaxMaskedLen = 4096
)

// boundsFieldLimits is each finding field's byte limit, keyed by its
// JSON name.
var boundsFieldLimits = map[string]int{
	"target": 256, "package": 256, "version": 128, "type": 64,
	"vulnerability": 128, "severity": 16, "fix_version": 128,
}

func boundsFinding(i int) map[string]any {
	return map[string]any{
		"target": "dir:/host", "package": fmt.Sprintf("libfoo-%d", i), "version": "1.2.3-4ubuntu5",
		"type": "deb", "vulnerability": fmt.Sprintf("CVE-2024-%05d", i), "severity": "high",
		"fix_version": "1.2.3-4ubuntu5.1",
	}
}

func boundsScanBody(t *testing.T, findings []map[string]any, masked []string) string {
	t.Helper()
	if findings == nil {
		findings = []map[string]any{}
	}
	if masked == nil {
		masked = []string{}
	}
	b, err := json.Marshal(map[string]any{
		"taken_at": "2026-01-02T00:00:00Z",
		"engine":   map[string]string{"name": "grype", "version": "v0.119.0", "db_built_at": "2026-01-01T12:00:00Z"},
		"status":   "ok", "findings": findings, "masked_paths": masked,
	})
	if err != nil {
		t.Fatalf("marshal scan body: %v", err)
	}
	return string(b)
}

func boundsPost(h http.Handler, raw, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/scans", raw, body))
	return rec
}

// boundsSeed posts validScanOKBody so a later refusal has previous
// findings to leave untouched; it returns the handler and token.
func boundsSeed(t *testing.T, database *db.DB, now func() time.Time) (http.Handler, string) {
	t.Helper()
	enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
	raw := mintToken(t, database, "canary-a")
	h := newHandler(database, nil, now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)
	if rec := boundsPost(h, raw, validScanOKBody); rec.Code != http.StatusOK {
		t.Fatalf("seed scan: status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	return h, raw
}

// boundsAssertRefused checks a 400 whose body contains every want
// string, and that the seed's one snapshot and one open finding are all
// that is stored.
func boundsAssertRefused(t *testing.T, database *db.DB, rec *httptest.ResponseRecorder, want ...string) {
	t.Helper()
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %.200q)", rec.Code, rec.Body.String())
	}
	for _, w := range want {
		if !strings.Contains(rec.Body.String(), w) {
			t.Errorf("body %q does not contain %q", rec.Body.String(), w)
		}
	}
	if n := len(listScans(t, database)); n != 1 {
		t.Errorf("got %d scan snapshots after a refusal, want only the seed's 1", n)
	}
	fs := listFindingsFor(t, database, "canary-a")
	if len(fs) != 1 || fs[0].VulnerabilityID != "CVE-2014-0160" || fs[0].State != store.FindingOpen {
		t.Errorf("previous findings changed by a refused scan: %+v", fs)
	}
}

func TestHandleScanRefusesTooManyFindings(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		h, raw := boundsSeed(t, database, time.Now)
		findings := make([]map[string]any, boundsMaxFindings+1)
		for i := range findings {
			findings[i] = boundsFinding(i)
		}
		rec := boundsPost(h, raw, boundsScanBody(t, findings, nil))
		boundsAssertRefused(t, database, rec, "findings", "10000")
	})
}

func TestHandleScanRefusesFindingFieldOneByteOver(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		h, raw := boundsSeed(t, database, time.Now)
		for field, limit := range boundsFieldLimits {
			f := boundsFinding(1)
			f[field] = strings.Repeat("a", limit+1)
			rec := boundsPost(h, raw, boundsScanBody(t, []map[string]any{f}, nil))
			boundsAssertRefused(t, database, rec, field, fmt.Sprint(limit))
		}
	})
}

func TestHandleScanRefusesTooManyMaskedPaths(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		h, raw := boundsSeed(t, database, time.Now)
		paths := make([]string, boundsMaxMasked+1)
		for i := range paths {
			paths[i] = fmt.Sprintf("/p%d", i)
		}
		rec := boundsPost(h, raw, boundsScanBody(t, nil, paths))
		boundsAssertRefused(t, database, rec, "masked_paths")
	})
}

func TestHandleScanRefusesOverlongMaskedPath(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		h, raw := boundsSeed(t, database, time.Now)
		long := "/" + strings.Repeat("a", boundsMaxMaskedLen) // 4097 bytes
		rec := boundsPost(h, raw, boundsScanBody(t, nil, []string{long}))
		boundsAssertRefused(t, database, rec, "masked_paths")
	})
}

// TestHandleScanAcceptsEveryBoundExactly: 100 findings with every field
// at its exact limit, and 256 masked paths of exactly 4096 bytes, are
// accepted and stored.
func TestHandleScanAcceptsEveryBoundExactly(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		findings := make([]map[string]any, 100)
		for i := range findings {
			f := map[string]any{}
			for field, limit := range boundsFieldLimits {
				f[field] = strings.Repeat("a", limit)
			}
			// Distinct identity per finding, still exactly at the limit.
			f["vulnerability"] = fmt.Sprintf("%0128d", i)
			findings[i] = f
		}
		paths := make([]string, boundsMaxMasked)
		for i := range paths {
			paths[i] = fmt.Sprintf("/%0*d", boundsMaxMaskedLen-1, i)
		}
		rec := boundsPost(h, raw, boundsScanBody(t, findings, paths))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %.200q)", rec.Code, rec.Body.String())
		}
		if n := len(listFindingsFor(t, database, "canary-a")); n != 100 {
			t.Errorf("stored %d findings, want 100", n)
		}
		s := listScans(t, database)
		if len(s) != 1 || len(s[0].MaskedPaths) != boundsMaxMasked {
			t.Errorf("snapshot masked paths not stored intact: %+v", s)
		}
	})
}

// TestHandleScanAcceptsExactlyMaxFindings: the cap is on "more than".
func TestHandleScanAcceptsExactlyMaxFindings(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)
		findings := make([]map[string]any, boundsMaxFindings)
		for i := range findings {
			findings[i] = boundsFinding(i)
		}
		if rec := boundsPost(h, raw, boundsScanBody(t, findings, nil)); rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %.200q)", rec.Code, rec.Body.String())
		}
	})
}

// TestHandleScanRefusalWritesOneCoalescedAuditRow: refusals go through
// the audit coalescer keyed on (canary, action), like
// recordSelfTestAudit's other callers: the first writes a row, later
// ones inside auditCoalesceInterval are counted, not written -- whatever
// bound they broke.
func TestHandleScanRefusalWritesOneCoalescedAuditRow(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		fixed := mustParseTime(t, "2026-01-05T00:00:00Z")
		h, raw := boundsSeed(t, database, func() time.Time { return fixed })
		if n := countAuditRows(t, database, "scan.refused_oversize", "canary-a"); n != 0 {
			t.Fatalf("audit rows before any refusal = %d, want 0", n)
		}

		f := boundsFinding(1)
		f["package"] = strings.Repeat("a", 257)
		bodies := []string{
			boundsScanBody(t, []map[string]any{f}, nil),
			boundsScanBody(t, nil, []string{"/" + strings.Repeat("a", boundsMaxMaskedLen)}),
			boundsScanBody(t, []map[string]any{f}, nil),
		}
		for i, b := range bodies {
			if rec := boundsPost(h, raw, b); rec.Code != http.StatusBadRequest {
				t.Fatalf("refusal %d: status = %d, want 400", i, rec.Code)
			}
		}
		if n := countAuditRows(t, database, "scan.refused_oversize", "canary-a"); n != 1 {
			t.Errorf("scan.refused_oversize rows after 3 refusals in one burst = %d, want 1", n)
		}
	})
}

// TestHandleScanOtherRefusalsWriteNoOversizeAudit: a plain validation
// failure is not an oversize refusal.
func TestHandleScanOtherRefusalsWriteNoOversizeAudit(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		h, raw := boundsSeed(t, database, time.Now)
		f := boundsFinding(1)
		f["package"] = ""
		if rec := boundsPost(h, raw, boundsScanBody(t, []map[string]any{f}, nil)); rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if n := countAuditRows(t, database, "scan.refused_oversize", "canary-a"); n != 0 {
			t.Errorf("scan.refused_oversize rows = %d, want 0", n)
		}
	})
}

// TestHandleScanRealisticLargeScanIsStored: 9,999 realistic findings
// (about 200 bytes each) fit the 4 MiB body cap and the count cap: 200,
// all stored; posting the identical snapshot again only moves last_seen.
func TestHandleScanRealisticLargeScanIsStored(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		clock := stepClock(mustParseTime(t, "2026-01-01T00:00:00Z"))
		h := newHandler(database, nil, clock, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		findings := make([]map[string]any, 9999)
		for i := range findings {
			findings[i] = boundsFinding(i)
		}
		body := boundsScanBody(t, findings, []string{"/etc/shadow", "/root"})
		if len(body) >= scanMaxBodyBytes {
			t.Fatalf("test body is %d bytes, not under the %d byte cap", len(body), scanMaxBodyBytes)
		}

		if rec := boundsPost(h, raw, body); rec.Code != http.StatusOK {
			t.Fatalf("first post: status = %d, want 200 (body %.200q)", rec.Code, rec.Body.String())
		}
		first := listFindingsFor(t, database, "canary-a")
		if len(first) != 9999 {
			t.Fatalf("stored %d findings, want 9999", len(first))
		}

		if rec := boundsPost(h, raw, body); rec.Code != http.StatusOK {
			t.Fatalf("second post: status = %d, want 200 (body %.200q)", rec.Code, rec.Body.String())
		}
		second := listFindingsFor(t, database, "canary-a")
		if len(second) != 9999 {
			t.Fatalf("after an identical rescan: %d findings, want still 9999", len(second))
		}
		byID := make(map[int64]store.Finding, len(first))
		for _, f := range first {
			byID[f.ID] = f
		}
		for _, f := range second {
			old, ok := byID[f.ID]
			if !ok {
				t.Fatalf("finding %d is new after an identical rescan", f.ID)
			}
			if f.State != store.FindingOpen || !f.FirstSeen.Equal(old.FirstSeen) || !f.LastSeen.After(old.LastSeen) {
				t.Fatalf("rescan changed more than last_seen: before %+v after %+v", old, f)
			}
		}
	})
}
