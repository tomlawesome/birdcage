package ingest

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// Issue #213 (retention): a scan ingest removes the agent's fixed
// findings and scan snapshots older than the retention window, using
// the handler's own clock. The window is set with
// WithFindingsRetentionDays(n); with no option it is 90 days, and 0
// means keep for good.

const retentionNowText = "2026-06-01T00:00:00Z"

func retentionBody() string {
	return strings.Replace(validScanOKBody, `"taken_at": "2026-01-02T00:00:00Z"`, `"taken_at": "`+retentionNowText+`"`, 1)
}

// seedRetentionAndPost enrols canary-a with two old snapshots and three old
// fixed findings, then posts one scan at the handler's clock.
func seedRetentionAndPost(t *testing.T, database *db.DB, opts ...Option) {
	t.Helper()
	enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
	raw := mintToken(t, database, "canary-a")
	now, err := time.Parse(time.RFC3339, retentionNowText)
	if err != nil {
		t.Fatal(err)
	}
	old := now.AddDate(0, 0, -151)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		at := old.Add(time.Duration(i) * time.Hour)
		if err := store.RecordScanSnapshot(ctx, database, store.ScanSnapshot{
			CanaryID: "canary-a", TakenAt: at, ReceivedAt: at,
			EngineName: "grype", EngineVersion: "v0.119.0", Status: store.ScanStatusOK,
		}); err != nil {
			t.Fatalf("seed snapshot: %v", err)
		}
	}
	ts := old.UTC().Format("2006-01-02T15:04:05.000000000Z")
	for _, v := range []string{"CVE-OLD-1", "CVE-OLD-2", "CVE-OLD-3"} {
		if _, err := database.ExecContext(ctx, `
			INSERT INTO findings (agent_id, target, vulnerability_id, severity, installed_version, fixing_version, first_seen, last_seen, state)
			VALUES ('canary-a', 'deb:pkg', ?, 'high', '1', '', ?, ?, 'fixed')`, v, ts, ts); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
	}
	h := newHandler(database, nil, func() time.Time { return now }, defaultLimiterLimits, store.NewSelfTestIndex(), nil, opts...)
	if rec := boundsPost(h, raw, retentionBody()); rec.Code != http.StatusOK {
		t.Fatalf("scan: status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
}

func fixedFindingCount(t *testing.T, database *db.DB) int {
	t.Helper()
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM findings WHERE agent_id = 'canary-a' AND state = 'fixed'`).Scan(&n); err != nil {
		t.Fatalf("count fixed: %v", err)
	}
	return n
}

func TestScanIngestRemovesOldFixedFindingsAndSnapshots(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		seedRetentionAndPost(t, database, WithFindingsRetentionDays(90))
		if n := fixedFindingCount(t, database); n != 0 {
			t.Errorf("fixed findings = %d, want 0 (all older than 90 days)", n)
		}
		if n := len(listScans(t, database)); n != 1 {
			t.Errorf("snapshots = %d, want 1 (just the one just received)", n)
		}
		if n := auditCount(t, database, store.AuditActionRetentionPruned, "canary-a"); n != 1 {
			t.Errorf("%s audit rows = %d, want 1", store.AuditActionRetentionPruned, n)
		}
	})
}

func TestScanIngestDefaultRetentionIs90Days(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		seedRetentionAndPost(t, database) // no option
		if n := fixedFindingCount(t, database); n != 0 {
			t.Errorf("fixed findings = %d, want 0 (default window is 90 days)", n)
		}
	})
}

func TestScanIngestRetentionZeroRemovesNothingByAge(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		seedRetentionAndPost(t, database, WithFindingsRetentionDays(0))
		if n := fixedFindingCount(t, database); n != 3 {
			t.Errorf("fixed findings = %d, want 3 (0 keeps for good)", n)
		}
		if n := len(listScans(t, database)); n != 3 {
			t.Errorf("snapshots = %d, want 3", n)
		}
		if n := auditCount(t, database, store.AuditActionRetentionPruned, "canary-a"); n != 0 {
			t.Errorf("%s audit rows = %d, want 0", store.AuditActionRetentionPruned, n)
		}
	})
}
