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
	seedRetentionAndPostBody(t, database, retentionBody(), opts...)
}

func seedRetentionAndPostBody(t *testing.T, database *db.DB, body string, opts ...Option) {
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
	if rec := boundsPost(h, raw, body); rec.Code != http.StatusOK {
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

// ---- Review fixes (issue #213 notes 63369 and 63709) ----

const retentionFailedBody = `{"taken_at": "` + retentionNowText + `", "status": "failed", "reason": "scan could not run", "findings": [], "masked_paths": []}`

// A failed scan prunes too: old fixed findings and old snapshots go, the
// agent's newest old ok snapshot stays, with the failed scan just stored.
func TestScanIngestFailedScanPrunes(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		seedRetentionAndPostBody(t, database, retentionFailedBody, WithFindingsRetentionDays(90))
		if n := fixedFindingCount(t, database); n != 0 {
			t.Errorf("fixed findings = %d, want 0 (pruning runs after a failed scan)", n)
		}
		snaps := listScans(t, database)
		if len(snaps) != 2 {
			t.Fatalf("snapshots = %d, want 2 (newest old ok, and the failed one just received)", len(snaps))
		}
		var okKept, failedKept bool
		for _, s := range snaps {
			okKept = okKept || s.Status == store.ScanStatusOK
			failedKept = failedKept || s.Status == store.ScanStatusFailed
		}
		if !okKept || !failedKept {
			t.Errorf("snapshots = %+v, want one ok and one failed", snaps)
		}
		if n := auditCount(t, database, store.AuditActionRetentionPruned, "canary-a"); n != 1 {
			t.Errorf("%s audit rows = %d, want 1", store.AuditActionRetentionPruned, n)
		}
	})
}

// An agent that has sent only failed scans past the window keeps its
// last ok scan through ingest.
func TestScanIngestKeepsLastOKScanWhenOnlyFailuresFollow(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		raw := mintToken(t, database, "canary-a")
		now, _ := time.Parse(time.RFC3339, retentionNowText)
		old := now.AddDate(0, 0, -151)
		okAt := old
		ctx := context.Background()
		seed := func(status string, at time.Time) {
			s := store.ScanSnapshot{CanaryID: "canary-a", TakenAt: at, ReceivedAt: at, Status: status}
			if status == store.ScanStatusOK {
				s.EngineName, s.EngineVersion = "grype", "v0.119.0"
			} else {
				s.Reason = "scan could not run"
			}
			if err := store.RecordScanSnapshot(ctx, database, s); err != nil {
				t.Fatalf("seed %s: %v", status, err)
			}
		}
		seed(store.ScanStatusOK, okAt)
		seed(store.ScanStatusFailed, old.Add(24*time.Hour))
		seed(store.ScanStatusFailed, old.Add(48*time.Hour))
		h := newHandler(database, nil, func() time.Time { return now }, defaultLimiterLimits, store.NewSelfTestIndex(), nil, WithFindingsRetentionDays(90))
		if rec := boundsPost(h, raw, retentionFailedBody); rec.Code != http.StatusOK {
			t.Fatalf("scan: status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
		}
		st, err := store.FindingsStaleness(ctx, database, "canary-a")
		if err != nil {
			t.Fatalf("FindingsStaleness: %v", err)
		}
		s := st["canary-a"]
		if s.LastOKScan == nil || !s.LastOKScan.Equal(okAt) {
			t.Errorf("LastOKScan = %v, want %v (the last ok scan must survive pruning)", s.LastOKScan, okAt)
		}
		if !s.Stale {
			t.Error("Stale = false, want true (latest scan failed)")
		}
		if n := len(listScans(t, database)); n != 2 {
			t.Errorf("snapshots = %d, want 2 (the old ok one and the new failed one)", n)
		}
	})
}

// One unparseable received_at row must not make the scan fail: the scan
// is answered 200 and stored.
func TestScanIngestSurvivesUnparseableReceivedAtRow(t *testing.T) {
	for _, bad := range []string{"2020-13-45T99:00:00Z", "not-a-time"} {
		t.Run(bad, func(t *testing.T) {
			forEachEngine(t, func(t *testing.T, database *db.DB) {
				enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
				raw := mintToken(t, database, "canary-a")
				now, _ := time.Parse(time.RFC3339, retentionNowText)
				old := now.AddDate(0, 0, -151)
				ctx := context.Background()
				for i := 0; i < 3; i++ {
					at := old.Add(time.Duration(i) * time.Hour)
					if err := store.RecordScanSnapshot(ctx, database, store.ScanSnapshot{
						CanaryID: "canary-a", TakenAt: at, ReceivedAt: at,
						EngineName: "grype", EngineVersion: "v0.119.0", Status: store.ScanStatusOK,
					}); err != nil {
						t.Fatalf("seed: %v", err)
					}
				}
				if _, err := database.ExecContext(ctx, `UPDATE scan_snapshots SET received_at = ? WHERE agent_id = 'canary-a' AND received_at = ?`,
					bad, old.Add(2*time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
					t.Fatalf("corrupt received_at: %v", err)
				}
				h := newHandler(database, nil, func() time.Time { return now }, defaultLimiterLimits, store.NewSelfTestIndex(), nil, WithFindingsRetentionDays(90))
				rec := boundsPost(h, raw, retentionBody())
				if rec.Code != http.StatusOK {
					t.Fatalf("scan: status = %d, want 200 (a bad old row must not block ingest; body %q)", rec.Code, rec.Body.String())
				}
				var n int
				if err := database.QueryRow(`SELECT COUNT(*) FROM scan_snapshots WHERE agent_id = 'canary-a' AND taken_at = ?`,
					now.UTC().Format(time.RFC3339Nano)).Scan(&n); err != nil {
					t.Fatal(err)
				}
				if n != 1 {
					t.Errorf("stored scans for the new taken_at = %d, want 1", n)
				}
			})
		})
	}
}
