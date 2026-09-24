package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/hostmask"
	"github.com/tomlawesome/birdcage/internal/store"
)

// Issue #116 (ADR-0012): the ingest half of the scanner proof -- the
// scan command on /ingest/commands, stage and database-refresh reports
// on the scanner heartbeat, and the run_id answer on /ingest/scans.

var proofT0 = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

type proofFixture struct {
	database *db.DB
	h        http.Handler
	now      time.Time
}

func (f *proofFixture) clock() time.Time { return f.now }

func newProofFixture(t *testing.T, database *db.DB) *proofFixture {
	t.Helper()
	f := &proofFixture{database: database, now: proofT0}
	f.h = newHandler(database, nil, f.clock, defaultLimiterLimits, store.NewSelfTestIndex(), nil)
	return f
}

// pendingScanner registers a pending scanner and returns its token.
func pendingScanner(t *testing.T, database *db.DB, id string) string {
	t.Helper()
	if err := store.InsertCanary(context.Background(), database, store.Canary{
		ID: id, Name: id, Lane: "lan", Kind: agentkind.Scanner, EnrolledAt: proofT0.Add(-time.Hour), Pending: true,
	}); err != nil {
		t.Fatalf("InsertCanary(%s): %v", id, err)
	}
	return mintTokenForKind(t, database, id, agentkind.Scanner)
}

func mintProofRun(t *testing.T, database *db.DB, id string, at time.Time) (store.CanaryCommand, string) {
	t.Helper()
	cmd, err := store.MintScanCommand(context.Background(), database, id, store.TriggerProof, at, at.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("MintScanCommand(%s): %v", id, err)
	}
	var params store.ScanParams
	if err := json.Unmarshal([]byte(cmd.Params), &params); err != nil {
		t.Fatalf("scan params: %v", err)
	}
	return cmd, params.RunID
}

func (f *proofFixture) post(t *testing.T, path, token, body string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, ingestRequest(http.MethodPost, path, token, body))
	return rec.Code, rec.Body.String()
}

func runStage(t *testing.T, database *db.DB, commandID string) (stage string, completed bool, passed *int64) {
	t.Helper()
	var completedAt *string
	if err := database.QueryRow(`SELECT stage, completed_at, passed FROM self_test_runs WHERE command_id = ?`, commandID).
		Scan(&stage, &completedAt, &passed); err != nil {
		t.Fatalf("read run: %v", err)
	}
	return stage, completedAt != nil, passed
}

func isRegistered(t *testing.T, database *db.DB, id string) bool {
	t.Helper()
	var at *string
	if err := database.QueryRow(`SELECT registered_at FROM canaries WHERE id = ?`, id).Scan(&at); err != nil {
		t.Fatalf("read registered_at: %v", err)
	}
	return at != nil
}

// auditMentions reports whether any audit_log row mentions s anywhere.
func auditMentions(t *testing.T, database *db.DB, s string) bool {
	t.Helper()
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE reason LIKE ? OR target LIKE ?`, "%"+s+"%", "%"+s+"%").Scan(&n); err != nil {
		t.Fatalf("search audit_log: %v", err)
	}
	return n > 0
}

func proofScanBody(runID string, issued time.Time, mutate func(m map[string]any)) string {
	taken := issued.Add(2 * time.Minute)
	m := map[string]any{
		"taken_at": taken.Format(time.RFC3339),
		"engine": map[string]any{
			"name": "grype", "version": "v0.119.0",
			"db_built_at":     taken.Add(-6 * time.Hour).Format(time.RFC3339),
			"db_refreshed_at": issued.Add(time.Minute).Format(time.RFC3339),
		},
		"status":       "ok",
		"findings":     []any{},
		"masked_paths": hostmask.Paths(),
	}
	if runID != "" {
		m["run_id"] = runID
	}
	if mutate != nil {
		mutate(m)
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func TestScannerClaimsScanCommandAndRunIsCollected(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newProofFixture(t, database)
		raw := pendingScanner(t, database, "scan-a")
		cmd, runID := mintProofRun(t, database, "scan-a", proofT0)
		f.now = proofT0.Add(time.Minute)

		code, got := pollCommands(t, f.h, raw, "")
		if code != http.StatusOK || got == nil {
			t.Fatalf("poll = %d %v, want the scan command", code, got)
		}
		params, _ := got["params"].(map[string]any)
		if got["id"] != cmd.ID || got["kind"] != "scan" || params["run_id"] != runID || len(params) != 1 || got["expires_at"] == nil {
			t.Errorf("command = %v, want {id, kind scan, params {run_id}, expires_at}", got)
		}
		if stage, _, _ := runStage(t, database, cmd.ID); stage != "collected" {
			t.Errorf("stage after claim = %q, want collected", stage)
		}
	})
}

// TestCommandKindAllowList: each kind claims only its own command kinds;
// a wrongly queued command is never delivered.
func TestCommandKindAllowList(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newProofFixture(t, database)
		scanner := pendingScanner(t, database, "scan-a")
		mintSelfTest(t, database, "scan-a", proofT0, time.Hour)
		honeypot := mintToken(t, database, "hp-a")
		if _, err := store.MintCanaryCommand(context.Background(), database, "hp-a", store.CommandScan, `{"run_id":"x"}`, proofT0, proofT0.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		f.now = proofT0.Add(time.Minute)

		if code, got := pollCommands(t, f.h, scanner, ""); code != http.StatusOK || got != nil {
			t.Errorf("scanner poll with only a selftest queued = %d %v, want 200 null", code, got)
		}
		if code, got := pollCommands(t, f.h, honeypot, ""); code != http.StatusOK || got != nil {
			t.Errorf("honeypot poll with only a scan queued = %d %v, want 200 null", code, got)
		}
		var undelivered int
		if err := database.QueryRow(`SELECT COUNT(*) FROM canary_commands WHERE delivered_at IS NULL`).Scan(&undelivered); err != nil {
			t.Fatal(err)
		}
		if undelivered != 2 {
			t.Errorf("undelivered commands = %d, want 2 (neither handed over)", undelivered)
		}
		if got := commandKindsFor(agentkind.Kind("bogus")); got == nil || len(got) != 0 {
			t.Errorf("commandKindsFor(unknown) = %v, want an empty non-nil set", got)
		}
	})
}

func TestScannerHeartbeatAdvancesStage(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newProofFixture(t, database)
		raw := pendingScanner(t, database, "scan-a")
		cmd, runID := mintProofRun(t, database, "scan-a", proofT0)
		for i, stage := range []string{"mounts_checked", "db_refreshed", "db_refreshed", "scanning"} {
			f.now = proofT0.Add(time.Duration(i+1) * time.Minute)
			body := fmt.Sprintf(`{"agent_version":"1.0.0","run":{"run_id":%q,"stage":%q}}`, runID, stage)
			if code, resp := f.post(t, "/ingest/heartbeat", raw, body); code != http.StatusOK {
				t.Fatalf("heartbeat %s = %d %s", stage, code, resp)
			}
		}
		if stage, _, _ := runStage(t, database, cmd.ID); stage != "scanning" {
			t.Errorf("stage = %q, want scanning", stage)
		}
		if n := countAuditRows(t, database, "selftest.stage_stale", "scan-a"); n != 0 {
			t.Errorf("stage_stale audits = %d, want 0 (a repeated stage is not stale)", n)
		}
	})
}

func TestScannerHeartbeatStaleStageIgnoredAndAudited(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newProofFixture(t, database)
		rawA := pendingScanner(t, database, "scan-a")
		rawB := pendingScanner(t, database, "scan-b")
		cmd, runID := mintProofRun(t, database, "scan-a", proofT0)
		f.now = proofT0.Add(time.Minute)

		// Another node's run: ignored, audited against the reporter, 200.
		body := fmt.Sprintf(`{"run":{"run_id":%q,"stage":"scanning"}}`, runID)
		if code, resp := f.post(t, "/ingest/heartbeat", rawB, body); code != http.StatusOK {
			t.Fatalf("heartbeat = %d %s", code, resp)
		}
		if stage, _, _ := runStage(t, database, cmd.ID); stage != "ordered" {
			t.Errorf("stage = %q, want ordered (another node cannot move it)", stage)
		}
		if n := countAuditRows(t, database, "selftest.stage_stale", "scan-b"); n != 1 {
			t.Errorf("stage_stale audits for scan-b = %d, want 1", n)
		}
		// Backwards on its own run.
		f.post(t, "/ingest/heartbeat", rawA, fmt.Sprintf(`{"run":{"run_id":%q,"stage":"scanning"}}`, runID))
		f.now = proofT0.Add(3 * time.Minute)
		f.post(t, "/ingest/heartbeat", rawA, fmt.Sprintf(`{"run":{"run_id":%q,"stage":"mounts_checked"}}`, runID))
		if stage, _, _ := runStage(t, database, cmd.ID); stage != "scanning" {
			t.Errorf("stage = %q, want scanning (forward only)", stage)
		}
		if n := countAuditRows(t, database, "selftest.stage_stale", "scan-a"); n != 1 {
			t.Errorf("stage_stale audits for scan-a = %d, want 1", n)
		}
		if auditMentions(t, database, runID) {
			t.Error("a run id reached the audit log")
		}
	})
}

func TestHeartbeatRunAndDBRefreshValidation(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newProofFixture(t, database)
		scanner := pendingScanner(t, database, "scan-a")
		honeypot := mintToken(t, database, "hp-a")
		cases := []struct {
			name, token, body string
		}{
			{"honeypot run", honeypot, `{"queue_depth":0,"log_read_ok":true,"run":{"run_id":"r","stage":"scanning"}}`},
			{"honeypot db_refresh", honeypot, `{"queue_depth":0,"log_read_ok":true,"db_refresh":{"last_ok_at":null,"failing_since":null,"last_error":""}}`},
			{"unknown stage", scanner, `{"run":{"run_id":"r","stage":"exploded"}}`},
			{"server stage", scanner, `{"run":{"run_id":"r","stage":"answered"}}`},
			{"empty run id", scanner, `{"run":{"run_id":"","stage":"scanning"}}`},
			{"unknown run field", scanner, `{"run":{"run_id":"r","stage":"scanning","extra":1}}`},
			{"bad failing_since", scanner, `{"db_refresh":{"failing_since":"yesterday","last_error":"x"}}`},
			{"bad last_ok_at", scanner, `{"db_refresh":{"last_ok_at":"soon","failing_since":null,"last_error":""}}`},
		}
		for _, tc := range cases {
			if code, resp := f.post(t, "/ingest/heartbeat", tc.token, tc.body); code != http.StatusBadRequest {
				t.Errorf("%s: status = %d (%s), want 400", tc.name, code, resp)
			}
		}
		var beats int
		if err := database.QueryRow(`SELECT COUNT(*) FROM heartbeats WHERE canary_id = 'scan-a'`).Scan(&beats); err != nil {
			t.Fatal(err)
		}
		if beats != 0 {
			t.Errorf("refused heartbeats recorded %d beats, want 0", beats)
		}
	})
}

// TestHeartbeatDBRefreshUsesBirdcagesClock: failing_since is birdcage's
// first failing report, whatever the agent claims; a heartbeat without
// the field clears it.
func TestHeartbeatDBRefreshUsesBirdcagesClock(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newProofFixture(t, database)
		raw := pendingScanner(t, database, "scan-a")
		failing := func(agentSince string) string {
			return fmt.Sprintf(`{"db_refresh":{"last_ok_at":null,"failing_since":%q,"last_error":"mirror unreachable"}}`, agentSince)
		}
		read := func() (*string, *string) {
			var since, msg *string
			if err := database.QueryRow(`SELECT db_refresh_failing_since, db_refresh_error FROM canaries WHERE id = 'scan-a'`).Scan(&since, &msg); err != nil {
				t.Fatal(err)
			}
			return since, msg
		}

		// The agent claims three days of failure; birdcage counts from now.
		if code, resp := f.post(t, "/ingest/heartbeat", raw, failing(proofT0.Add(-72*time.Hour).Format(time.RFC3339))); code != http.StatusOK {
			t.Fatalf("heartbeat = %d %s", code, resp)
		}
		since, msg := read()
		if since == nil || !mustParseTime(t, *since).Equal(proofT0) || msg == nil || *msg != "mirror unreachable" {
			t.Fatalf("failing_since/error = %v/%v, want birdcage's t0 and the error", since, msg)
		}
		f.now = proofT0.Add(time.Hour)
		f.post(t, "/ingest/heartbeat", raw, failing(proofT0.Format(time.RFC3339)))
		if since, _ := read(); since == nil || !mustParseTime(t, *since).Equal(proofT0) {
			t.Errorf("failing_since moved to %v, want it kept at t0", since)
		}
		// null failing_since is not failing.
		f.post(t, "/ingest/heartbeat", raw, `{"db_refresh":{"last_ok_at":null,"failing_since":null,"last_error":""}}`)
		if since, _ := read(); since != nil {
			t.Errorf("failing_since = %v after a non-failing report, want cleared", *since)
		}
		f.post(t, "/ingest/heartbeat", raw, failing(proofT0.Format(time.RFC3339)))
		f.post(t, "/ingest/heartbeat", raw, `{"agent_version":"1.0.0"}`)
		if since, msg := read(); since != nil || msg != nil {
			t.Errorf("after a heartbeat without db_refresh: %v/%v, want cleared", since, msg)
		}
	})
}

func TestScanAnswerPassesAndSettlesPending(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newProofFixture(t, database)
		raw := pendingScanner(t, database, "scan-a")
		cmd, runID := mintProofRun(t, database, "scan-a", proofT0)
		f.now = proofT0.Add(5 * time.Minute)
		if code, resp := f.post(t, "/ingest/scans", raw, proofScanBody(runID, proofT0, nil)); code != http.StatusOK {
			t.Fatalf("scan = %d %s", code, resp)
		}
		stage, completed, passed := runStage(t, database, cmd.ID)
		if stage != "answered" || !completed || passed == nil || *passed != 1 {
			t.Errorf("run = %s/%v/%v, want answered, completed, passed", stage, completed, passed)
		}
		if !isRegistered(t, database, "scan-a") {
			t.Error("passing proof did not register the scanner")
		}
		snaps := listScans(t, database)
		if len(snaps) != 1 || snaps[0].SelfTestRunID != cmd.ID || snaps[0].DBRefreshedAt == nil {
			t.Fatalf("snapshots = %+v, want one linked to the run with db_refreshed_at", snaps)
		}
		// The same answer again: stored, stale, audited.
		f.now = proofT0.Add(6 * time.Minute)
		if code, resp := f.post(t, "/ingest/scans", raw, proofScanBody(runID, proofT0, nil)); code != http.StatusOK {
			t.Fatalf("replay = %d %s", code, resp)
		}
		if n := len(listScans(t, database)); n != 2 {
			t.Errorf("snapshots after replay = %d, want 2 (a spent run's answer is still stored)", n)
		}
		if n := countAuditRows(t, database, "selftest.run_stale", "scan-a"); n != 1 {
			t.Errorf("run_stale audits = %d, want 1", n)
		}
		if auditMentions(t, database, runID) {
			t.Error("a run id reached the audit log")
		}
	})
}

// TestScanAnswerUnknownRunRefused: another node's run, or none, is a 400
// with nothing stored.
func TestScanAnswerUnknownRunRefused(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newProofFixture(t, database)
		pendingScanner(t, database, "scan-a")
		rawB := pendingScanner(t, database, "scan-b")
		cmd, runID := mintProofRun(t, database, "scan-a", proofT0)
		f.now = proofT0.Add(5 * time.Minute)
		for _, id := range []string{runID, "not-a-run", strings.Repeat("a", 200)} {
			code, resp := f.post(t, "/ingest/scans", rawB, proofScanBody(id, proofT0, nil))
			if code != http.StatusBadRequest || !strings.Contains(resp, "unknown run") {
				t.Errorf("run %.10s: %d %s, want 400 unknown run", id, code, resp)
			}
		}
		if n := len(listScans(t, database)); n != 0 {
			t.Errorf("snapshots stored = %d, want 0", n)
		}
		if _, completed, _ := runStage(t, database, cmd.ID); completed {
			t.Error("another node's answer completed the run")
		}
		if n := countAuditRows(t, database, "selftest.run_unknown", "scan-b"); n != 1 {
			t.Errorf("run_unknown audits = %d, want 1 (coalesced)", n)
		}
	})
}

func TestScanAnswerFailuresFailTheRun(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(m map[string]any)
		reason string
	}{
		{"failed status", func(m map[string]any) {
			m["status"], m["reason"] = "failed", "mask check failed"
		}, "scan_failed: mask check failed"},
		{"refresh not fresh", func(m map[string]any) {
			e := m["engine"].(map[string]any)
			e["db_refreshed_at"] = proofT0.Add(-time.Hour).Format(time.RFC3339)
			e["db_refresh_error"] = "mirror unreachable"
		}, store.ReasonDBRefreshFailed},
		{"taken before issued", func(m map[string]any) {
			m["taken_at"] = proofT0.Add(-time.Minute).Format(time.RFC3339)
		}, store.ReasonTakenBeforeIssued},
		{"masks incomplete", func(m map[string]any) {
			m["masked_paths"] = []string{"/etc/shadow"}
		}, store.ReasonMasksIncomplete},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forEachEngine(t, func(t *testing.T, database *db.DB) {
				f := newProofFixture(t, database)
				raw := pendingScanner(t, database, "scan-a")
				cmd, runID := mintProofRun(t, database, "scan-a", proofT0)
				f.now = proofT0.Add(5 * time.Minute)
				if code, resp := f.post(t, "/ingest/scans", raw, proofScanBody(runID, proofT0, tc.mutate)); code != http.StatusOK {
					t.Fatalf("scan = %d %s", code, resp)
				}
				stage, completed, passed := runStage(t, database, cmd.ID)
				if stage != "answered" || !completed || passed == nil || *passed != 0 {
					t.Errorf("run = %s/%v/%v, want answered, completed, failed", stage, completed, passed)
				}
				var reason string
				if err := database.QueryRow(`SELECT reason FROM self_test_runs WHERE command_id = ?`, cmd.ID).Scan(&reason); err != nil || reason != tc.reason {
					t.Errorf("reason = %q (%v), want %q", reason, err, tc.reason)
				}
				if isRegistered(t, database, "scan-a") {
					t.Error("a failed answer registered the scanner")
				}
				if n := len(listScans(t, database)); n != 1 {
					t.Errorf("snapshots = %d, want 1 (stored, not a pass)", n)
				}
			})
		})
	}
}

// TestScanOldDatabaseIsNeverOK is the server-side five-day backstop on
// every snapshot, timer or ordered.
func TestScanOldDatabaseIsNeverOK(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newProofFixture(t, database)
		raw := pendingScanner(t, database, "scan-a")
		f.now = proofT0.Add(5 * time.Minute)
		old := func(m map[string]any) {
			m["engine"].(map[string]any)["db_built_at"] = proofT0.Add(-6 * 24 * time.Hour).Format(time.RFC3339)
			m["findings"] = []map[string]string{{"target": "dir:/host", "package": "p", "version": "1", "type": "deb", "vulnerability": "CVE-1", "severity": "low"}}
		}
		if code, resp := f.post(t, "/ingest/scans", raw, proofScanBody("", proofT0, old)); code != http.StatusOK {
			t.Fatalf("scan = %d %s", code, resp)
		}
		snaps := listScans(t, database)
		if len(snaps) != 1 || snaps[0].Status != store.ScanStatusFailed || !strings.HasPrefix(snaps[0].Reason, store.ReasonDBTooOld) || snaps[0].FindingCount != 0 {
			t.Fatalf("snapshot = %+v, want stored as failed db_too_old", snaps)
		}

		cmd, runID := mintProofRun(t, database, "scan-a", proofT0)
		if code, resp := f.post(t, "/ingest/scans", raw, proofScanBody(runID, proofT0, old)); code != http.StatusOK {
			t.Fatalf("ordered scan = %d %s", code, resp)
		}
		if _, _, passed := runStage(t, database, cmd.ID); passed == nil || *passed != 0 {
			t.Errorf("run passed = %v, want failed", passed)
		}
	})
}

// TestScanDBRefreshStateFromSnapshot: a snapshot carrying a refresh
// error marks the node failing; an ok snapshot with a clean refresh
// clears it.
func TestScanDBRefreshStateFromSnapshot(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newProofFixture(t, database)
		raw := pendingScanner(t, database, "scan-a")
		f.now = proofT0.Add(5 * time.Minute)
		withError := func(m map[string]any) {
			m["engine"].(map[string]any)["db_refresh_error"] = "mirror unreachable"
		}
		f.post(t, "/ingest/scans", raw, proofScanBody("", proofT0, withError))
		var since *string
		if err := database.QueryRow(`SELECT db_refresh_failing_since FROM canaries WHERE id = 'scan-a'`).Scan(&since); err != nil {
			t.Fatal(err)
		}
		if since == nil || !mustParseTime(t, *since).Equal(f.now) {
			t.Fatalf("failing_since = %v, want birdcage's now", since)
		}
		if snaps := listScans(t, database); snaps[0].Status != store.ScanStatusOK || snaps[0].DBRefreshError != "mirror unreachable" {
			t.Errorf("snapshot = %+v, want ok carrying the refresh error", snaps[0])
		}
		f.now = proofT0.Add(time.Hour)
		f.post(t, "/ingest/scans", raw, proofScanBody("", proofT0.Add(50*time.Minute), nil))
		if err := database.QueryRow(`SELECT db_refresh_failing_since FROM canaries WHERE id = 'scan-a'`).Scan(&since); err != nil {
			t.Fatal(err)
		}
		if since != nil {
			t.Errorf("failing_since = %s after a clean refresh, want cleared", *since)
		}
	})
}

func TestScanRejectsBadRefreshTimestamp(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newProofFixture(t, database)
		raw := pendingScanner(t, database, "scan-a")
		body := proofScanBody("", proofT0, func(m map[string]any) {
			m["engine"].(map[string]any)["db_refreshed_at"] = "not a time"
		})
		if code, _ := f.post(t, "/ingest/scans", raw, body); code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", code)
		}
	})
}
