package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/db/dbtest"
	"github.com/tomlawesome/birdcage/internal/hostmask"
	"github.com/tomlawesome/birdcage/internal/store"
)

// forEachAPIEngine mirrors internal/selftestsched's and internal/store's
// own forEachEngine: every test in this file that needs a real database
// runs once per engine dbtest.Targets returns (SQLite always, Postgres
// too when BIRDCAGE_TEST_DATABASE_URL is set).
func forEachAPIEngine(t *testing.T, fn func(t *testing.T, database *db.DB)) {
	t.Helper()
	for _, tgt := range dbtest.Targets(t) {
		tgt := tgt
		t.Run(tgt.Name, func(t *testing.T) {
			fn(t, tgt.DB)
		})
	}
}

func insertScannerCanary(t *testing.T, database *db.DB, id string, pending bool) {
	t.Helper()
	insertCanary(t, database, store.Canary{
		ID: id, Name: id, Lane: "lan", Kind: agentkind.Scanner, EnrolledAt: time.Now().UTC(), Pending: pending,
	})
}

// mintScanRun mints one scan command for canaryID and returns its
// command id and run id (decoded from the command's own params, since
// no run id is ever handed back on the wire -- ADR-0012, "never the run
// id").
func mintScanRun(t *testing.T, database *db.DB, canaryID string, trigger store.ScanRunTrigger, issued, deadline time.Time) (store.CanaryCommand, string) {
	t.Helper()
	cmd, err := store.MintScanCommand(context.Background(), database, canaryID, trigger, issued, deadline)
	if err != nil {
		t.Fatalf("MintScanCommand: %v", err)
	}
	var params store.ScanParams
	if err := json.Unmarshal([]byte(cmd.Params), &params); err != nil {
		t.Fatalf("unmarshal scan params: %v", err)
	}
	if params.RunID == "" {
		t.Fatalf("scan command %s carries no run_id", cmd.ID)
	}
	return cmd, params.RunID
}

// settleScanRun answers canaryID's runID with snap, in its own
// transaction, the same shape internal/ingest/scans.go's storeScan
// uses: MatchScanRun then RecordScanSnapshot, both inside one commit.
func settleScanRun(t *testing.T, database *db.DB, canaryID, runID string, snap store.ScanSnapshot, now time.Time) store.ScanRunMatch {
	t.Helper()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	match, err := store.MatchScanRun(context.Background(), tx, canaryID, runID, snap, now)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("MatchScanRun: %v", err)
	}
	if match.Outcome == store.ScanRunPass || match.Outcome == store.ScanRunFail {
		snap.SelfTestRunID = match.CommandID
	}
	if err := store.RecordScanSnapshot(context.Background(), tx, snap); err != nil {
		_ = tx.Rollback()
		t.Fatalf("RecordScanSnapshot: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return match
}

// snapshotIDForRun looks up the scan_snapshots.id that settled
// commandID, for a test asserting the runs list carries it.
func snapshotIDForRun(t *testing.T, database *db.DB, canaryID, commandID string) int64 {
	t.Helper()
	var id int64
	if err := database.QueryRow(`
		SELECT id FROM scan_snapshots WHERE agent_id = ? AND self_test_run_id = ?`, canaryID, commandID).Scan(&id); err != nil {
		t.Fatalf("look up snapshot for run %s: %v", commandID, err)
	}
	return id
}

// TestCanaryRunsListsCompletedRunsNewestFirst is ADR-0012 decision 11:
// GET /api/canaries/{id}/runs lists only completed runs, newest issued
// first, each with its settling snapshot when it has one.
func TestCanaryRunsListsCompletedRunsNewestFirst(t *testing.T) {
	forEachAPIEngine(t, func(t *testing.T, database *db.DB) {
		insertScannerCanary(t, database, "scanner-a", true)
		t0 := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)

		// Run 1: minted at t0, settled failed one minute later.
		cmd1, runID1 := mintScanRun(t, database, "scanner-a", store.TriggerProof, t0, t0.Add(30*time.Minute))
		failAt := t0.Add(time.Minute)
		match1 := settleScanRun(t, database, "scanner-a", runID1, store.ScanSnapshot{
			CanaryID:   "scanner-a",
			TakenAt:    failAt,
			ReceivedAt: failAt,
			Status:     store.ScanStatusFailed,
			Reason:     "mask check failed",
		}, failAt)
		if match1.Outcome != store.ScanRunFail {
			t.Fatalf("match1.Outcome = %v, want ScanRunFail", match1.Outcome)
		}
		snap1ID := snapshotIDForRun(t, database, "scanner-a", cmd1.ID)

		// Run 2: minted at t0+40m, left to expire at t0+71m.
		mintAt2 := t0.Add(40 * time.Minute)
		if _, err := store.MintScanCommand(context.Background(), database, "scanner-a", store.TriggerProof, mintAt2, mintAt2.Add(30*time.Minute)); err != nil {
			t.Fatalf("MintScanCommand (run 2): %v", err)
		}
		if _, err := store.SweepExpiredSelfTestRuns(context.Background(), database, t0.Add(71*time.Minute)); err != nil {
			t.Fatalf("SweepExpiredSelfTestRuns: %v", err)
		}

		// Run 3: minted at t0+72m, left open.
		mintAt3 := t0.Add(72 * time.Minute)
		if _, err := store.MintScanCommand(context.Background(), database, "scanner-a", store.TriggerProof, mintAt3, mintAt3.Add(30*time.Minute)); err != nil {
			t.Fatalf("MintScanCommand (run 3): %v", err)
		}

		h := newHandler(database, fixedNow(t0.Add(80*time.Minute)), nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/canaries/scanner-a/runs", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
		}

		var resp canaryRunsResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
		}
		if len(resp.Runs) != 2 {
			t.Fatalf("runs = %+v, want exactly 2 (the open run excluded)", resp.Runs)
		}

		expired, failed := resp.Runs[0], resp.Runs[1]
		if !expired.IssuedAt.Equal(mintAt2) {
			t.Errorf("runs[0].issued_at = %v, want the newer run %v", expired.IssuedAt, mintAt2)
		}
		if expired.Trigger != store.TriggerProof {
			t.Errorf("runs[0].trigger = %q, want proof", expired.Trigger)
		}
		if expired.Verdict != store.VerdictExpired {
			t.Errorf("runs[0].verdict = %q, want expired", expired.Verdict)
		}
		if expired.LastStage != store.StageOrdered {
			t.Errorf("runs[0].last_stage = %q, want ordered", expired.LastStage)
		}
		if expired.SnapshotID != nil {
			t.Errorf("runs[0].snapshot_id = %v, want nil (nothing ever answered it)", *expired.SnapshotID)
		}

		if !failed.IssuedAt.Equal(t0) {
			t.Errorf("runs[1].issued_at = %v, want the older run %v", failed.IssuedAt, t0)
		}
		if failed.Verdict != store.VerdictFail {
			t.Errorf("runs[1].verdict = %q, want fail", failed.Verdict)
		}
		if failed.LastStage != store.StageAnswered {
			t.Errorf("runs[1].last_stage = %q, want answered", failed.LastStage)
		}
		if !strings.HasPrefix(failed.Reason, store.ReasonScanFailed+": ") {
			t.Errorf("runs[1].reason = %q, want a %q prefix", failed.Reason, store.ReasonScanFailed+": ")
		}
		if failed.SnapshotID == nil || *failed.SnapshotID != snap1ID {
			t.Errorf("runs[1].snapshot_id = %v, want %d", failed.SnapshotID, snap1ID)
		}
	})
}

// TestCanaryRunsUnknownCanaryIs404AndHoneypotIsEmpty covers the two
// non-scanner edges: an id naming no canary at all is 404, matching
// GET /api/canary's own stance; a canary that has never had a scan run
// (a honeypot) is 200 with an empty, never-null, "runs" array.
func TestCanaryRunsUnknownCanaryIs404AndHoneypotIsEmpty(t *testing.T) {
	forEachAPIEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, store.Canary{
			ID: "honeypot-a", Name: "honeypot-a", Lane: "lan", EnrolledAt: time.Now().UTC(),
		})
		h := newHandler(database, fixedNow(time.Now().UTC()), nil)

		t.Run("unknown canary", func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/canaries/no-such-canary/runs", nil))
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
			}
		})

		t.Run("honeypot has no scan runs", func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/canaries/honeypot-a/runs", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
				t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
			}
			if string(raw["runs"]) != "[]" {
				t.Errorf(`body["runs"] = %s, want "[]" (never null)`, raw["runs"])
			}
		})
	})
}

// TestCanaryRunsNeverExposeRunID is ADR-0012's own repeated instruction,
// checked directly against the wire: run_id (self_test_runs.run_id, the
// value a scanner posts back on POST /ingest/scans) must never appear in
// any dashboard response body, on any of the endpoints that read a
// scanner's data.
func TestCanaryRunsNeverExposeRunID(t *testing.T) {
	forEachAPIEngine(t, func(t *testing.T, database *db.DB) {
		insertScannerCanary(t, database, "scanner-a", true)
		t0 := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
		_, runID := mintScanRun(t, database, "scanner-a", store.TriggerProof, t0, t0.Add(30*time.Minute))
		settleScanRun(t, database, "scanner-a", runID, store.ScanSnapshot{
			CanaryID:   "scanner-a",
			TakenAt:    t0.Add(time.Minute),
			ReceivedAt: t0.Add(time.Minute),
			Status:     store.ScanStatusFailed,
			Reason:     "mask check failed",
		}, t0.Add(time.Minute))

		var storedRunID string
		if err := database.QueryRow(`SELECT run_id FROM self_test_runs WHERE agent_id = ?`, "scanner-a").Scan(&storedRunID); err != nil {
			t.Fatalf("read run_id: %v", err)
		}
		if storedRunID != runID {
			t.Fatalf("storedRunID = %q, want %q", storedRunID, runID)
		}

		h := newHandler(database, fixedNow(t0.Add(time.Hour)), nil)
		for _, path := range []string{
			"/api/canaries/scanner-a/runs",
			"/api/canaries",
			"/api/canary?id=scanner-a",
			"/api/scans",
		} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: status = %d, want 200; body=%s", path, rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			if strings.Contains(body, storedRunID) {
				t.Errorf("%s: body contains the run id %q", path, storedRunID)
			}
			if strings.Contains(body, "run_id") {
				t.Errorf("%s: body contains the substring \"run_id\"", path)
			}
		}
	})
}

// TestCanaryReadModelCarriesRunAndLastRun is ADR-0012 decision 6/9's
// read model: GET /api/canaries shows an open scan run's trigger, stage
// and timestamps, and a status of "pending" while the canary's own
// enrolment proof has not yet passed; once the run passes, "run" is
// gone, "last_run" carries the settled verdict, and the canary is no
// longer pending.
func TestCanaryReadModelCarriesRunAndLastRun(t *testing.T) {
	forEachAPIEngine(t, func(t *testing.T, database *db.DB) {
		insertScannerCanary(t, database, "scanner-a", true)
		issued := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
		// A recent heartbeat keeps applyStatus reading "ok" rather than
		// "silent" -- silent outranks pending (health.go's own
		// healthStateRank), so without one the headline status would be
		// "silent" and pending would only show up in ActiveStates.
		if err := store.RecordHeartbeat(context.Background(), database, "scanner-a", issued); err != nil {
			t.Fatalf("RecordHeartbeat: %v", err)
		}
		_, runID := mintScanRun(t, database, "scanner-a", store.TriggerProof, issued, issued.Add(30*time.Minute))
		collectedAt := issued.Add(time.Minute)
		if _, err := store.AdvanceRunStage(context.Background(), database, "scanner-a", runID, store.StageCollected, collectedAt); err != nil {
			t.Fatalf("AdvanceRunStage(collected): %v", err)
		}

		h := newHandler(database, fixedNow(issued.Add(2*time.Minute)), nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/canaries", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
		}
		var resp canariesResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
		}
		c := findCanary(t, resp.Canaries, "scanner-a")
		if c.Run == nil {
			t.Fatal("run = nil, want the open run")
		}
		if c.Run.Trigger != store.TriggerProof {
			t.Errorf("run.trigger = %q, want proof", c.Run.Trigger)
		}
		if c.Run.Stage != store.StageCollected {
			t.Errorf("run.stage = %q, want collected", c.Run.Stage)
		}
		if !c.Run.StageAt.Equal(collectedAt) {
			t.Errorf("run.stage_at = %v, want %v", c.Run.StageAt, collectedAt)
		}
		if !c.Run.IssuedAt.Equal(issued) {
			t.Errorf("run.issued_at = %v, want %v", c.Run.IssuedAt, issued)
		}
		if c.LastRun != nil {
			t.Errorf("last_run = %+v, want nil (nothing has completed yet)", c.LastRun)
		}
		if c.Status != "pending" {
			t.Errorf("status = %q, want pending", c.Status)
		}

		// Now settle it with a passing snapshot.
		takenAt := issued.Add(3 * time.Minute)
		dbBuiltAt := takenAt.Add(-time.Hour)
		dbRefreshedAt := issued.Add(2 * time.Minute)
		match := settleScanRun(t, database, "scanner-a", runID, store.ScanSnapshot{
			CanaryID:      "scanner-a",
			TakenAt:       takenAt,
			ReceivedAt:    takenAt,
			Status:        store.ScanStatusOK,
			EngineName:    "grype",
			EngineVersion: "0.90.0",
			DBBuiltAt:     &dbBuiltAt,
			DBRefreshedAt: &dbRefreshedAt,
			MaskedPaths:   hostmask.Paths(),
		}, takenAt)
		if match.Outcome != store.ScanRunPass {
			t.Fatalf("match.Outcome = %v, want ScanRunPass", match.Outcome)
		}
		if err := store.RecordHeartbeat(context.Background(), database, "scanner-a", takenAt); err != nil {
			t.Fatalf("RecordHeartbeat: %v", err)
		}

		h2 := newHandler(database, fixedNow(takenAt.Add(time.Minute)), nil)
		rec2 := httptest.NewRecorder()
		h2.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/api/canaries", nil))
		if rec2.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rec2.Code, rec2.Body.String())
		}
		var resp2 canariesResponse
		if err := json.Unmarshal(rec2.Body.Bytes(), &resp2); err != nil {
			t.Fatalf("decode response: %v; body=%s", err, rec2.Body.String())
		}
		c2 := findCanary(t, resp2.Canaries, "scanner-a")
		if c2.Run != nil {
			t.Errorf("run = %+v, want nil (the run has completed)", c2.Run)
		}
		if c2.LastRun == nil {
			t.Fatal("last_run = nil, want the completed run")
		}
		if c2.LastRun.Verdict != store.VerdictPass {
			t.Errorf("last_run.verdict = %q, want pass", c2.LastRun.Verdict)
		}
		if c2.LastRun.LastStage != store.StageAnswered {
			t.Errorf("last_run.last_stage = %q, want answered", c2.LastRun.LastStage)
		}
		if c2.Status == "pending" {
			t.Error("status = pending, want registered (the enrolment proof passed)")
		}
	})
}

func findCanary(t *testing.T, canaries []canaryWithSelfTest, id string) canaryWithSelfTest {
	t.Helper()
	for _, c := range canaries {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("canary %s not found in %+v", id, canaries)
	return canaryWithSelfTest{}
}

// TestRunsRouteRejectsMutatingMethods: the runs route is GET-only, like
// every other dashboard read, and a path one segment further than the
// registered pattern falls through to the outer mux's catch-all 404.
func TestRunsRouteRejectsMutatingMethods(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, fixedNow(time.Now().UTC()), nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/canaries/x/runs", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/canaries/x/runs: status = %d, want 405", rec.Code)
	}

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/api/canaries/x/other", nil))
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("GET /api/canaries/x/other: status = %d, want 404; body=%s", rec2.Code, rec2.Body.String())
	}
	if ct := rec2.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("GET /api/canaries/x/other: Content-Type = %q, want application/json", ct)
	}
}

// TestCanaryRunsStoreFailureIs500: a runs table the store cannot read is
// a 500 with the generic body, never a partial list.
func TestCanaryRunsStoreFailureIs500(t *testing.T) {
	database := openTempDB(t)
	insertScannerCanary(t, database, "scanner-a", true)
	if _, err := database.Exec(`DROP TABLE self_test_runs`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	h := newHandler(database, fixedNow(time.Now().UTC()), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/canaries/scanner-a/runs", nil))
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "runs") {
		t.Fatalf("status = %d body %q, want 500 internal error", rec.Code, rec.Body.String())
	}
}
