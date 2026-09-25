package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/hostmask"
)

var scanT0 = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func insertScanner(t *testing.T, database *db.DB, id string, pending bool) {
	t.Helper()
	if err := InsertCanary(context.Background(), database, Canary{
		ID: id, Name: id, Lane: "lan", Kind: agentkind.Scanner, EnrolledAt: scanT0.Add(-time.Hour), Pending: pending,
	}); err != nil {
		t.Fatalf("InsertCanary(%s): %v", id, err)
	}
}

func mintScan(t *testing.T, database *db.DB, id string, trigger ScanRunTrigger, at time.Time) (CanaryCommand, string) {
	t.Helper()
	cmd, err := MintScanCommand(context.Background(), database, id, trigger, at, at.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("MintScanCommand(%s): %v", id, err)
	}
	var runID string
	if err := database.QueryRow(`SELECT run_id FROM self_test_runs WHERE command_id = ?`, cmd.ID).Scan(&runID); err != nil {
		t.Fatalf("read run_id: %v", err)
	}
	return cmd, runID
}

// passingSnapshot is a snapshot that passes a run issued at issued.
func passingSnapshot(id string, issued time.Time) ScanSnapshot {
	taken := issued.Add(2 * time.Minute)
	built := taken.Add(-6 * time.Hour)
	refreshed := issued.Add(time.Minute)
	return ScanSnapshot{
		CanaryID: id, TakenAt: taken, ReceivedAt: taken.Add(time.Minute),
		EngineName: "grype", EngineVersion: "v0.119.0", DBBuiltAt: &built, DBRefreshedAt: &refreshed,
		Status: ScanStatusOK, FindingCount: 3, MaskedPaths: hostmask.Paths(),
	}
}

// matchAndStore runs MatchScanRun and stores the snapshot in one
// transaction, the way POST /ingest/scans does.
func matchAndStore(t *testing.T, database *db.DB, id, runID string, snap ScanSnapshot, now time.Time) ScanRunMatch {
	t.Helper()
	ctx := context.Background()
	tx, err := database.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	m, err := MatchScanRun(ctx, tx, id, runID, snap, now)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("MatchScanRun: %v", err)
	}
	if m.Outcome == ScanRunUnknown {
		_ = tx.Rollback()
		return m
	}
	snap.SelfTestRunID = m.CommandID
	if err := RecordScanSnapshot(ctx, tx, snap); err != nil {
		_ = tx.Rollback()
		t.Fatalf("RecordScanSnapshot: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return m
}

type runRow struct {
	completed bool
	passed    *int64
	stage     string
	reason    *string
}

func readRun(t *testing.T, database *db.DB, commandID string) runRow {
	t.Helper()
	var (
		r           runRow
		completedAt *string
	)
	if err := database.QueryRow(`SELECT completed_at, passed, stage, reason FROM self_test_runs WHERE command_id = ?`, commandID).
		Scan(&completedAt, &r.passed, &r.stage, &r.reason); err != nil {
		t.Fatalf("read run %s: %v", commandID, err)
	}
	r.completed = completedAt != nil
	return r
}

func registered(t *testing.T, database *db.DB, id string) bool {
	t.Helper()
	var at *string
	if err := database.QueryRow(`SELECT registered_at FROM agents WHERE id = ?`, id).Scan(&at); err != nil {
		t.Fatalf("read registered_at: %v", err)
	}
	return at != nil
}

func TestMintScanCommandWritesCommandRunAndTarget(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertScanner(t, database, "scan-a", true)
		cmd, runID := mintScan(t, database, "scan-a", TriggerProof, scanT0)
		if cmd.Kind != CommandScan || cmd.Params != `{"run_id":"`+runID+`"}` {
			t.Fatalf("command = %+v, want kind scan with params {run_id}", cmd)
		}
		if !cmd.ExpiresAt.Equal(scanT0.Add(30 * time.Minute)) {
			t.Errorf("ExpiresAt = %s, want the run's deadline", cmd.ExpiresAt)
		}
		var trigger, stage, stageAt, service, hash string
		var port int
		if err := database.QueryRow(`
			SELECT r."trigger", r.stage, r.stage_at, t.service, t.dest_port, t.marker_hash
			FROM self_test_runs r JOIN self_test_targets t ON t.command_id = r.command_id
			WHERE r.command_id = ?`, cmd.ID).Scan(&trigger, &stage, &stageAt, &service, &port, &hash); err != nil {
			t.Fatalf("read run/target: %v", err)
		}
		if trigger != "proof" || stage != "ordered" || service != "scan" || port != 0 || hash != "" {
			t.Errorf("run/target = %s/%s/%s/%d/%q, want proof/ordered/scan/0/empty", trigger, stage, service, port, hash)
		}
		if got := mustParse(t, stageAt); !got.Equal(scanT0) {
			t.Errorf("stage_at = %s, want %s", got, scanT0)
		}
	})
}

func TestMintScanCommandRefusedWhileRunOpen(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertScanner(t, database, "scan-a", true)
		mintScan(t, database, "scan-a", TriggerProof, scanT0)
		_, err := MintScanCommand(context.Background(), database, "scan-a", TriggerManual, scanT0.Add(time.Minute), scanT0.Add(31*time.Minute))
		if !errors.Is(err, ErrScanRunOpen) {
			t.Fatalf("second mint err = %v, want ErrScanRunOpen", err)
		}
		// Even past the deadline, an unswept run still blocks: the sweep
		// closes it first.
		_, err = MintScanCommand(context.Background(), database, "scan-a", TriggerProof, scanT0.Add(40*time.Minute), scanT0.Add(70*time.Minute))
		if !errors.Is(err, ErrScanRunOpen) {
			t.Fatalf("mint past deadline before sweep err = %v, want ErrScanRunOpen", err)
		}
		if _, err := SweepExpiredSelfTestRuns(context.Background(), database, scanT0.Add(40*time.Minute)); err != nil {
			t.Fatalf("sweep: %v", err)
		}
		mintScan(t, database, "scan-a", TriggerProof, scanT0.Add(41*time.Minute))
	})
}

// TestOneOpenScanRunIsEnforcedByTheDatabase proves migration 0022's
// partial unique index holds even when the Go check is bypassed.
func TestOneOpenScanRunIsEnforcedByTheDatabase(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertScanner(t, database, "scan-a", true)
		mintScan(t, database, "scan-a", TriggerProof, scanT0)
		_, err := database.Exec(`INSERT INTO self_test_runs (command_id, agent_id, run_id, issued_at, deadline_at, stage)
			VALUES ('c2', 'scan-a', 'r2', ?, ?, 'ordered')`, scanT0.Format(time.RFC3339Nano), scanT0.Add(time.Hour).Format(time.RFC3339Nano))
		if err == nil {
			t.Fatal("second open scan run inserted; want the unique index to refuse it")
		}
		// Honeypot runs (stage NULL) are not limited.
		for _, id := range []string{"h1", "h2"} {
			if _, err := database.Exec(`INSERT INTO self_test_runs (command_id, agent_id, run_id, issued_at, deadline_at)
				VALUES (?, 'hp', ?, ?, ?)`, id, id, scanT0.Format(time.RFC3339Nano), scanT0.Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
				t.Fatalf("honeypot run %s: %v", id, err)
			}
		}
	})
}

func TestMintScanCommandRefusesNonScanner(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		if err := InsertCanary(context.Background(), database, Canary{
			ID: "hp", Name: "hp", Lane: "lan", Kind: agentkind.Honeypot, EnrolledAt: scanT0,
		}); err != nil {
			t.Fatalf("InsertCanary: %v", err)
		}
		for _, id := range []string{"hp", "nobody"} {
			if _, err := MintScanCommand(context.Background(), database, id, TriggerProof, scanT0, scanT0.Add(time.Minute)); !errors.Is(err, ErrNotScanner) {
				t.Errorf("MintScanCommand(%s) err = %v, want ErrNotScanner", id, err)
			}
		}
		insertScanner(t, database, "scan-a", true)
		if _, err := MintScanCommand(context.Background(), database, "scan-a", "bogus", scanT0, scanT0.Add(time.Minute)); err == nil {
			t.Error("unknown trigger minted; want an error")
		}
	})
}

func TestMatchScanRunPassSettlesProof(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertScanner(t, database, "scan-a", true)
		cmd, runID := mintScan(t, database, "scan-a", TriggerProof, scanT0)
		snap := passingSnapshot("scan-a", scanT0)
		m := matchAndStore(t, database, "scan-a", runID, snap, snap.ReceivedAt)
		if m.Outcome != ScanRunPass || m.CommandID != cmd.ID {
			t.Fatalf("match = %+v, want pass for %s", m, cmd.ID)
		}
		r := readRun(t, database, cmd.ID)
		if !r.completed || r.passed == nil || *r.passed != 1 || r.stage != "answered" || r.reason != nil {
			t.Errorf("run = %+v, want completed, passed, answered, no reason", r)
		}
		if !registered(t, database, "scan-a") {
			t.Error("proof pass did not settle pending")
		}
		snaps, err := ListScanSnapshots(context.Background(), database)
		if err != nil || len(snaps) != 1 || snaps[0].SelfTestRunID != cmd.ID {
			t.Fatalf("snapshots = %+v (%v), want one linked to %s", snaps, err, cmd.ID)
		}
		// Answering again: the run is spent.
		if m := matchAndStore(t, database, "scan-a", runID, snap, snap.ReceivedAt.Add(time.Minute)); m.Outcome != ScanRunStale {
			t.Errorf("second answer = %+v, want stale", m)
		}
	})
}

func TestMatchScanRunManualPassNeverSettlesPending(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertScanner(t, database, "scan-a", true)
		cmd, runID := mintScan(t, database, "scan-a", TriggerManual, scanT0)
		snap := passingSnapshot("scan-a", scanT0)
		if m := matchAndStore(t, database, "scan-a", runID, snap, snap.ReceivedAt); m.Outcome != ScanRunPass {
			t.Fatalf("match = %+v, want pass", m)
		}
		if r := readRun(t, database, cmd.ID); r.passed == nil || *r.passed != 1 {
			t.Fatalf("run = %+v, want passed", r)
		}
		if registered(t, database, "scan-a") {
			t.Error("manual pass settled pending; only a proof run may")
		}
	})
}

// TestMatchScanRunFailures is decision 4's pass rule, one failure at a
// time: each case fails the run with its reason, stores the snapshot,
// and leaves the node pending.
func TestMatchScanRunFailures(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(s *ScanSnapshot)
		reason string
	}{
		{"failed status", func(s *ScanSnapshot) {
			s.Status, s.Reason, s.FindingCount = ScanStatusFailed, "mask check failed: /etc/shadow", 0
		}, ReasonScanFailed + ": mask check failed: /etc/shadow"},
		{"taken before issued", func(s *ScanSnapshot) { s.TakenAt = scanT0.Add(-time.Second) }, ReasonTakenBeforeIssued},
		{"stale database", func(s *ScanSnapshot) {
			old := s.TakenAt.Add(-ScanDBMaxAge - time.Minute)
			s.DBBuiltAt = &old
		}, ReasonDBTooOld},
		{"no database", func(s *ScanSnapshot) { s.DBBuiltAt = nil }, ReasonDBTooOld},
		{"refresh not fresh", func(s *ScanSnapshot) {
			before := scanT0.Add(-time.Minute)
			s.DBRefreshedAt = &before
			s.DBRefreshError = "mirror unreachable"
		}, ReasonDBRefreshFailed},
		{"refresh missing", func(s *ScanSnapshot) { s.DBRefreshedAt = nil }, ReasonDBRefreshFailed},
		{"incomplete masks", func(s *ScanSnapshot) { s.MaskedPaths = hostmask.Paths()[1:] }, ReasonMasksIncomplete},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forEachEngine(t, func(t *testing.T, database *db.DB) {
				insertScanner(t, database, "scan-a", true)
				cmd, runID := mintScan(t, database, "scan-a", TriggerProof, scanT0)
				snap := passingSnapshot("scan-a", scanT0)
				tc.mutate(&snap)
				m := matchAndStore(t, database, "scan-a", runID, snap, scanT0.Add(5*time.Minute))
				if m.Outcome != ScanRunFail || m.Reason != tc.reason {
					t.Fatalf("match = %+v, want fail %q", m, tc.reason)
				}
				r := readRun(t, database, cmd.ID)
				if !r.completed || r.passed == nil || *r.passed != 0 || r.stage != "answered" || r.reason == nil || *r.reason != tc.reason {
					t.Errorf("run = %+v, want completed, failed, answered, reason %q", r, tc.reason)
				}
				if registered(t, database, "scan-a") {
					t.Error("failed run settled pending")
				}
				if snaps, _ := ListScanSnapshots(context.Background(), database); len(snaps) != 1 {
					t.Errorf("snapshots = %d, want the answer stored", len(snaps))
				}
			})
		})
	}
}

func TestMatchScanRunMasksSupersetPasses(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertScanner(t, database, "scan-a", true)
		_, runID := mintScan(t, database, "scan-a", TriggerProof, scanT0)
		snap := passingSnapshot("scan-a", scanT0)
		snap.MaskedPaths = append(hostmask.Paths(), "/srv/secrets")
		if m := matchAndStore(t, database, "scan-a", runID, snap, snap.ReceivedAt); m.Outcome != ScanRunPass {
			t.Fatalf("match = %+v, want pass", m)
		}
	})
}

func TestMatchScanRunUnknownAndStale(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertScanner(t, database, "scan-a", true)
		insertScanner(t, database, "scan-b", true)
		cmd, runID := mintScan(t, database, "scan-a", TriggerProof, scanT0)

		snap := passingSnapshot("scan-b", scanT0)
		if m := matchAndStore(t, database, "scan-b", runID, snap, snap.ReceivedAt); m.Outcome != ScanRunUnknown {
			t.Errorf("other node's run = %+v, want unknown", m)
		}
		if m := matchAndStore(t, database, "scan-a", "no-such-run", snap, snap.ReceivedAt); m.Outcome != ScanRunUnknown {
			t.Errorf("unknown run = %+v, want unknown", m)
		}
		if snaps, _ := ListScanSnapshots(context.Background(), database); len(snaps) != 0 {
			t.Errorf("unknown-run answers stored %d snapshots, want 0", len(snaps))
		}

		// Past the deadline, not yet swept: stale, stored, settles nothing.
		snapA := passingSnapshot("scan-a", scanT0)
		if m := matchAndStore(t, database, "scan-a", runID, snapA, scanT0.Add(30*time.Minute)); m.Outcome != ScanRunStale {
			t.Errorf("expired run = %+v, want stale", m)
		}
		if r := readRun(t, database, cmd.ID); r.completed {
			t.Error("stale answer completed the run")
		}
		if registered(t, database, "scan-a") {
			t.Error("stale answer settled pending")
		}
		if snaps, _ := ListScanSnapshots(context.Background(), database); len(snaps) != 1 || snaps[0].SelfTestRunID != "" {
			t.Errorf("stale snapshot = %+v, want stored unlinked", snaps)
		}
	})
}

func TestMatchScanRunIgnoresHoneypotRuns(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertScanner(t, database, "scan-a", true)
		// A honeypot-style run (stage NULL) recorded against the scanner
		// is not a scan run and cannot be answered with a snapshot.
		if _, err := database.Exec(`INSERT INTO self_test_runs (command_id, agent_id, run_id, issued_at, deadline_at)
			VALUES ('c', 'scan-a', 'hp-run', ?, ?)`, scanT0.Format(time.RFC3339Nano), scanT0.Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert: %v", err)
		}
		snap := passingSnapshot("scan-a", scanT0)
		if m := matchAndStore(t, database, "scan-a", "hp-run", snap, snap.ReceivedAt); m.Outcome != ScanRunUnknown {
			t.Errorf("honeypot run answered = %+v, want unknown", m)
		}
	})
}

func TestAdvanceRunStage(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		insertScanner(t, database, "scan-a", true)
		insertScanner(t, database, "scan-b", true)
		cmd, runID := mintScan(t, database, "scan-a", TriggerProof, scanT0)

		step := func(id string, stage ScanStage, at time.Time, want StageResult) {
			t.Helper()
			got, err := AdvanceRunStage(ctx, database, id, runID, stage, at)
			if err != nil {
				t.Fatalf("AdvanceRunStage(%s, %s): %v", id, stage, err)
			}
			if got != want {
				t.Errorf("AdvanceRunStage(%s, %s) = %v, want %v", id, stage, got, want)
			}
		}
		step("scan-a", StageCollected, scanT0.Add(time.Minute), StageAdvanced)
		step("scan-a", StageDBRefreshed, scanT0.Add(2*time.Minute), StageAdvanced) // a skipped stage is still forward
		step("scan-a", StageDBRefreshed, scanT0.Add(3*time.Minute), StageUnchanged)
		step("scan-a", StageMountsChecked, scanT0.Add(3*time.Minute), StageStale) // backwards
		step("scan-b", StageScanning, scanT0.Add(3*time.Minute), StageStale)      // wrong node
		step("scan-a", StageScanning, scanT0.Add(30*time.Minute), StageStale)     // past the deadline

		var stage, stageAt string
		if err := database.QueryRow(`SELECT stage, stage_at FROM self_test_runs WHERE command_id = ?`, cmd.ID).Scan(&stage, &stageAt); err != nil {
			t.Fatalf("read: %v", err)
		}
		if stage != "db_refreshed" || !mustParse(t, stageAt).Equal(scanT0.Add(2*time.Minute)) {
			t.Errorf("stage = %s at %s, want db_refreshed at +2m", stage, stageAt)
		}

		if _, err := AdvanceRunStage(ctx, database, "scan-a", runID, "bogus", scanT0); err == nil {
			t.Error("unknown stage accepted")
		}

		// Closed run.
		snap := passingSnapshot("scan-a", scanT0)
		matchAndStore(t, database, "scan-a", runID, snap, scanT0.Add(4*time.Minute))
		step("scan-a", StageScanning, scanT0.Add(5*time.Minute), StageStale)
	})
}

func TestAgentReportableStage(t *testing.T) {
	for s, want := range map[string]bool{
		"mounts_checked": true, "db_refreshed": true, "scanning": true,
		"ordered": false, "collected": false, "answered": false, "": false, "SCANNING": false,
	} {
		if AgentReportableStage(s) != want {
			t.Errorf("AgentReportableStage(%q) = %v, want %v", s, !want, want)
		}
	}
}

func TestSweepKeepsLastStageAndReadsExpired(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		insertScanner(t, database, "scan-a", true)
		cmd, runID := mintScan(t, database, "scan-a", TriggerProof, scanT0)
		if _, err := AdvanceRunStage(ctx, database, "scan-a", runID, StageCollected, scanT0.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		if _, err := SweepExpiredSelfTestRuns(ctx, database, scanT0.Add(31*time.Minute)); err != nil {
			t.Fatal(err)
		}
		if r := readRun(t, database, cmd.ID); !r.completed || r.stage != "collected" {
			t.Fatalf("swept run = %+v, want completed at stage collected", r)
		}
		runs, err := ListScannerRuns(ctx, database, "scan-a", 0)
		if err != nil || len(runs) != 1 {
			t.Fatalf("ListScannerRuns = %+v, %v", runs, err)
		}
		if runs[0].Verdict != VerdictExpired || runs[0].LastStage != StageCollected || runs[0].SnapshotID != nil {
			t.Errorf("run = %+v, want expired at collected with no snapshot", runs[0])
		}
	})
}

func TestListScannerRunsOrderLimitAndSnapshot(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		insertScanner(t, database, "scan-a", true)
		for i := 0; i < 3; i++ {
			at := scanT0.Add(time.Duration(i) * time.Hour)
			_, runID := mintScan(t, database, "scan-a", TriggerProof, at)
			snap := passingSnapshot("scan-a", at)
			snap.Status, snap.Reason, snap.FindingCount = ScanStatusFailed, "boom", 0
			matchAndStore(t, database, "scan-a", runID, snap, at.Add(5*time.Minute))
		}
		mintScan(t, database, "scan-a", TriggerProof, scanT0.Add(4*time.Hour)) // open: not listed

		runs, err := ListScannerRuns(ctx, database, "scan-a", 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(runs) != 2 || !runs[0].IssuedAt.Equal(scanT0.Add(2*time.Hour)) || !runs[1].IssuedAt.Equal(scanT0.Add(time.Hour)) {
			t.Fatalf("runs = %+v, want the two newest completed, newest first", runs)
		}
		snaps, _ := ListScanSnapshots(ctx, database)
		if runs[0].SnapshotID == nil || *runs[0].SnapshotID != snaps[0].ID {
			t.Errorf("newest run snapshot = %v, want %d", runs[0].SnapshotID, snaps[0].ID)
		}
		if runs[0].Verdict != VerdictFail || runs[0].Reason != "scan_failed: boom" || runs[0].Trigger != TriggerProof {
			t.Errorf("run = %+v", runs[0])
		}
	})
}

func scannerCanary(t *testing.T, database *db.DB, id string, now time.Time) Canary {
	t.Helper()
	canaries, err := ListCanaries(context.Background(), database, now, time.Hour)
	if err != nil {
		t.Fatalf("ListCanaries: %v", err)
	}
	for _, c := range canaries {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("canary %s not listed", id)
	return Canary{}
}

func hasActive(c Canary, s HealthState) bool {
	for _, a := range c.ActiveStates {
		if a == string(s) {
			return true
		}
	}
	return false
}

func TestScannerReadModelRunLastRunAndTestFailedClears(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		insertScanner(t, database, "scan-a", true)
		_, runID := mintScan(t, database, "scan-a", TriggerProof, scanT0)
		if _, err := AdvanceRunStage(ctx, database, "scan-a", runID, StageScanning, scanT0.Add(3*time.Minute)); err != nil {
			t.Fatal(err)
		}
		c := scannerCanary(t, database, "scan-a", scanT0.Add(4*time.Minute))
		if c.Run == nil || c.Run.Stage != StageScanning || !c.Run.StageAt.Equal(scanT0.Add(3*time.Minute)) ||
			!c.Run.IssuedAt.Equal(scanT0) || c.Run.Trigger != TriggerProof || c.LastRun != nil {
			t.Fatalf("open run read model = %+v / %+v", c.Run, c.LastRun)
		}
		if !hasActive(c, StatePending) {
			t.Errorf("ActiveStates = %v, want pending", c.ActiveStates)
		}

		// Fails on a failed snapshot: self_test_failed naming the scan target.
		snap := passingSnapshot("scan-a", scanT0)
		snap.Status, snap.Reason, snap.FindingCount = ScanStatusFailed, "grype exited 1", 0
		snap.ReceivedAt = scanT0.Add(5 * time.Minute)
		matchAndStore(t, database, "scan-a", runID, snap, snap.ReceivedAt)
		c = scannerCanary(t, database, "scan-a", scanT0.Add(6*time.Minute))
		if c.Run != nil || c.LastRun == nil || c.LastRun.Verdict != VerdictFail || c.LastRun.LastStage != StageAnswered {
			t.Fatalf("after fail: run %+v last %+v", c.Run, c.LastRun)
		}
		if !hasActive(c, StateTestFailed) || len(c.SelfTestFailedServices) != 1 || c.SelfTestFailedServices[0] != "scan 0" {
			t.Fatalf("after fail: states %v services %v, want self_test_failed on scan 0", c.ActiveStates, c.SelfTestFailedServices)
		}

		// A later ok timer snapshot clears the tile's self_test_failed.
		timer := passingSnapshot("scan-a", scanT0.Add(time.Hour))
		if err := RecordScanSnapshot(ctx, database, timer); err != nil {
			t.Fatal(err)
		}
		c = scannerCanary(t, database, "scan-a", scanT0.Add(2*time.Hour))
		if hasActive(c, StateTestFailed) {
			t.Errorf("after later ok snapshot: states %v, want self_test_failed cleared", c.ActiveStates)
		}
		if c.LastRun == nil || c.LastRun.Verdict != VerdictFail {
			t.Errorf("last_run = %+v; the record stays", c.LastRun)
		}
	})
}

// TestScannerTestFailedNotClearedByItsOwnAnswer: an ok snapshot that
// failed the run (stale refresh) must not clear the failure it caused.
func TestScannerTestFailedNotClearedByItsOwnAnswer(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertScanner(t, database, "scan-a", true)
		_, runID := mintScan(t, database, "scan-a", TriggerProof, scanT0)
		snap := passingSnapshot("scan-a", scanT0)
		snap.DBRefreshedAt = nil
		snap.ReceivedAt = scanT0.Add(5 * time.Minute)
		matchAndStore(t, database, "scan-a", runID, snap, snap.ReceivedAt)
		c := scannerCanary(t, database, "scan-a", scanT0.Add(6*time.Minute))
		if !hasActive(c, StateTestFailed) || c.LastRun == nil || c.LastRun.Reason != ReasonDBRefreshFailed {
			t.Fatalf("states %v last %+v, want self_test_failed with db_refresh_failed", c.ActiveStates, c.LastRun)
		}
	})
}

func TestHoneypotCarriesNoScanRunFields(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		if err := InsertCanary(context.Background(), database, Canary{
			ID: "hp", Name: "hp", Lane: "lan", Kind: agentkind.Honeypot, EnrolledAt: scanT0,
		}); err != nil {
			t.Fatal(err)
		}
		c := scannerCanary(t, database, "hp", scanT0)
		if c.Run != nil || c.LastRun != nil || c.DBRefresh != nil {
			t.Errorf("honeypot carries scan fields: %+v %+v %+v", c.Run, c.LastRun, c.DBRefresh)
		}
	})
}

// TestDBStaleByBirdcagesClock: db_stale counts from birdcage's first
// failing report, not from anything the agent said, and clears.
func TestDBStaleByBirdcagesClock(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		insertScanner(t, database, "scan-a", false)
		if err := SetCanaryDBRefresh(ctx, database, "scan-a", true, "mirror unreachable", scanT0); err != nil {
			t.Fatal(err)
		}
		// A later failing report keeps the first failing_since.
		if err := SetCanaryDBRefresh(ctx, database, "scan-a", true, "still unreachable", scanT0.Add(12*time.Hour)); err != nil {
			t.Fatal(err)
		}
		c := scannerCanary(t, database, "scan-a", scanT0.Add(24*time.Hour))
		if c.DBRefresh == nil || !c.DBRefresh.FailingSince.Equal(scanT0) || c.DBRefresh.LastError != "still unreachable" {
			t.Fatalf("db_refresh = %+v, want failing since t0 with the newest error", c.DBRefresh)
		}
		if hasActive(c, StateDBStale) {
			t.Errorf("at exactly 24h: states %v, want not yet db_stale", c.ActiveStates)
		}
		c = scannerCanary(t, database, "scan-a", scanT0.Add(24*time.Hour+time.Second))
		if !hasActive(c, StateDBStale) {
			t.Fatalf("past 24h: states %v, want db_stale", c.ActiveStates)
		}
		if err := SetCanaryDBRefresh(ctx, database, "scan-a", false, "", scanT0.Add(25*time.Hour)); err != nil {
			t.Fatal(err)
		}
		c = scannerCanary(t, database, "scan-a", scanT0.Add(25*time.Hour))
		if c.DBRefresh != nil || hasActive(c, StateDBStale) {
			t.Errorf("after success: db_refresh %+v states %v, want cleared", c.DBRefresh, c.ActiveStates)
		}
	})
}

func TestDBStaleRanksBetweenTestFailedAndThrottled(t *testing.T) {
	if healthStateRank[StateTestFailed] >= healthStateRank[StateDBStale] || healthStateRank[StateDBStale] >= healthStateRank[StateThrottled] {
		t.Fatalf("ranks: self_test_failed %d, db_stale %d, throttled %d", healthStateRank[StateTestFailed], healthStateRank[StateDBStale], healthStateRank[StateThrottled])
	}
	c := Canary{ActiveStates: []string{string(StateThrottled), string(StatePending)}, Status: string(StateThrottled)}
	addActiveStates(&c, StateDBStale)
	if c.Status != string(StateDBStale) || strings.Join(c.ActiveStates, ",") != "db_stale,throttled,pending" {
		t.Errorf("status %s active %v", c.Status, c.ActiveStates)
	}
}

func TestClaimNextCanaryCommandOfKindsFiltersKinds(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		insertScanner(t, database, "scan-a", true)
		if _, err := MintCanaryCommand(ctx, database, "scan-a", CommandSelfTest, "", scanT0, scanT0.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		scanCmd, _ := mintScan(t, database, "scan-a", TriggerProof, scanT0.Add(time.Second))

		allowScan := map[CommandKind]bool{CommandScan: true}
		got, err := ClaimNextCanaryCommandOfKinds(ctx, database, "scan-a", allowScan, scanT0.Add(time.Minute))
		if err != nil || got.ID != scanCmd.ID {
			t.Fatalf("claim = %+v, %v; want the scan command, not the older selftest", got, err)
		}
		if _, err := ClaimNextCanaryCommandOfKinds(ctx, database, "scan-a", allowScan, scanT0.Add(time.Minute)); !errors.Is(err, ErrCommandNotFound) {
			t.Errorf("second claim err = %v, want not found (selftest stays unclaimed)", err)
		}
		if _, err := ClaimNextCanaryCommandOfKinds(ctx, database, "scan-a", map[CommandKind]bool{}, scanT0.Add(time.Minute)); !errors.Is(err, ErrCommandNotFound) {
			t.Errorf("empty allow-list err = %v, want not found", err)
		}
	})
}

func TestListPendingCanariesForSelfTestAllKinds(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		insertScanner(t, database, "scan-p", true)
		insertScanner(t, database, "scan-r", false)
		if err := InsertCanary(ctx, database, Canary{ID: "hp-p", Name: "hp-p", Lane: "lan", Kind: agentkind.Honeypot, Ports: "22", EnrolledAt: scanT0, Pending: true}); err != nil {
			t.Fatal(err)
		}
		got, err := ListPendingCanariesForSelfTest(ctx, database)
		if err != nil {
			t.Fatal(err)
		}
		kinds := map[string]agentkind.Kind{}
		for _, c := range got {
			kinds[c.ID] = c.Kind
		}
		if len(kinds) != 2 || kinds["scan-p"] != agentkind.Scanner || kinds["hp-p"] != agentkind.Honeypot {
			t.Errorf("pending = %v, want scan-p and hp-p", kinds)
		}
	})
}
