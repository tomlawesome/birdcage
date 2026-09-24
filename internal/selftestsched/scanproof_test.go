package selftestsched

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// insertScannerCanary inserts a kind-scanner canary, pending or already
// registered. A scanner needs no address or ports (agentkind.Scanner's
// own profile: Nightjar has no listener), unlike insertHoneypotCanary.
func insertScannerCanary(t *testing.T, database *db.DB, id string, pending bool) {
	t.Helper()
	if err := store.InsertCanary(context.Background(), database, store.Canary{
		ID: id, Name: id, Lane: "lan", Kind: agentkind.Scanner, EnrolledAt: time.Now().UTC(), Pending: pending,
	}); err != nil {
		t.Fatalf("InsertCanary(%s): %v", id, err)
	}
}

// openScanRunCount counts scanner runs (stage set) for canaryID still
// open (completed_at IS NULL) -- the "never more than one open run at a
// time" invariant.
func openScanRunCount(t *testing.T, database *db.DB, canaryID string) int {
	t.Helper()
	var n int
	if err := database.QueryRow(`
		SELECT COUNT(*) FROM self_test_runs
		WHERE canary_id = ? AND completed_at IS NULL AND stage IS NOT NULL`, canaryID).Scan(&n); err != nil {
		t.Fatalf("count open scan runs for %s: %v", canaryID, err)
	}
	return n
}

// scanRunIDFor decodes the run_id a store.MintScanCommand mint carries
// in its command's params, for a test that needs to call
// store.AdvanceRunStage directly.
func scanRunIDFor(t *testing.T, cmd store.CanaryCommand) string {
	t.Helper()
	var params store.ScanParams
	if err := json.Unmarshal([]byte(cmd.Params), &params); err != nil {
		t.Fatalf("unmarshal scan params: %v", err)
	}
	if params.RunID == "" {
		t.Fatalf("scan command %s carries no run_id", cmd.ID)
	}
	return params.RunID
}

// TestRetryPendingMintsScanForPendingScanner is issue #116's widening of
// the pending retry (ADR-0012 decisions 3, 6): a pending scanner gets an
// ordered scan minted on the first tick, stays guarded for the whole
// 30-minute scanRunWindow (never a second open run while the first is
// still live), and once that first run's deadline sweeps it closed, the
// very next tick re-mints -- never leaving more than one run open at a
// time.
func TestRetryPendingMintsScanForPendingScanner(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "false")
		insertScannerCanary(t, database, "scanner-a", true)

		start := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
		now := start
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())

		s.Tick(context.Background())
		if n := selfTestRunCount(t, database, "scanner-a"); n != 1 {
			t.Fatalf("runs after first tick = %d, want 1", n)
		}
		var kind, stage string
		if err := database.QueryRow(`
			SELECT c.kind, r.stage FROM self_test_runs r JOIN canary_commands c ON c.id = r.command_id
			WHERE r.canary_id = ?`, "scanner-a").Scan(&kind, &stage); err != nil {
			t.Fatalf("read minted run: %v", err)
		}
		if kind != string(store.CommandScan) || stage != string(store.StageOrdered) {
			t.Errorf("command kind/stage = %q/%q, want scan/ordered", kind, stage)
		}

		// Every minute through t0+29m: the 30-minute guard blocks a
		// second mint while the first run is still open.
		for m := 1; m <= 29; m++ {
			now = start.Add(time.Duration(m) * time.Minute)
			s.Tick(context.Background())
			if n := selfTestRunCount(t, database, "scanner-a"); n != 1 {
				t.Fatalf("runs at t0+%dm = %d, want still 1 (30-minute guard)", m, n)
			}
		}
		if n := openScanRunCount(t, database, "scanner-a"); n != 1 {
			t.Fatalf("open runs at t0+29m = %d, want 1", n)
		}

		// t0+30m: the deadline sweep closes the first run as failed.
		now = start.Add(scanRunWindow)
		s.Tick(context.Background())
		run, ok, err := store.LatestCompletedSelfTestRun(context.Background(), database, "scanner-a")
		if err != nil {
			t.Fatalf("LatestCompletedSelfTestRun: %v", err)
		}
		if !ok || run.Passed == nil || *run.Passed {
			t.Fatalf("first run was not swept as failed by t0+30m: ok=%v run=%+v", ok, run)
		}

		// t0+31m: the retry re-mints a second run.
		now = start.Add(scanRunWindow + time.Minute)
		s.Tick(context.Background())
		if n := selfTestRunCount(t, database, "scanner-a"); n != 2 {
			t.Fatalf("runs at t0+31m = %d, want 2", n)
		}
		if n := openScanRunCount(t, database, "scanner-a"); n != 1 {
			t.Fatalf("open runs at t0+31m = %d, want 1 (never more than one open at a time)", n)
		}
	})
}

// TestRetryPendingSkipsRegisteredScanner: a scanner whose enrolment
// proof already passed (registered_at set, Pending false) is not what
// the pending retry is for -- Tick must mint nothing for it.
func TestRetryPendingSkipsRegisteredScanner(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "false")
		insertScannerCanary(t, database, "scanner-a", false)

		now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())
		s.Tick(context.Background())

		if n := selfTestRunCount(t, database, "scanner-a"); n != 0 {
			t.Fatalf("runs for a registered scanner = %d, want 0", n)
		}
	})
}

// TestSweepKeepsScanRunStage proves the deadline sweep (issue #46 item
// 5d, widened by #116) never touches a scan run's stage: it only sets
// completed_at and passed=0, so a run that had progressed to
// mounts_checked before it went quiet still says mounts_checked
// afterwards -- the dashboard's own evidence of where a silent scanner
// stopped.
func TestSweepKeepsScanRunStage(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "false")
		insertScannerCanary(t, database, "scanner-a", true)

		start := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
		cmd, err := store.MintScanCommand(context.Background(), database, "scanner-a", store.TriggerProof, start, start.Add(scanRunWindow))
		if err != nil {
			t.Fatalf("MintScanCommand: %v", err)
		}
		runID := scanRunIDFor(t, cmd)

		if _, err := store.AdvanceRunStage(context.Background(), database, "scanner-a", runID, store.StageCollected, start.Add(time.Minute)); err != nil {
			t.Fatalf("AdvanceRunStage(collected): %v", err)
		}
		if _, err := store.AdvanceRunStage(context.Background(), database, "scanner-a", runID, store.StageMountsChecked, start.Add(2*time.Minute)); err != nil {
			t.Fatalf("AdvanceRunStage(mounts_checked): %v", err)
		}

		now := start.Add(31 * time.Minute)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())
		s.Tick(context.Background())

		var completedAt *string
		var passed *int64
		var stage string
		if err := database.QueryRow(`
			SELECT completed_at, passed, stage FROM self_test_runs WHERE command_id = ?`, cmd.ID).
			Scan(&completedAt, &passed, &stage); err != nil {
			t.Fatalf("read original run: %v", err)
		}
		if completedAt == nil {
			t.Fatal("completed_at = nil, want set by the deadline sweep")
		}
		if passed == nil || *passed != 0 {
			t.Errorf("passed = %v, want 0", passed)
		}
		if stage != string(store.StageMountsChecked) {
			t.Errorf("stage = %q, want %q (the sweep must not touch it)", stage, store.StageMountsChecked)
		}
	})
}

// TestMintForCanaryUnknownKindErrors is ADR-0012 decision 5: a canary of
// a kind mintForCanary has no minter for is a loud error, never a silent
// skip, and nothing is minted for it.
func TestMintForCanaryUnknownKindErrors(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())

		c := store.SelfTestCanary{ID: "x", Kind: agentkind.Kind("bogus"), Pending: true}
		err := s.mintForCanary(context.Background(), c, now, doubleMintGuard)
		if !errors.Is(err, ErrUnknownKind) {
			t.Fatalf("mintForCanary error = %v, want ErrUnknownKind", err)
		}
		if n := selfTestRunCount(t, database, "x"); n != 0 {
			t.Fatalf("runs for unknown-kind canary = %d, want 0", n)
		}
	})
}

// TestRotationSucceededNeverMintsForScanner: the rotation-coupled
// schedule is a honeypot-only path (RotationSucceeded's own doc
// comment: a self-test command is never delivered to any kind but
// Honeypot). A scanner's rotation succeeding must never mint a scan.
func TestRotationSucceededNeverMintsForScanner(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "true")
		mustSetSetting(t, database, store.SettingSelfTestUseRotationSchedule, "true")
		insertScannerCanary(t, database, "scanner-a", false)

		now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())
		s.RotationSucceeded(context.Background(), "scanner-a", now)

		if n := selfTestRunCount(t, database, "scanner-a"); n != 0 {
			t.Fatalf("runs for scanner-a after RotationSucceeded = %d, want 0 (rotation self-test is honeypot-only)", n)
		}
	})
}

// TestScheduledTickNeverMintsForRegisteredScanner: the scheduled daily
// mint (mintForEligibleCanaries) only ever lists honeypot canaries
// (store.ListHoneypotCanariesForSelfTest), so a scheduled tick must mint
// for an eligible honeypot at its schedule time but never for a
// registered scanner sitting alongside it.
func TestScheduledTickNeverMintsForRegisteredScanner(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "true")
		mustSetSetting(t, database, store.SettingSelfTestUseRotationSchedule, "false")
		mustSetSetting(t, database, store.SettingSelfTestSchedule, "04:12")
		insertHoneypotCanary(t, database, "honeypot-a", "22", "192.0.2.10")
		insertScannerCanary(t, database, "scanner-a", false)

		now := time.Date(2026, 1, 1, 4, 12, 0, 0, time.UTC)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())
		s.Tick(context.Background())

		if n := selfTestRunCount(t, database, "honeypot-a"); n != 1 {
			t.Fatalf("runs for honeypot-a = %d, want 1", n)
		}
		if n := selfTestRunCount(t, database, "scanner-a"); n != 0 {
			t.Fatalf("runs for scanner-a = %d, want 0 (scheduled mint is honeypot-only)", n)
		}
	})
}

// TestUnknownKindPendingCanaryStaysPendingAndIsLogged: a pending row of
// a kind with no proof minter (written straight to the table -- the
// store refuses to insert one) is reached by both the pending retry and
// FirstContact, refused with an error each time, and minted nothing.
func TestUnknownKindPendingCanaryStaysPendingAndIsLogged(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
		if _, err := database.Exec(`INSERT INTO canaries (id, name, lane, kind, ports, heartbeat_interval_s, enrolled_at)
			VALUES ('odd', 'odd', 'lan', 'bogus', '', 60, ?)`, now.Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert: %v", err)
		}
		var logged []string
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, recordingLogger(&logged))
		s.Tick(context.Background())
		s.FirstContact(context.Background(), "odd", now)
		if n := selfTestRunCount(t, database, "odd"); n != 0 {
			t.Fatalf("runs = %d, want 0", n)
		}
		if len(logged) != 2 {
			t.Errorf("error logs = %v, want one from the retry and one from first contact", logged)
		}
	})
}

// TestMintForCanaryPropagatesMintErrors: a scanner mint the store
// refuses for any reason but an open run, and a honeypot with no address
// to probe, are errors -- not silent skips.
func TestMintForCanaryPropagatesMintErrors(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
		insertHoneypotCanary(t, database, "hp", "22", "")
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())

		// A scanner projection naming a honeypot row: the store refuses.
		err := s.mintForCanary(context.Background(), store.SelfTestCanary{ID: "hp", Kind: agentkind.Scanner}, now, doubleMintGuard)
		if !errors.Is(err, store.ErrNotScanner) {
			t.Errorf("scanner mint on a honeypot row: err = %v, want ErrNotScanner", err)
		}
		err = s.mintForCanary(context.Background(), store.SelfTestCanary{ID: "hp", Kind: agentkind.Honeypot, Ports: []int{22}}, now, doubleMintGuard)
		if err == nil {
			t.Error("honeypot mint with no address: err = nil, want an error")
		}
		if n := selfTestRunCount(t, database, "hp"); n != 0 {
			t.Errorf("runs = %d, want 0", n)
		}
	})
}

// TestRetryPendingSkipsHoneypotWithNoAddress: a pending honeypot not yet
// heard from has nothing to probe; the retry skips it quietly.
func TestRetryPendingSkipsHoneypotWithNoAddress(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
		if err := store.InsertCanary(context.Background(), database, store.Canary{
			ID: "hp", Name: "hp", Lane: "lan", Kind: agentkind.Honeypot, Ports: "22", EnrolledAt: now, Pending: true,
		}); err != nil {
			t.Fatal(err)
		}
		var logged []string
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, recordingLogger(&logged))
		s.retryPending(context.Background(), now)
		if n := selfTestRunCount(t, database, "hp"); n != 0 || len(logged) != 0 {
			t.Errorf("runs = %d, logs = %v, want a quiet skip", n, logged)
		}
	})
}

// errorRecorder is a slog.Handler that keeps each error-level message.
type errorRecorder struct{ out *[]string }

func (r errorRecorder) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelError }
func (r errorRecorder) Handle(_ context.Context, rec slog.Record) error {
	*r.out = append(*r.out, rec.Message)
	return nil
}
func (r errorRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r errorRecorder) WithGroup(string) slog.Handler      { return r }

func recordingLogger(out *[]string) *slog.Logger { return slog.New(errorRecorder{out: out}) }
