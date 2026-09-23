package selftestsched

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/db/dbtest"
	"github.com/tomlawesome/birdcage/internal/store"
)

// forEachEngine mirrors internal/store's and internal/ingest's own test
// helper of the same name: every test in this package that needs a real
// database runs once per engine dbtest.Targets returns.
func forEachEngine(t *testing.T, fn func(t *testing.T, database *db.DB)) {
	t.Helper()
	for _, tgt := range dbtest.Targets(t) {
		tgt := tgt
		t.Run(tgt.Name, func(t *testing.T) {
			fn(t, tgt.DB)
		})
	}
}

// discardLogger is a *slog.Logger a test can hand to New without its
// Warn/Error lines cluttering `go test -v` output -- the tests
// themselves assert on database state, not log lines.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func mustSetSetting(t *testing.T, database *db.DB, key store.SettingKey, value string) {
	t.Helper()
	if err := store.SetSetting(context.Background(), database, key, value, time.Now().UTC()); err != nil {
		t.Fatalf("SetSetting(%s): %v", key, err)
	}
}

func insertHoneypotCanary(t *testing.T, database *db.DB, id, ports string, lastSeenAddr string) {
	t.Helper()
	if err := store.InsertCanary(context.Background(), database, store.Canary{
		ID: id, Name: id, Lane: "lan", Kind: agentkind.Honeypot, Ports: ports, EnrolledAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("InsertCanary(%s): %v", id, err)
	}
	if lastSeenAddr != "" {
		if err := store.SetCanaryLastSeenAddr(context.Background(), database, id, lastSeenAddr); err != nil {
			t.Fatalf("SetCanaryLastSeenAddr(%s): %v", id, err)
		}
	}
}

func selfTestRunCount(t *testing.T, database *db.DB, canaryID string) int {
	t.Helper()
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM self_test_runs WHERE canary_id = ?`, canaryID).Scan(&n); err != nil {
		t.Fatalf("count self_test_runs for %s: %v", canaryID, err)
	}
	return n
}

// TestTickDisabledMintsNothing is issue #46's required test: with
// selftest_enabled = false, an eligible canary at its scheduled minute
// gets no command at all.
func TestTickDisabledMintsNothing(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "false")
		mustSetSetting(t, database, store.SettingSelfTestUseRotationSchedule, "false")
		mustSetSetting(t, database, store.SettingSelfTestSchedule, "04:12")
		insertHoneypotCanary(t, database, "canary-a", "22,80", "192.0.2.10")

		now := time.Date(2026, 1, 1, 4, 12, 0, 0, time.UTC)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())
		s.Tick(context.Background())

		if n := selfTestRunCount(t, database, "canary-a"); n != 0 {
			t.Fatalf("self_test_runs for canary-a = %d, want 0 (selftest disabled)", n)
		}
	})
}

// TestTickEnabledAtScheduleMintsOnePerEligibleCanary is issue #46's
// required test: enabled at HH:MM mints exactly one command per
// eligible canary, and none for a canary with no address.
func TestTickEnabledAtScheduleMintsOnePerEligibleCanary(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "true")
		mustSetSetting(t, database, store.SettingSelfTestUseRotationSchedule, "false")
		mustSetSetting(t, database, store.SettingSelfTestSchedule, "04:12")
		insertHoneypotCanary(t, database, "canary-eligible", "22,80", "192.0.2.10")
		insertHoneypotCanary(t, database, "canary-no-addr", "22", "") // never heartbeated over the ingest token

		now := time.Date(2026, 1, 1, 4, 12, 0, 0, time.UTC)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())
		s.Tick(context.Background())

		if n := selfTestRunCount(t, database, "canary-eligible"); n != 1 {
			t.Fatalf("self_test_runs for canary-eligible = %d, want 1", n)
		}
		if n := selfTestRunCount(t, database, "canary-no-addr"); n != 0 {
			t.Fatalf("self_test_runs for canary-no-addr = %d, want 0 (no last-seen address)", n)
		}
	})
}

// TestTickOutsideScheduledMinuteMintsNothing proves the schedule is
// exact-minute, not "at or after".
func TestTickOutsideScheduledMinuteMintsNothing(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "true")
		mustSetSetting(t, database, store.SettingSelfTestUseRotationSchedule, "false")
		mustSetSetting(t, database, store.SettingSelfTestSchedule, "04:12")
		insertHoneypotCanary(t, database, "canary-a", "22", "192.0.2.10")

		now := time.Date(2026, 1, 1, 4, 13, 0, 0, time.UTC) // one minute past the schedule
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())
		s.Tick(context.Background())

		if n := selfTestRunCount(t, database, "canary-a"); n != 0 {
			t.Fatalf("self_test_runs for canary-a = %d, want 0 (not the scheduled minute)", n)
		}
	})
}

// TestTickNeverMintsTwiceInTheSameMinute is issue #46 item 5b's
// required test: two ticks landing at the same scheduled minute (e.g. a
// restart, or a ticker firing twice close together) mint only once per
// canary.
func TestTickNeverMintsTwiceInTheSameMinute(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "true")
		mustSetSetting(t, database, store.SettingSelfTestUseRotationSchedule, "false")
		mustSetSetting(t, database, store.SettingSelfTestSchedule, "04:12")
		insertHoneypotCanary(t, database, "canary-a", "22", "192.0.2.10")

		now := time.Date(2026, 1, 1, 4, 12, 0, 0, time.UTC)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())
		s.Tick(context.Background())
		s.Tick(context.Background())

		if n := selfTestRunCount(t, database, "canary-a"); n != 1 {
			t.Fatalf("self_test_runs for canary-a after two ticks = %d, want 1", n)
		}
	})
}

// TestRotationSucceededMintsWhenUsingRotationSchedule is issue #46 item
// 5c's required test: with the rotation-coupled schedule on, minting
// happens the instant RotationSucceeded fires, not on a tick.
func TestRotationSucceededMintsWhenUsingRotationSchedule(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "true")
		mustSetSetting(t, database, store.SettingSelfTestUseRotationSchedule, "true")
		insertHoneypotCanary(t, database, "canary-a", "22", "192.0.2.10")

		now := time.Date(2026, 1, 1, 9, 30, 0, 0, time.UTC)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())

		// A tick at an arbitrary time must not mint anything itself --
		// see the scheduled-time test above for the non-rotation case;
		// this proves the rotation-coupled mode leaves ticks inert too.
		s.Tick(context.Background())
		if n := selfTestRunCount(t, database, "canary-a"); n != 0 {
			t.Fatalf("self_test_runs for canary-a after a tick (rotation-coupled mode) = %d, want 0", n)
		}

		s.RotationSucceeded(context.Background(), "canary-a", now)
		if n := selfTestRunCount(t, database, "canary-a"); n != 1 {
			t.Fatalf("self_test_runs for canary-a after RotationSucceeded = %d, want 1", n)
		}
	})
}

// TestRotationSucceededDoesNothingWhenNotUsingRotationSchedule: the
// rotation hook must stay inert when the operator has chosen the
// time-of-day schedule instead, or a rotation would mint an unwanted
// second self-test alongside the scheduled one.
func TestRotationSucceededDoesNothingWhenNotUsingRotationSchedule(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "true")
		mustSetSetting(t, database, store.SettingSelfTestUseRotationSchedule, "false")
		insertHoneypotCanary(t, database, "canary-a", "22", "192.0.2.10")

		now := time.Date(2026, 1, 1, 9, 30, 0, 0, time.UTC)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())
		s.RotationSucceeded(context.Background(), "canary-a", now)

		if n := selfTestRunCount(t, database, "canary-a"); n != 0 {
			t.Fatalf("self_test_runs for canary-a = %d, want 0 (schedule mode is time-of-day, not rotation-coupled)", n)
		}
	})
}

// TestRotationSucceededSkipsNonHoneypotCanary: a self-test command is
// never delivered to any kind but Honeypot (internal/ingest's
// ingestRoutes), so RotationSucceeded must not mint one for a Scanner
// even when the rotation-coupled schedule is on.
func TestRotationSucceededSkipsNonHoneypotCanary(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "true")
		mustSetSetting(t, database, store.SettingSelfTestUseRotationSchedule, "true")
		if err := store.InsertCanary(context.Background(), database, store.Canary{
			ID: "scanner-a", Name: "scanner-a", Lane: "lan", Kind: agentkind.Scanner, EnrolledAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("InsertCanary: %v", err)
		}
		if err := store.SetCanaryLastSeenAddr(context.Background(), database, "scanner-a", "192.0.2.20"); err != nil {
			t.Fatalf("SetCanaryLastSeenAddr: %v", err)
		}

		now := time.Date(2026, 1, 1, 9, 30, 0, 0, time.UTC)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())
		s.RotationSucceeded(context.Background(), "scanner-a", now)

		if n := selfTestRunCount(t, database, "scanner-a"); n != 0 {
			t.Fatalf("self_test_runs for scanner-a = %d, want 0 (self-test is honeypot-only)", n)
		}
	})
}

// TestRotationSucceededSkipsCanaryWithNoAddressOrUnknownCanary covers
// the two remaining early-outs: a canary with no last-seen address, and
// a canary id RotationSucceeded has never heard of.
func TestRotationSucceededSkipsCanaryWithNoAddressOrUnknownCanary(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "true")
		mustSetSetting(t, database, store.SettingSelfTestUseRotationSchedule, "true")
		insertHoneypotCanary(t, database, "canary-no-addr", "22", "")

		now := time.Date(2026, 1, 1, 9, 30, 0, 0, time.UTC)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())

		s.RotationSucceeded(context.Background(), "canary-no-addr", now)
		if n := selfTestRunCount(t, database, "canary-no-addr"); n != 0 {
			t.Fatalf("self_test_runs for canary-no-addr = %d, want 0 (no last-seen address)", n)
		}

		s.RotationSucceeded(context.Background(), "no-such-canary", now) // must not panic or error
		if n := selfTestRunCount(t, database, "no-such-canary"); n != 0 {
			t.Fatalf("self_test_runs for no-such-canary = %d, want 0", n)
		}
	})
}

// TestMintForCanarySkipsUnknownPortsButMintsKnownOnes: a port with no
// entry in store.WellKnownServiceForPort is skipped, not fatal to the
// whole mint, as long as at least one other port maps to a known
// service.
func TestMintForCanarySkipsUnknownPortsButMintsKnownOnes(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "true")
		mustSetSetting(t, database, store.SettingSelfTestUseRotationSchedule, "false")
		mustSetSetting(t, database, store.SettingSelfTestSchedule, "04:12")
		// 22 is ssh (known); 59999 maps to nothing in wellKnownPortNames.
		insertHoneypotCanary(t, database, "canary-a", "22,59999", "192.0.2.10")

		now := time.Date(2026, 1, 1, 4, 12, 0, 0, time.UTC)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())
		s.Tick(context.Background())

		if n := selfTestRunCount(t, database, "canary-a"); n != 1 {
			t.Fatalf("self_test_runs for canary-a = %d, want 1 (one known-service port is enough to mint)", n)
		}
	})
}

// TestMintForCanarySkipsCanaryWithNoKnownServicePorts: every port
// mapping to no known service means nothing to probe at all, so no
// command is minted for that canary.
func TestMintForCanarySkipsCanaryWithNoKnownServicePorts(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "true")
		mustSetSetting(t, database, store.SettingSelfTestUseRotationSchedule, "false")
		mustSetSetting(t, database, store.SettingSelfTestSchedule, "04:12")
		insertHoneypotCanary(t, database, "canary-a", "59999", "192.0.2.10")

		now := time.Date(2026, 1, 1, 4, 12, 0, 0, time.UTC)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())
		s.Tick(context.Background())

		if n := selfTestRunCount(t, database, "canary-a"); n != 0 {
			t.Fatalf("self_test_runs for canary-a = %d, want 0 (no port maps to a known service)", n)
		}
	})
}

// TestRunTicksOnItsOwnScheduleUntilContextCanceled exercises Run's
// ticker goroutine itself (not just Tick called directly), the same way
// cmd/nightjar's own heartbeat-loop test proves the real loop, not just
// its body.
func TestRunTicksOnItsOwnScheduleUntilContextCanceled(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "true")
		mustSetSetting(t, database, store.SettingSelfTestUseRotationSchedule, "false")

		now := time.Now().UTC()
		schedule := now.Format(scheduleTimeLayout)
		mustSetSetting(t, database, store.SettingSelfTestSchedule, schedule)
		insertHoneypotCanary(t, database, "canary-a", "22", "192.0.2.10")

		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			s.Run(ctx, 10*time.Millisecond)
			close(done)
		}()

		deadline := time.After(2 * time.Second)
		for {
			if selfTestRunCount(t, database, "canary-a") == 1 {
				break
			}
			select {
			case <-deadline:
				cancel()
				<-done
				t.Fatal("Run never minted a command for the eligible canary")
			case <-time.After(10 * time.Millisecond):
			}
		}

		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("Run did not return after its context was canceled")
		}
	})
}

// TestTickSweepsRunsPastTheirDeadline pins the sweep branch of Tick on
// its own: a run whose deadline has passed with a target still
// unmatched is closed as failed by the next tick, whether or not that
// tick minted anything. Without this the branch was only reached when
// TestRunTicksOnItsOwnScheduleUntilContextCanceled happened to tick a
// second time before cancel, which made the package's measured
// coverage swing by several points between runs.
func TestTickSweepsRunsPastTheirDeadline(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "true")
		mustSetSetting(t, database, store.SettingSelfTestUseRotationSchedule, "true")
		insertHoneypotCanary(t, database, "canary-a", "22", "192.0.2.10")

		issued := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
		idx := store.NewSelfTestIndex()
		if _, err := store.MintSelfTestCommand(context.Background(), database, idx, "canary-a", "192.0.2.10",
			[]store.SelfTestTarget{{Service: "ssh", DestPort: 22}}, issued, issued.Add(selfTestWindow)); err != nil {
			t.Fatalf("MintSelfTestCommand: %v", err)
		}

		now := issued.Add(selfTestWindow + time.Minute)
		s := New(database, idx, func() time.Time { return now }, discardLogger())
		s.Tick(context.Background())

		run, ok, err := store.LatestCompletedSelfTestRun(context.Background(), database, "canary-a")
		if err != nil {
			t.Fatalf("LatestCompletedSelfTestRun: %v", err)
		}
		if !ok {
			t.Fatal("run past its deadline was not completed by Tick")
		}
		if run.Passed == nil || *run.Passed {
			t.Errorf("Passed = %v, want false for a run nothing answered", run.Passed)
		}
	})
}

// TestSettingsUnreadableDoesNothing covers the settings-read error
// paths of Tick and RotationSucceeded deterministically: with the
// database closed under it, neither mints, neither panics, and the
// error is the only outcome (logged; the brief's "never fall back to a
// default schedule").
func TestSettingsUnreadableDoesNothing(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "true")
		insertHoneypotCanary(t, database, "canary-a", "22", "192.0.2.10")
		now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())

		if err := database.Close(); err != nil {
			t.Fatalf("close database: %v", err)
		}
		s.Tick(context.Background())
		s.RotationSucceeded(context.Background(), "canary-a", now)
		// Nothing to assert against a closed database beyond "returned
		// without panicking"; the mint paths all need it open.
	})
}

// TestTickSweepErrorIsLoggedNotFatal pins the sweep's own error path,
// which the Run-loop test otherwise reached only when cancel() landed
// mid-tick. With the runs table gone the settings still read fine, the
// tick reaches the sweep, and the sweep's failure ends the tick quietly.
func TestTickSweepErrorIsLoggedNotFatal(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mustSetSetting(t, database, store.SettingSelfTestEnabled, "true")
		mustSetSetting(t, database, store.SettingSelfTestUseRotationSchedule, "true")
		if _, err := database.ExecContext(context.Background(), `DROP TABLE self_test_runs`); err != nil {
			t.Fatalf("drop self_test_runs: %v", err)
		}
		now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
		s := New(database, store.NewSelfTestIndex(), func() time.Time { return now }, discardLogger())
		s.Tick(context.Background())
	})
}
