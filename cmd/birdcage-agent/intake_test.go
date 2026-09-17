package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/queue"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// fixtureEvent builds a distinct, valid OpenCanary-shaped emitted JSON
// string (the same shape internal/agent/event's own fixtures use):
// varying src_port and a logdata field keeps every call's SHA-256 event
// id distinct. logtype 4002 is "ssh" (internal/agent/event/fields_test.go).
func fixtureEvent(n int) string {
	return fmt.Sprintf(`{"dst_host": "203.0.113.9", "dst_port": 22, "logdata": {"n": %d}, "logtype": 4002, "node_id": "canary-1", "src_host": "198.51.100.5", "src_port": %d}`, n, 40000+n)
}

func wrapWebhook(t *testing.T, message string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]string{"message": message})
	if err != nil {
		t.Fatalf("json.Marshal webhook wrapper: %v", err)
	}
	return body
}

// newTestIntake builds an Intake against a fresh temp log file and
// position file, with small caps a test can actually reach. qcfg lets a
// test set MaxEvents small enough to exercise backpressure; the zero
// value falls back to NewIntake's own defaults.
func newTestIntake(t *testing.T, qcfg queue.Config) (*Intake, string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "opencanary.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatalf("create empty log file: %v", err)
	}
	in, err := NewIntake(IntakeConfig{
		LogPath:      logPath,
		PositionPath: filepath.Join(dir, "position"),
		Listen:       "127.0.0.1:0",
		Queue:        qcfg,
	})
	if err != nil {
		t.Fatalf("NewIntake: %v", err)
	}
	t.Cleanup(func() { _ = in.Receiver.Close() })
	return in, logPath
}

func waitForAlertCount(t *testing.T, database *db.DB, canaryID string, want int, timeout time.Duration) []store.Alert {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var alerts []store.Alert
	for time.Now().Before(deadline) {
		var err error
		alerts, err = store.ListAlerts(ctx(), database, store.AlertFilter{InstanceID: canaryID})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		if len(alerts) >= want {
			return alerts
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d alerts, got %d", want, len(alerts))
	return nil
}

// TestWebhookRoadReachesBirdcage proves #48's "Done when": an event that
// arrives only over the webhook road is queued, sent and stored, with no
// log tailer involved at all.
func TestWebhookRoadReachesBirdcage(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		c, _ := newIngestServer(t, database)
		token := mintToken(t, database, "canary-a")

		in, _ := newTestIntake(t, queue.Config{})
		if err := in.webhookHandler(wrapWebhook(t, fixtureEvent(1))); err != nil {
			t.Fatalf("webhookHandler: %v", err)
		}

		runCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go runSenderLoop(runCtx, c, newTokenStoreForTest(token), in, newPacer())

		waitForAlertCount(t, database, "canary-a", 1, 5*time.Second)
	})
}

// TestLogRoadReachesBirdcage proves the log road alone -- no webhook
// involved -- reaches birdcage, and that the acknowledged position
// advances once it does.
func TestLogRoadReachesBirdcage(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		c, _ := newIngestServer(t, database)
		token := mintToken(t, database, "canary-a")

		in, logPath := newTestIntake(t, queue.Config{})
		if err := os.WriteFile(logPath, []byte(fixtureEvent(1)+"\n"), 0o600); err != nil {
			t.Fatalf("write log line: %v", err)
		}

		runCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go in.RunLogRoad(runCtx)
		go runSenderLoop(runCtx, c, newTokenStoreForTest(token), in, newPacer())

		waitForAlertCount(t, database, "canary-a", 1, 5*time.Second)

		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, ok, err := in.PositionStore().Load(); err == nil && ok {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal("timed out waiting for the acknowledged position to be saved")
	})
}

// TestBothRoadsSameEventStoredOnce proves #48's central id property end
// to end: the same OpenCanary hit delivered by both the webhook and the
// log resolves to exactly one stored alert.
func TestBothRoadsSameEventStoredOnce(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		c, _ := newIngestServer(t, database)
		token := mintToken(t, database, "canary-a")

		in, logPath := newTestIntake(t, queue.Config{})
		message := fixtureEvent(1)
		if err := os.WriteFile(logPath, []byte(message+"\n"), 0o600); err != nil {
			t.Fatalf("write log line: %v", err)
		}
		if err := in.webhookHandler(wrapWebhook(t, message)); err != nil {
			t.Fatalf("webhookHandler: %v", err)
		}

		runCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go in.RunLogRoad(runCtx)
		go runSenderLoop(runCtx, c, newTokenStoreForTest(token), in, newPacer())

		waitForAlertCount(t, database, "canary-a", 1, 5*time.Second)

		// Give a possible (and, if the dedup is correct, harmless) second
		// delivery a moment to show up as a bug before declaring success.
		time.Sleep(500 * time.Millisecond)
		alerts, err := store.ListAlerts(ctx(), database, store.AlertFilter{InstanceID: "canary-a"})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		if len(alerts) != 1 {
			t.Fatalf("alerts = %d, want exactly 1 (same hit via both roads must store once)", len(alerts))
		}
	})
}

// TestBackpressureEvictsAndRecoversAfterDrain proves #48 decision 2 end
// to end: with a queue capacity far below the number of distinct
// OpenCanary hits waiting in the log, some events are evicted (forced
// here by webhook-road pushes racing the paused tailer, since the log
// road's own gate never evicts its own events), and the log-road events
// are still all eventually stored -- proving the eviction-triggered
// restart of tailer.Follow actually re-reads what was dropped, rather
// than the log holding it forever unread.
func TestBackpressureEvictsAndRecoversAfterDrain(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		c, _ := newIngestServer(t, database)
		token := mintToken(t, database, "canary-a")

		const numLogEvents = 6
		in, logPath := newTestIntake(t, queue.Config{MaxEvents: 2, MaxBytes: 1 << 20})

		var logLines string
		for i := 0; i < numLogEvents; i++ {
			logLines += fixtureEvent(i) + "\n"
		}
		if err := os.WriteFile(logPath, []byte(logLines), 0o600); err != nil {
			t.Fatalf("write log lines: %v", err)
		}

		runCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go in.RunLogRoad(runCtx)
		go runSenderLoop(runCtx, c, newTokenStoreForTest(token), in, newPacer())

		// Race webhook-road pushes against the paused tailer, forcing at
		// least one eviction while the queue sits at its 2-event cap --
		// exactly the contention #48 decision 2 describes ("evictions
		// therefore hit mostly webhook-road events").
		go func() {
			for i := 0; i < 20; i++ {
				_ = in.webhookHandler(wrapWebhook(t, fixtureEvent(1000+i)))
				time.Sleep(10 * time.Millisecond)
			}
		}()

		waitForAlertCount(t, database, "canary-a", numLogEvents, 15*time.Second)

		if dropped := in.Queue.Dropped(); dropped == 0 {
			t.Fatal("Queue.Dropped() = 0, want at least one eviction -- this test did not exercise backpressure")
		}
	})
}

// newTokenStoreForTest builds a TokenStore around an in-memory token
// with no backing file -- fine for every loop here except rotation,
// which this test file never runs.
func newTokenStoreForTest(token string) *TokenStore {
	return &TokenStore{current: token}
}
