package driftsched

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/db/dbtest"
	"github.com/tomlawesome/birdcage/internal/mail"
	"github.com/tomlawesome/birdcage/internal/store"
)

// forEachEngine mirrors internal/store's, internal/ingest's and
// internal/selftestsched's own test helper of the same name.
func forEachEngine(t *testing.T, fn func(t *testing.T, database *db.DB)) {
	t.Helper()
	for _, tgt := range dbtest.Targets(t) {
		tgt := tgt
		t.Run(tgt.Name, func(t *testing.T) {
			fn(t, tgt.DB)
		})
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testSender is a *mail.Sender whose SMTP side is never dialed: Tick
// only ever calls EnqueueAgentsBehind, which writes to mail_outbox and
// never sends.
func testSender(database *db.DB) *mail.Sender {
	return mail.New(database, mail.Config{
		Host: "smtp.example.invalid:465", Username: "u", Password: "p", From: "a@example.invalid", To: "b@example.invalid",
	}, discardLogger())
}

func insertCanary(t *testing.T, database *db.DB, id, name, lane string, enrolledAt time.Time) {
	t.Helper()
	if err := store.InsertCanary(context.Background(), database, store.Canary{
		ID: id, Name: name, Lane: lane, Kind: agentkind.Honeypot, EnrolledAt: enrolledAt,
	}); err != nil {
		t.Fatalf("InsertCanary(%s): %v", id, err)
	}
}

func pendingMailCount(t *testing.T, database *db.DB) int {
	t.Helper()
	status, err := store.GetMailStatus(context.Background(), database)
	if err != nil {
		t.Fatalf("GetMailStatus: %v", err)
	}
	return status.Pending
}

// TestTickMailsWhenAnAgentIsBehind: one canary behind, birdcage version
// set -- Tick enqueues one agents_behind message naming it.
func TestTickMailsWhenAnAgentIsBehind(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		enrolledAt := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
		insertCanary(t, database, "canary-lan", "canary-lan", "lan", enrolledAt)
		beatAt := enrolledAt.Add(time.Minute)
		if err := store.RecordCanaryAgentHeartbeat(ctx, database, "canary-lan", beatAt, store.AgentHeartbeat{
			QueueDepth: 1, LogReadOK: true, LastEventID: "abc", AgentVersion: "1.0.0",
		}); err != nil {
			t.Fatalf("RecordCanaryAgentHeartbeat: %v", err)
		}

		now := beatAt.Add(time.Minute)
		s := New(database, testSender(database), "1.2.3", func() time.Time { return now }, discardLogger())
		s.Tick(ctx)

		if got := pendingMailCount(t, database); got != 1 {
			t.Fatalf("pending mail after Tick = %d, want 1", got)
		}
		m, err := store.LatestMail(ctx, database, store.MailKindAgentsBehind, "")
		if err != nil {
			t.Fatalf("LatestMail: %v", err)
		}
		if m == nil {
			t.Fatal("no agents_behind mail found")
		}
	})
}

// TestTickNoOpWhenNothingBehind: every agent up to date (or none
// enrolled) -- no mail at all, not even a zero-agent message.
func TestTickNoOpWhenNothingBehind(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		enrolledAt := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
		insertCanary(t, database, "canary-lan", "canary-lan", "lan", enrolledAt)
		beatAt := enrolledAt.Add(time.Minute)
		if err := store.RecordCanaryAgentHeartbeat(ctx, database, "canary-lan", beatAt, store.AgentHeartbeat{
			QueueDepth: 1, LogReadOK: true, LastEventID: "abc", AgentVersion: "1.2.3",
		}); err != nil {
			t.Fatalf("RecordCanaryAgentHeartbeat: %v", err)
		}

		now := beatAt.Add(time.Minute)
		s := New(database, testSender(database), "1.2.3", func() time.Time { return now }, discardLogger())
		s.Tick(ctx)

		if got := pendingMailCount(t, database); got != 0 {
			t.Fatalf("pending mail with nothing behind = %d, want 0", got)
		}
	})
}

// TestTickDoesNotMailTwiceTheSameDay: two ticks the same UTC day, both
// with the same agent behind, write only one message between them --
// internal/mail's own daily dedup, exercised through the scheduler a
// real deployment would drive it with.
func TestTickDoesNotMailTwiceTheSameDay(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		enrolledAt := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
		insertCanary(t, database, "canary-lan", "canary-lan", "lan", enrolledAt)
		beatAt := enrolledAt.Add(time.Minute)
		if err := store.RecordCanaryAgentHeartbeat(ctx, database, "canary-lan", beatAt, store.AgentHeartbeat{
			QueueDepth: 1, LogReadOK: true, LastEventID: "abc", AgentVersion: "1.0.0",
		}); err != nil {
			t.Fatalf("RecordCanaryAgentHeartbeat: %v", err)
		}

		now := beatAt.Add(time.Minute)
		sender := testSender(database)
		s := New(database, sender, "1.2.3", func() time.Time { return now }, discardLogger())
		s.Tick(ctx)
		if got := pendingMailCount(t, database); got != 1 {
			t.Fatalf("after the first tick, pending mail = %d, want 1", got)
		}

		// A second tick, three hours later, same UTC day: no new mail.
		later := now.Add(3 * time.Hour)
		s2 := New(database, sender, "1.2.3", func() time.Time { return later }, discardLogger())
		s2.Tick(ctx)
		if got := pendingMailCount(t, database); got != 1 {
			t.Fatalf("after the second tick (same day), pending mail = %d, want still 1", got)
		}

		// A tick the next UTC day: a second, fresh message.
		tomorrow := now.Add(24 * time.Hour)
		s3 := New(database, sender, "1.2.3", func() time.Time { return tomorrow }, discardLogger())
		s3.Tick(ctx)
		if got := pendingMailCount(t, database); got != 2 {
			t.Fatalf("after the next day's tick, pending mail = %d, want 2", got)
		}
	})
}

// TestTickNilSenderNeverQueries: mail off (nil *mail.Sender) must not
// even query the database -- a canary that would otherwise be behind is
// still not enough to make Tick do anything.
func TestTickNilSenderNeverQueries(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		enrolledAt := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
		insertCanary(t, database, "canary-lan", "canary-lan", "lan", enrolledAt)
		beatAt := enrolledAt.Add(time.Minute)
		if err := store.RecordCanaryAgentHeartbeat(ctx, database, "canary-lan", beatAt, store.AgentHeartbeat{
			QueueDepth: 1, LogReadOK: true, LastEventID: "abc", AgentVersion: "1.0.0",
		}); err != nil {
			t.Fatalf("RecordCanaryAgentHeartbeat: %v", err)
		}

		now := beatAt.Add(time.Minute)
		s := New(database, nil, "1.2.3", func() time.Time { return now }, discardLogger())
		s.Tick(ctx) // must not panic

		if got := pendingMailCount(t, database); got != 0 {
			t.Fatalf("pending mail with mail off = %d, want 0", got)
		}
	})
}
