package mail

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

func agentsBehindLatest(t *testing.T, database *db.DB) *store.MailMessage {
	t.Helper()
	m, err := store.LatestMail(context.Background(), database, store.MailKindAgentsBehind, "")
	if err != nil {
		t.Fatalf("LatestMail(agents_behind): %v", err)
	}
	return m
}

// TestEnqueueAgentsBehindSendsOnceADay is issue #54's whole daily rule:
// one call with agents behind writes one message, a second call the
// same UTC day writes nothing more (even with a different, larger list),
// and a call the next day writes a fresh one.
func TestEnqueueAgentsBehindSendsOnceADay(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		sender := enqueueSender(database)
		start := pinnedNow

		alert := AgentsBehindAlert{
			BirdcageVersion: "1.2.3",
			Agents: []AgentBehindEntry{
				{CanaryID: "canary-lan", CanaryName: "canary-lan", Lane: "lan", AgentVersion: "1.0.0"},
			},
			At: start,
		}
		if err := sender.EnqueueAgentsBehind(ctx, database, alert); err != nil {
			t.Fatalf("first enqueue: %v", err)
		}
		if got := pendingCount(t, database); got != 1 {
			t.Fatalf("after the first check, %d messages are owed, want 1", got)
		}
		first := agentsBehindLatest(t, database)
		if !strings.Contains(first.Body, "canary-lan") || !strings.Contains(first.Body, "1.0.0") {
			t.Errorf("first message does not list the behind agent:\n%s", first.Body)
		}

		// Later the same UTC day, with a second agent now behind too:
		// still no second message, and the first is left exactly as it
		// was (it does not grow to include the second agent).
		later := start.Add(6 * time.Hour)
		alert2 := AgentsBehindAlert{
			BirdcageVersion: "1.2.3",
			Agents: []AgentBehindEntry{
				{CanaryID: "canary-lan", CanaryName: "canary-lan", Lane: "lan", AgentVersion: "1.0.0"},
				{CanaryID: "canary-iot", CanaryName: "canary-iot", Lane: "iot", AgentVersion: "1.1.0"},
			},
			At: later,
		}
		if err := sender.EnqueueAgentsBehind(ctx, database, alert2); err != nil {
			t.Fatalf("second enqueue, same day: %v", err)
		}
		if got := pendingCount(t, database); got != 1 {
			t.Fatalf("a second check the same day was mailed (%d owed, want 1)", got)
		}
		if body := agentsBehindLatest(t, database).Body; strings.Contains(body, "canary-iot") {
			t.Errorf("the same-day check rewrote the existing message:\n%s", body)
		}

		// The next UTC day: a fresh message.
		tomorrow := start.Add(24 * time.Hour)
		if err := sender.EnqueueAgentsBehind(ctx, database, AgentsBehindAlert{
			BirdcageVersion: "1.2.3",
			Agents:          alert2.Agents,
			At:              tomorrow,
		}); err != nil {
			t.Fatalf("third enqueue, next day: %v", err)
		}
		if got := pendingCount(t, database); got != 2 {
			t.Fatalf("after the next day's check, %d messages are owed, want 2", got)
		}
	})
}

// TestEnqueueAgentsBehindNothingBehindIsANoOp: an empty list -- nothing
// currently behind -- must never write a message, even the first time
// it is called.
func TestEnqueueAgentsBehindNothingBehindIsANoOp(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		sender := enqueueSender(database)
		if err := sender.EnqueueAgentsBehind(ctx, database, AgentsBehindAlert{BirdcageVersion: "1.2.3", At: pinnedNow}); err != nil {
			t.Fatalf("enqueue with nothing behind: %v", err)
		}
		if got := pendingCount(t, database); got != 0 {
			t.Errorf("%d messages owed with nothing behind, want 0", got)
		}
	})
}

// TestEnqueueAgentsBehindNilSenderIsANoOp mirrors
// TestNilSenderEnqueueIsANoOp: cmd/birdcage's way of saying mail is off
// must not panic or error.
func TestEnqueueAgentsBehindNilSenderIsANoOp(t *testing.T) {
	var s *Sender
	alert := AgentsBehindAlert{
		BirdcageVersion: "1.2.3",
		Agents:          []AgentBehindEntry{{CanaryID: "canary-lan", CanaryName: "canary-lan", Lane: "lan", AgentVersion: "1.0.0"}},
		At:              pinnedNow,
	}
	if err := s.EnqueueAgentsBehind(context.Background(), nil, alert); err != nil {
		t.Errorf("EnqueueAgentsBehind on a nil Sender: %v", err)
	}
}

// TestAgentsBehindBodyMentionsUpgradeButNoCommand: #54's own rule --
// this message points at each canary's own page for the exact upgrade
// command, and never composes or carries one itself (that field is a
// separate change's to add).
func TestAgentsBehindBodyMentionsUpgradeButNoCommand(t *testing.T) {
	body := AgentsBehindBody(AgentsBehindAlert{
		BirdcageVersion: "1.2.3",
		Agents:          []AgentBehindEntry{{CanaryID: "canary-lan", CanaryName: "canary-lan", Lane: "lan", AgentVersion: "1.0.0"}},
		At:              pinnedNow,
	})
	if !strings.Contains(body, "1.2.3") || !strings.Contains(body, "1.0.0") {
		t.Errorf("body does not mention both versions:\n%s", body)
	}
	if strings.Contains(body, "http://") || strings.Contains(body, "https://") {
		t.Errorf("body carries a link, which #54 rules out:\n%s", body)
	}
}
