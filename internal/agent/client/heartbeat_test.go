package client

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

func enrollCanary(t *testing.T, database *db.DB, id string) {
	t.Helper()
	if err := store.InsertCanary(ctx(), database, store.Canary{
		ID: id, Name: id, Lane: "lan", Kind: agentkind.Honeypot,
		EnrolledAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("InsertCanary(%s): %v", id, err)
	}
}

// TestSendHeartbeatStoresSelfReport proves the self-report this package
// sends decodes into internal/ingest's real handler correctly, field for
// field, by reading it back from the database exactly like
// internal/ingest/heartbeat_test.go's own equivalent test. This covers
// #48's process-composition note (gap 3) end to end: the agent-side
// SelfReport struct -> wireHeartbeat -> ingest's handler -> store ->
// read back, for the dropped/rejected/event-id-collision counters and
// the position-found flag alongside the original four fields.
func TestSendHeartbeatStoresSelfReport(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		c, _ := newIngestServer(t, database)
		token := mintToken(t, database, "canary-a")

		err := c.SendHeartbeat(ctx(), token, SelfReport{
			QueueDepth:        7,
			LogReadOK:         true,
			LastEventID:       validID1,
			AgentVersion:      "1.2.3",
			Dropped:           4,
			Rejected:          1,
			EventIDCollisions: 0,
			PositionFound:     true,
		})
		if err != nil {
			t.Fatalf("SendHeartbeat: %v", err)
		}

		var (
			version                                      string
			queueDepth                                   int
			logReadOK                                    int
			lastEvent                                    string
			dropped, rejected, collisions, positionFound *int64
		)
		row := database.QueryRow(
			`SELECT agent_version, agent_queue_depth, agent_log_read_ok, agent_last_event_id,
				agent_dropped, agent_rejected, agent_event_id_collisions, agent_position_found
			FROM canaries WHERE id = ?`,
			"canary-a")
		if err := row.Scan(&version, &queueDepth, &logReadOK, &lastEvent, &dropped, &rejected, &collisions, &positionFound); err != nil {
			t.Fatalf("scan self-report columns: %v", err)
		}
		if version != "1.2.3" || queueDepth != 7 || logReadOK != 1 || lastEvent != validID1 {
			t.Errorf("stored self-report = (%q, %d, %d, %q), want (\"1.2.3\", 7, 1, %q)",
				version, queueDepth, logReadOK, lastEvent, validID1)
		}
		if dropped == nil || *dropped != 4 {
			t.Errorf("agent_dropped = %v, want 4", dropped)
		}
		if rejected == nil || *rejected != 1 {
			t.Errorf("agent_rejected = %v, want 1", rejected)
		}
		if collisions == nil || *collisions != 0 {
			t.Errorf("agent_event_id_collisions = %v, want 0 (explicitly reported, not absent)", collisions)
		}
		if positionFound == nil || *positionFound != 1 {
			t.Errorf("agent_position_found = %v, want 1 (true)", positionFound)
		}
	})
}

// TestSendHeartbeatUnauthorized proves a dead token surfaces as
// ErrUnauthorized.
func TestSendHeartbeatUnauthorized(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		c, _ := newIngestServer(t, database)

		err := c.SendHeartbeat(ctx(), "not-a-real-token", SelfReport{AgentVersion: "1.0.0"})
		if !IsUnauthorized(err) {
			t.Fatalf("err = %v, want ErrUnauthorized", err)
		}
	})
}

// TestSendHeartbeatRetryableOn429 proves a rate-limited heartbeat is
// reported as retryable, matching #32 item 8's "crossing a limit is
// recorded and surfaced, never a silent discard".
func TestSendHeartbeatRetryableOn429(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate limit exceeded"}`))
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	err := c.SendHeartbeat(ctx(), "tok", SelfReport{AgentVersion: "1.0.0"})
	if !IsRetryable(err) {
		t.Fatalf("err = %v, want a *RetryableError", err)
	}
}
