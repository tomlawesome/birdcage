package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// enrollCanary registers id as a Honeypot -- the kind almost every test
// in this package wants; enrollCanaryKind is the same with the kind
// explicit, for scans_test.go's scanner-only route.
func enrollCanary(t *testing.T, database *db.DB, id string) {
	t.Helper()
	enrollCanaryKind(t, database, id, agentkind.Honeypot)
}

func enrollCanaryKind(t *testing.T, database *db.DB, id string, kind agentkind.Kind) {
	t.Helper()
	if err := store.InsertCanary(ctx(), database, store.Canary{
		ID: id, Name: id, Lane: "lan", Kind: kind,
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
		c, _ := newIngestServer(t, database, agentkind.Honeypot)
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
		c, _ := newIngestServer(t, database, agentkind.Honeypot)

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

// TestSendCommonHeartbeatStoresAgentVersion proves the common-only
// heartbeat (issue #106) decodes into internal/ingest's real handler
// correctly against a Scanner-kind token, mirroring
// TestSendHeartbeatStoresSelfReport's own shape for the richer one.
func TestSendCommonHeartbeatStoresAgentVersion(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		c, _ := newIngestServer(t, database, agentkind.Scanner)
		token := mintToken(t, database, "canary-a")

		if err := c.SendCommonHeartbeat(ctx(), token, CommonHeartbeat{AgentVersion: "1.2.3"}); err != nil {
			t.Fatalf("SendCommonHeartbeat: %v", err)
		}

		var version string
		if err := database.QueryRow(`SELECT agent_version FROM canaries WHERE id = ?`, "canary-a").Scan(&version); err != nil {
			t.Fatalf("scan agent_version: %v", err)
		}
		if version != "1.2.3" {
			t.Errorf("agent_version = %q, want %q", version, "1.2.3")
		}
	})
}

// TestSendCommonHeartbeatUnauthorized mirrors TestSendHeartbeatUnauthorized.
func TestSendCommonHeartbeatUnauthorized(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		c, _ := newIngestServer(t, database, agentkind.Scanner)

		err := c.SendCommonHeartbeat(ctx(), "not-a-real-token", CommonHeartbeat{AgentVersion: "1.0.0"})
		if !IsUnauthorized(err) {
			t.Fatalf("err = %v, want ErrUnauthorized", err)
		}
	})
}

// TestSendCommonHeartbeatWireCarriesRunAndDBRefresh proves the wire body
// carries ADR-0012's run and db_refresh objects, against a plain test
// server rather than internal/ingest's real handler (its own MR lands
// separately) -- this proves the client's own encoding.
func TestSendCommonHeartbeatWireCarriesRunAndDBRefresh(t *testing.T) {
	var gotBody map[string]any
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	failingSince := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	lastOK := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	err := c.SendCommonHeartbeat(ctx(), "tok", CommonHeartbeat{
		AgentVersion: "1.2.3",
		Run:          &RunReport{RunID: "run-1", Stage: "db_refreshed"},
		DBRefresh:    &DBRefreshReport{LastOKAt: lastOK, FailingSince: failingSince, LastError: "mirror down"},
	})
	if err != nil {
		t.Fatalf("SendCommonHeartbeat: %v", err)
	}

	run, _ := gotBody["run"].(map[string]any)
	if run == nil || run["run_id"] != "run-1" || run["stage"] != "db_refreshed" {
		t.Errorf("run = %v, want {run_id: run-1, stage: db_refreshed}", run)
	}
	dbr, _ := gotBody["db_refresh"].(map[string]any)
	if dbr == nil {
		t.Fatal("db_refresh missing from body")
	}
	if dbr["last_ok_at"] != "2026-09-22T10:00:00Z" {
		t.Errorf("db_refresh.last_ok_at = %v, want 2026-09-22T10:00:00Z", dbr["last_ok_at"])
	}
	if dbr["failing_since"] != "2026-09-23T10:00:00Z" {
		t.Errorf("db_refresh.failing_since = %v, want 2026-09-23T10:00:00Z", dbr["failing_since"])
	}
	if dbr["last_error"] != "mirror down" {
		t.Errorf("db_refresh.last_error = %v, want %q", dbr["last_error"], "mirror down")
	}
}

// TestSendCommonHeartbeatWireOmitsRunAndDBRefreshWhenUnset proves an
// ordinary healthy heartbeat -- no run, no failing refresh -- carries
// neither object, exactly as today.
func TestSendCommonHeartbeatWireOmitsRunAndDBRefreshWhenUnset(t *testing.T) {
	var gotBody map[string]any
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	if err := c.SendCommonHeartbeat(ctx(), "tok", CommonHeartbeat{AgentVersion: "1.2.3"}); err != nil {
		t.Fatalf("SendCommonHeartbeat: %v", err)
	}

	if _, present := gotBody["run"]; present {
		t.Errorf("run present in body, want omitted: %v", gotBody["run"])
	}
	if _, present := gotBody["db_refresh"]; present {
		t.Errorf("db_refresh present in body, want omitted: %v", gotBody["db_refresh"])
	}
}

// TestDBRefreshReportNullsWhenLastOKAtZero proves last_ok_at is an
// explicit JSON null, never omitted or a zero-value time string, when no
// refresh has ever succeeded -- the wire contract's own "<RFC3339>|null"
// shape for that field.
func TestDBRefreshReportNullsWhenLastOKAtZero(t *testing.T) {
	var gotBody map[string]any
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	err := c.SendCommonHeartbeat(ctx(), "tok", CommonHeartbeat{
		AgentVersion: "1.0.0",
		DBRefresh:    &DBRefreshReport{FailingSince: time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC), LastError: "no db yet"},
	})
	if err != nil {
		t.Fatalf("SendCommonHeartbeat: %v", err)
	}

	dbr, _ := gotBody["db_refresh"].(map[string]any)
	if dbr == nil {
		t.Fatal("db_refresh missing from body")
	}
	if v, present := dbr["last_ok_at"]; !present || v != nil {
		t.Errorf("db_refresh.last_ok_at = %v (present=%v), want explicit null", v, present)
	}
}
