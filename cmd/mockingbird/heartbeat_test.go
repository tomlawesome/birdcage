package main

import (
	"strings"
	"testing"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/db"
)

// TestSendHeartbeatStoresReport proves sendHeartbeat's report reaches
// internal/ingest's real handler and is stored, the same way
// internal/agent/client/heartbeat_test.go proves it one layer down --
// here through this package's own loop function, current-token lookup
// included.
func TestSendHeartbeatStoresReport(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		c, _ := newIngestServer(t, database)
		token := mintToken(t, database, "canary-a")
		ts := &TokenStore{current: token}

		sendHeartbeat(ctx(), c, ts, func() client.SelfReport {
			return client.SelfReport{QueueDepth: 3, LogReadOK: true, LastEventID: validID1, AgentVersion: "9.9.9"}
		})

		var (
			version     string
			queueDepth  int
			logReadOK   int
			lastEventID string
		)
		row := database.QueryRow(
			`SELECT agent_version, agent_queue_depth, agent_log_read_ok, agent_last_event_id FROM canaries WHERE id = ?`,
			"canary-a")
		if err := row.Scan(&version, &queueDepth, &logReadOK, &lastEventID); err != nil {
			t.Fatalf("scan self-report columns: %v", err)
		}
		if version != "9.9.9" || queueDepth != 3 || logReadOK != 1 || lastEventID != validID1 {
			t.Errorf("stored = (%q, %d, %d, %q), want (\"9.9.9\", 3, 1, %q)", version, queueDepth, logReadOK, lastEventID, validID1)
		}
	})
}

// TestSendHeartbeatPersistentUnauthorizedLogsLoudly proves #48's
// fail-closed rule for a dead token: "log loudly ... keep every loop
// running." With no rotation happening concurrently, TokenStore's value
// is unchanged on authedRetry's re-check, so this is the "current token
// itself is refused" branch -- captured here by redirecting os.Stdout
// (internal/logging's component loggers write there, see
// captureStdout) and checking the loud message actually printed, since
// sendHeartbeat itself must not panic or block on this path.
func TestSendHeartbeatPersistentUnauthorizedLogsLoudly(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		c, _ := newIngestServer(t, database)
		ts := &TokenStore{current: "not-a-real-token"}

		out := captureStdout(t, func() {
			sendHeartbeat(ctx(), c, ts, func() client.SelfReport { return client.SelfReport{} })
		})

		if !strings.Contains(out, "re-enrolment") {
			t.Fatalf("log output = %q, want a loud re-enrolment message", out)
		}
	})
}
