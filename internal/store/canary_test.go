package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
)

// insertCanary defaults c.Kind to agentkind.Honeypot when the caller
// left it unset -- InsertCanary itself (issue #105) requires a valid
// kind and no longer defaults one, but every canary this package's own
// tests have ever built is a honeypot, so this fixture helper carries
// that default rather than every call site repeating it.
func insertCanary(t *testing.T, database *db.DB, c Canary) {
	t.Helper()
	if c.Kind == "" {
		c.Kind = agentkind.Honeypot
	}
	if err := InsertCanary(context.Background(), database, c); err != nil {
		t.Fatalf("InsertCanary(%+v): %v", c, err)
	}
}

func listCanaries(t *testing.T, database *db.DB, now time.Time, rangeWindow time.Duration) []Canary {
	t.Helper()
	canaries, err := ListCanaries(context.Background(), database, now, rangeWindow)
	if err != nil {
		t.Fatalf("ListCanaries: %v", err)
	}
	return canaries
}

func findCanary(t *testing.T, canaries []Canary, id string) Canary {
	t.Helper()
	for _, c := range canaries {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no canary %q in %+v", id, canaries)
	return Canary{}
}

func TestInsertCanaryAndListFields(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrolledAt := mustParse(t, "2026-01-01T00:00:00Z")
		insertCanary(t, database, Canary{
			ID: "canary-lan", Name: "canary-lan", Lane: "lan",
			Ports: "22,80,445", HeartbeatIntervalS: 60, EnrolledAt: enrolledAt,
		})

		canaries := listCanaries(t, database, enrolledAt, rangeDurations[DefaultRange])
		if len(canaries) != 1 {
			t.Fatalf("got %d canaries, want 1: %+v", len(canaries), canaries)
		}
		c := canaries[0]
		if c.ID != "canary-lan" || c.Name != "canary-lan" || c.Lane != "lan" {
			t.Errorf("canary = %+v, want id/name/lane canary-lan/canary-lan/lan", c)
		}
		if c.Ports != "ssh 22 · http 80 · smb 445" {
			t.Errorf("Ports = %q, want %q", c.Ports, "ssh 22 · http 80 · smb 445")
		}
		if c.LastHeartbeatAt != nil {
			t.Errorf("LastHeartbeatAt = %v, want nil (never beaten)", c.LastHeartbeatAt)
		}
		if c.Hits != 0 {
			t.Errorf("Hits = %d, want 0 (no alerts inserted)", c.Hits)
		}
	})
}

func TestPortsDisplayUnknownPortShownBare(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrolledAt := mustParse(t, "2026-01-01T00:00:00Z")
		insertCanary(t, database, Canary{
			ID: "canary-x", Name: "canary-x", Lane: "lan",
			Ports: "22,9999", HeartbeatIntervalS: 60, EnrolledAt: enrolledAt,
		})

		c := findCanary(t, listCanaries(t, database, enrolledAt, rangeDurations[DefaultRange]), "canary-x")
		if c.Ports != "ssh 22 · 9999" {
			t.Errorf("Ports = %q, want %q", c.Ports, "ssh 22 · 9999")
		}
	})
}

func TestCanaryStatusOkWithinThreeIntervals(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrolledAt := mustParse(t, "2026-01-01T00:00:00Z")
		insertCanary(t, database, Canary{
			ID: "canary-a", Name: "canary-a", Lane: "lan",
			HeartbeatIntervalS: 60, EnrolledAt: enrolledAt,
		})
		beatAt := mustParse(t, "2026-01-01T01:00:00Z")
		if err := RecordHeartbeat(context.Background(), database, "canary-a", beatAt); err != nil {
			t.Fatalf("RecordHeartbeat: %v", err)
		}

		// Exactly 3 * 60s after the beat: still "ok" (inclusive threshold).
		now := beatAt.Add(180 * time.Second)
		c := findCanary(t, listCanaries(t, database, now, rangeDurations[DefaultRange]), "canary-a")
		if c.Status != "ok" {
			t.Errorf("Status = %q at exactly the threshold, want ok", c.Status)
		}
		if c.SilentForS != nil || c.BeatsMissed != nil {
			t.Errorf("SilentForS/BeatsMissed set while ok: %v/%v", c.SilentForS, c.BeatsMissed)
		}
		if c.LastHeartbeatAt == nil || !c.LastHeartbeatAt.Equal(beatAt) {
			t.Errorf("LastHeartbeatAt = %v, want %v", c.LastHeartbeatAt, beatAt)
		}
	})
}

func TestCanaryStatusSilentPastThreshold(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrolledAt := mustParse(t, "2026-01-01T00:00:00Z")
		insertCanary(t, database, Canary{
			ID: "canary-b", Name: "canary-b", Lane: "lan",
			HeartbeatIntervalS: 60, EnrolledAt: enrolledAt,
		})
		beatAt := mustParse(t, "2026-01-01T01:00:00Z")
		if err := RecordHeartbeat(context.Background(), database, "canary-b", beatAt); err != nil {
			t.Fatalf("RecordHeartbeat: %v", err)
		}

		// One second past 3 * 60s: silent.
		now := beatAt.Add(181 * time.Second)
		c := findCanary(t, listCanaries(t, database, now, rangeDurations[DefaultRange]), "canary-b")
		if c.Status != "silent" {
			t.Fatalf("Status = %q, want silent", c.Status)
		}
		if c.SilentForS == nil || *c.SilentForS != 181 {
			t.Errorf("SilentForS = %v, want 181", c.SilentForS)
		}
		if c.BeatsMissed == nil || *c.BeatsMissed != 3 {
			t.Errorf("BeatsMissed = %v, want 3 (181/60)", c.BeatsMissed)
		}
	})
}

func TestCanaryStatusSilentNeverBeaten(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrolledAt := mustParse(t, "2026-01-01T00:00:00Z")
		insertCanary(t, database, Canary{
			ID: "canary-c", Name: "canary-c", Lane: "lan",
			HeartbeatIntervalS: 60, EnrolledAt: enrolledAt,
		})

		now := enrolledAt.Add(500 * time.Second)
		c := findCanary(t, listCanaries(t, database, now, rangeDurations[DefaultRange]), "canary-c")
		if c.Status != "silent" {
			t.Fatalf("Status = %q, want silent (never beaten)", c.Status)
		}
		if c.SilentForS == nil || *c.SilentForS != 500 {
			t.Errorf("SilentForS = %v, want 500 (measured from enrolled_at)", c.SilentForS)
		}
		if c.LastHeartbeatAt != nil {
			t.Errorf("LastHeartbeatAt = %v, want nil", c.LastHeartbeatAt)
		}
	})
}

func TestRecordHeartbeatUnknownCanary(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		err := RecordHeartbeat(context.Background(), database, "no-such-canary", time.Now())
		if !errors.Is(err, ErrCanaryNotFound) {
			t.Fatalf("RecordHeartbeat(unknown) = %v, want ErrCanaryNotFound", err)
		}
	})
}

func TestRecordHeartbeatPrunesOlderThan24h(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrolledAt := mustParse(t, "2026-01-01T00:00:00Z")
		insertCanary(t, database, Canary{
			ID: "canary-d", Name: "canary-d", Lane: "lan",
			HeartbeatIntervalS: 60, EnrolledAt: enrolledAt,
		})

		old := mustParse(t, "2026-01-01T00:00:00Z")
		if err := RecordHeartbeat(context.Background(), database, "canary-d", old); err != nil {
			t.Fatalf("RecordHeartbeat(old): %v", err)
		}

		// 25h later: RecordHeartbeat's own prune should remove the row
		// above (older than 24h of the new beat) but keep the new one.
		recent := old.Add(25 * time.Hour)
		if err := RecordHeartbeat(context.Background(), database, "canary-d", recent); err != nil {
			t.Fatalf("RecordHeartbeat(recent): %v", err)
		}

		var n int
		if err := database.QueryRow(`SELECT COUNT(*) FROM heartbeats WHERE canary_id = ?`, "canary-d").Scan(&n); err != nil {
			t.Fatalf("count heartbeats: %v", err)
		}
		if n != 1 {
			t.Errorf("heartbeats for canary-d = %d, want 1 (old one pruned)", n)
		}
	})
}

func TestListCanariesHitsPerRange(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrolledAt := mustParse(t, "2026-01-01T00:00:00Z")
		insertCanary(t, database, Canary{
			ID: "node-1", Name: "canary-1", Lane: "lan",
			HeartbeatIntervalS: 60, EnrolledAt: enrolledAt,
		})
		insertFixtures(t, database) // node-1/node-2/node-3 alerts, 2026-01-01..05

		now := mustParse(t, "2026-01-05T12:00:00Z")
		// node-1 fixture rows: id1 (01-01), id2 (01-01), id6 (01-03), id9 (01-05) = 4 total.
		c14d := findCanary(t, listCanaries(t, database, now, rangeDurations["14d"]), "node-1")
		if c14d.Hits != 4 {
			t.Errorf("Hits over 14d = %d, want 4", c14d.Hits)
		}
		c24h := findCanary(t, listCanaries(t, database, now, rangeDurations["24h"]), "node-1")
		if c24h.Hits != 1 {
			t.Errorf("Hits over 24h = %d, want 1 (only id9, 2026-01-05)", c24h.Hits)
		}
	})
}

func TestParseRangeDefaultAndUnknown(t *testing.T) {
	d, err := ParseRange("")
	if err != nil {
		t.Fatalf("ParseRange(\"\"): %v", err)
	}
	if d != rangeDurations[DefaultRange] {
		t.Errorf("ParseRange(\"\") = %v, want default %v", d, rangeDurations[DefaultRange])
	}

	for _, r := range []string{"15m", "1h", "24h", "14d", "90d"} {
		if _, err := ParseRange(r); err != nil {
			t.Errorf("ParseRange(%q): %v", r, err)
		}
	}

	if _, err := ParseRange("7d"); err == nil {
		t.Error("ParseRange(\"7d\") = nil error, want an error (not a recognized range)")
	}
}

// TestRecordCanaryAgentHeartbeatStoresReport is #32 slice 5a's storage
// half: the agent's self-report fields land against the canary, and
// last_heartbeat_at advances exactly as RecordHeartbeat's own does.
func TestRecordCanaryAgentHeartbeatStoresReport(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrolledAt := mustParse(t, "2026-01-01T00:00:00Z")
		insertCanary(t, database, Canary{
			ID: "canary-a", Name: "canary-a", Lane: "lan",
			HeartbeatIntervalS: 60, EnrolledAt: enrolledAt,
		})

		beatAt := mustParse(t, "2026-01-01T01:00:00Z")
		report := AgentHeartbeat{QueueDepth: 7, LogReadOK: true, LastEventID: "abc123", AgentVersion: "1.2.3"}
		if err := RecordCanaryAgentHeartbeat(context.Background(), database, "canary-a", beatAt, report); err != nil {
			t.Fatalf("RecordCanaryAgentHeartbeat: %v", err)
		}

		canaries := listCanaries(t, database, beatAt, rangeDurations[DefaultRange])
		c := findCanary(t, canaries, "canary-a")
		if c.LastHeartbeatAt == nil || !c.LastHeartbeatAt.Equal(beatAt) {
			t.Errorf("LastHeartbeatAt = %v, want %v", c.LastHeartbeatAt, beatAt)
		}

		var (
			version    string
			queueDepth int
			logReadOK  int
			lastEvent  string
		)
		row := database.QueryRow(
			`SELECT agent_version, agent_queue_depth, agent_log_read_ok, agent_last_event_id FROM canaries WHERE id = ?`,
			"canary-a")
		if err := row.Scan(&version, &queueDepth, &logReadOK, &lastEvent); err != nil {
			t.Fatalf("scan self-report columns: %v", err)
		}
		if version != "1.2.3" || queueDepth != 7 || logReadOK != 1 || lastEvent != "abc123" {
			t.Errorf("stored self-report = (%q, %d, %d, %q), want (\"1.2.3\", 7, 1, \"abc123\")",
				version, queueDepth, logReadOK, lastEvent)
		}
	})
}

// TestRecordCanaryAgentHeartbeatUnknownCanary mirrors RecordHeartbeat's
// own contract: an unregistered canary id reports ErrCanaryNotFound and
// touches nothing.
func TestRecordCanaryAgentHeartbeatUnknownCanary(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		err := RecordCanaryAgentHeartbeat(context.Background(), database, "no-such-canary",
			mustParse(t, "2026-01-01T00:00:00Z"), AgentHeartbeat{AgentVersion: "1.0.0"})
		if !errors.Is(err, ErrCanaryNotFound) {
			t.Fatalf("RecordCanaryAgentHeartbeat(unknown canary) = %v, want ErrCanaryNotFound", err)
		}
	})
}
