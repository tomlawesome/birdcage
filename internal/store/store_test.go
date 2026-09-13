package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/db/dbtest"
)

// forEachEngine runs fn once per database engine dbtest.Targets returns
// for this test run (always SQLite, plus Postgres when
// BIRDCAGE_TEST_DATABASE_URL is set -- see issue #7), each as its own
// subtest so a Postgres-only failure is reported distinctly from
// SQLite's result.
func forEachEngine(t *testing.T, fn func(t *testing.T, database *db.DB)) {
	t.Helper()
	for _, tgt := range dbtest.Targets(t) {
		tgt := tgt
		t.Run(tgt.Name, func(t *testing.T) {
			fn(t, tgt.DB)
		})
	}
}

// fixtureAlert is one row of the fixture set insertFixtures loads.
type fixtureAlert struct {
	id         int64
	instanceID string
	sourceIP   string
	destPort   int
	service    string
	receivedAt string // pre-formatted, deliberately varying fractional-second width
}

// fixtures spans three instances, four source IPs and three services
// over five days (2026-01-01 through 2026-01-05), inserted in id order
// (lowest id = earliest). A few receivedAt values are chosen with
// trimmed fractional seconds (".5", ".25", ".999999999", no fraction at
// all) specifically to exercise the timestamp comparison
// receivedAtCompare's doc comment explains -- see
// TestListAlertsSinceHandlesTrimmedFractionalSeconds.
var fixtures = []fixtureAlert{
	{1, "node-1", "203.0.113.9", 22, "ssh", "2026-01-01T00:00:00Z"},
	{2, "node-1", "203.0.113.10", 23, "telnet", "2026-01-01T12:00:00.5Z"},
	{3, "node-2", "203.0.113.9", 80, "http", "2026-01-02T00:00:00Z"},
	{4, "node-2", "198.51.100.8", 8080, "http", "2026-01-02T06:00:00.25Z"},
	{5, "node-3", "198.51.100.9", 22, "ssh", "2026-01-03T00:00:00Z"},
	{6, "node-1", "203.0.113.9", 22, "ssh", "2026-01-03T00:00:00.999999999Z"},
	{7, "node-2", "198.51.100.8", 23, "telnet", "2026-01-04T00:00:00Z"},
	{8, "node-3", "198.51.100.9", 80, "http", "2026-01-04T00:00:00.1Z"},
	{9, "node-1", "203.0.113.10", 22, "ssh", "2026-01-05T00:00:00Z"},
	{10, "node-2", "198.51.100.8", 8080, "http", "2026-01-05T00:00:00.5Z"},
}

func insertFixtures(t *testing.T, database *db.DB) {
	t.Helper()
	for _, f := range fixtures {
		_, err := database.Exec(
			`INSERT INTO alerts (instance_id, source_ip, dest_port, service, raw, received_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			f.instanceID, f.sourceIP, f.destPort, f.service, rawFor(f.id), f.receivedAt,
		)
		if err != nil {
			t.Fatalf("insert fixture %d: %v", f.id, err)
		}
	}
}

// rawFor is the fixture's placeholder for the alerts.raw column -- unique
// per row so a round-trip test can confirm it came back unmodified.
func rawFor(id int64) string {
	return fmt.Sprintf("raw-%d", id)
}

func idsOf(alerts []Alert) []int64 {
	ids := make([]int64, len(alerts))
	for i, a := range alerts {
		ids[i] = a.ID
	}
	return ids
}

func mustParse(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return tm
}

func assertIDs(t *testing.T, got []Alert, want []int64) {
	t.Helper()
	gotIDs := idsOf(got)
	if len(gotIDs) != len(want) {
		t.Fatalf("got %d alerts %v, want %d %v", len(gotIDs), gotIDs, len(want), want)
	}
	for i := range want {
		if gotIDs[i] != want[i] {
			t.Fatalf("alert %d: got id %v, want %v (full got=%v, want=%v)", i, gotIDs[i], want[i], gotIDs, want)
		}
	}
}

func TestListAlertsNoFilterOrdering(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertFixtures(t, database)

		alerts, err := ListAlerts(context.Background(), database, AlertFilter{})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		assertIDs(t, alerts, []int64{10, 9, 8, 7, 6, 5, 4, 3, 2, 1})

		// The full row, not just the id, must round-trip correctly.
		first := alerts[0]
		if first.InstanceID != "node-2" || first.SourceIP != "198.51.100.8" || first.DestPort != 8080 ||
			first.Service != "http" || first.Raw != rawFor(10) {
			t.Errorf("alerts[0] = %+v, want the fixture row for id 10", first)
		}
		if !first.ReceivedAt.Equal(mustParse(t, "2026-01-05T00:00:00.5Z")) {
			t.Errorf("alerts[0].ReceivedAt = %v, want 2026-01-05T00:00:00.5Z", first.ReceivedAt)
		}
	})
}

func TestListAlertsFilterInstanceID(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertFixtures(t, database)

		alerts, err := ListAlerts(context.Background(), database, AlertFilter{InstanceID: "node-2"})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		assertIDs(t, alerts, []int64{10, 7, 4, 3})
	})
}

func TestListAlertsFilterSourceIP(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertFixtures(t, database)

		// 203.0.113.9 spans two different instances (node-1 and node-2), so
		// this filter must not collapse to the instance filter's result.
		alerts, err := ListAlerts(context.Background(), database, AlertFilter{SourceIP: "203.0.113.9"})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		assertIDs(t, alerts, []int64{6, 3, 1})
	})
}

func TestListAlertsFilterService(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertFixtures(t, database)

		alerts, err := ListAlerts(context.Background(), database, AlertFilter{Service: "telnet"})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		assertIDs(t, alerts, []int64{7, 2})
	})
}

func TestListAlertsCombinedFilters(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertFixtures(t, database)

		alerts, err := ListAlerts(context.Background(), database, AlertFilter{InstanceID: "node-2", Service: "http"})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		assertIDs(t, alerts, []int64{10, 4, 3})
	})
}

// TestListAlertsSinceHandlesTrimmedFractionalSeconds proves the
// timestamp-aware comparison receivedAtCompare's doc comment describes:
// a naive `received_at >= ?` TEXT comparison would incorrectly include
// fixture row 5 (received "2026-01-03T00:00:00Z", no fractional
// seconds) when filtering Since "2026-01-03T00:00:00.5Z", because
// "...:00Z" sorts after "...:00.5Z" as plain text even though the
// instant it names is earlier. Row 5 must be excluded; row 6 (genuinely
// later) must still be included.
func TestListAlertsSinceHandlesTrimmedFractionalSeconds(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertFixtures(t, database)

		since := mustParse(t, "2026-01-03T00:00:00.5Z")
		alerts, err := ListAlerts(context.Background(), database, AlertFilter{Since: since})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		assertIDs(t, alerts, []int64{10, 9, 8, 7, 6})
	})
}

func TestListAlertsUntilInclusive(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertFixtures(t, database)

		until := mustParse(t, "2026-01-02T06:00:00.25Z") // exactly fixture row 4's received_at
		alerts, err := ListAlerts(context.Background(), database, AlertFilter{Until: until})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		assertIDs(t, alerts, []int64{4, 3, 2, 1})
	})
}

func TestListAlertsSinceAndUntilRange(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertFixtures(t, database)

		alerts, err := ListAlerts(context.Background(), database, AlertFilter{
			Since: mustParse(t, "2026-01-02T00:00:00Z"),
			Until: mustParse(t, "2026-01-04T00:00:00Z"),
		})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		assertIDs(t, alerts, []int64{7, 6, 5, 4, 3})
	})
}

func TestListAlertsLimitDefaultAndCap(t *testing.T) {
	if got := NormalizeLimit(0); got != defaultLimit {
		t.Errorf("NormalizeLimit(0) = %d, want %d", got, defaultLimit)
	}
	if got := NormalizeLimit(-5); got != defaultLimit {
		t.Errorf("NormalizeLimit(-5) = %d, want %d", got, defaultLimit)
	}
	if got := NormalizeLimit(5000); got != maxLimit {
		t.Errorf("NormalizeLimit(5000) = %d, want %d", got, maxLimit)
	}
	if got := NormalizeLimit(50); got != 50 {
		t.Errorf("NormalizeLimit(50) = %d, want 50", got)
	}

	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertFixtures(t, database)

		alerts, err := ListAlerts(context.Background(), database, AlertFilter{Limit: 0})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		if len(alerts) != len(fixtures) {
			t.Fatalf("default limit returned %d alerts, want all %d fixtures", len(alerts), len(fixtures))
		}
	})
}

func TestListAlertsCursorPaging(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertFixtures(t, database)

		var seen []int64
		before := int64(0)
		for page := 0; page < 10; page++ {
			alerts, err := ListAlerts(context.Background(), database, AlertFilter{Limit: 3, Before: before})
			if err != nil {
				t.Fatalf("ListAlerts page %d: %v", page, err)
			}
			if len(alerts) == 0 {
				break
			}
			if len(alerts) > 3 {
				t.Fatalf("page %d returned %d alerts, want at most 3", page, len(alerts))
			}
			seen = append(seen, idsOf(alerts)...)
			before = alerts[len(alerts)-1].ID
			if len(alerts) < 3 {
				break // short page: no more after this
			}
		}

		assertNoDuplicates(t, seen)
		want := []int64{10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
		if len(seen) != len(want) {
			t.Fatalf("cursor paging visited %v, want every id %v exactly once", seen, want)
		}
		for i := range want {
			if seen[i] != want[i] {
				t.Fatalf("cursor paging order = %v, want %v", seen, want)
			}
		}
	})
}

func assertNoDuplicates(t *testing.T, ids []int64) {
	t.Helper()
	seen := make(map[int64]bool, len(ids))
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("id %d returned more than once across pages: %v", id, ids)
		}
		seen[id] = true
	}
}

func TestListInstances(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertFixtures(t, database)

		instances, err := ListInstances(context.Background(), database)
		if err != nil {
			t.Fatalf("ListInstances: %v", err)
		}

		want := []Instance{
			{InstanceID: "node-1", Count: 4, LastSeen: mustParse(t, "2026-01-05T00:00:00Z")},
			{InstanceID: "node-2", Count: 4, LastSeen: mustParse(t, "2026-01-05T00:00:00.5Z")},
			{InstanceID: "node-3", Count: 2, LastSeen: mustParse(t, "2026-01-04T00:00:00.1Z")},
		}
		if len(instances) != len(want) {
			t.Fatalf("got %d instances, want %d: %+v", len(instances), len(want), instances)
		}
		for i, w := range want {
			got := instances[i]
			if got.InstanceID != w.InstanceID || got.Count != w.Count || !got.LastSeen.Equal(w.LastSeen) {
				t.Errorf("instance %d = %+v, want %+v", i, got, w)
			}
		}
	})
}

func TestGetStats(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertFixtures(t, database)

		now := mustParse(t, "2026-01-05T12:00:00Z")
		stats, err := GetStats(context.Background(), database, now)
		if err != nil {
			t.Fatalf("GetStats: %v", err)
		}

		want := Stats{Total: 10, Last24h: 2, DistinctSources: 4, Instances: 3}
		if stats != want {
			t.Errorf("GetStats = %+v, want %+v", stats, want)
		}
	})
}
