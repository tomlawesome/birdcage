// Package store is birdcage's query layer backing the dashboard API
// (#3). It is read-only over the alerts table: all inserts there stay in
// internal/ingest, which is the only writer the alerts table has. It
// does own the write path for the separate canaries/heartbeats registry
// (issue #34, canary.go) -- POST /api/heartbeat and canary enrollment --
// since that data belongs to this layer's own tables, not to ingested
// honeypot data.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// receivedAtLayout is the exact layout internal/ingest/server.go writes
// to the received_at column (time.RFC3339Nano, always UTC via
// time.Now().UTC()). Every read and every filter bound in this package
// uses the same layout, so a value round-trips through SQLite unchanged.
const receivedAtLayout = time.RFC3339Nano

// Alert is one OpenCanary hit as read back from the alerts table.
type Alert struct {
	ID         int64     `json:"id"`
	InstanceID string    `json:"instance_id"`
	SourceIP   string    `json:"source_ip"`
	DestPort   int       `json:"dest_port"`
	Service    string    `json:"service"`
	Raw        string    `json:"raw"`
	ReceivedAt time.Time `json:"received_at"`
}

// AlertFilter narrows ListAlerts. Every field is optional: an empty
// string, a zero time.Time, or a zero Before applies no constraint on
// that field.
type AlertFilter struct {
	InstanceID string
	SourceIP   string
	Service    string
	// Since and Until bound received_at, both inclusive.
	Since time.Time
	Until time.Time
	// Before is a paging cursor: only alerts with id < Before are
	// returned. Zero means "no cursor" -- start from the newest row.
	Before int64
	// Limit caps the number of rows returned. See NormalizeLimit for the
	// default/cap rule.
	Limit int
}

const (
	defaultLimit = 100
	maxLimit     = 1000
)

// NormalizeLimit applies AlertFilter.Limit's defaulting/capping rule: a
// limit <= 0 becomes defaultLimit, and anything above maxLimit is capped
// to it. Exported so the API handler can compute the exact same
// effective page size ListAlerts used (to decide whether a page was
// short, i.e. whether next_before should be null) without duplicating
// the two numbers above.
func NormalizeLimit(limit int) int {
	if limit <= 0 {
		return defaultLimit
	}
	if limit > maxLimit {
		return maxLimit
	}
	return limit
}

// timeCompare returns the SQL fragment that compares column against a
// bound parameter with op (">=", "<=", or "<"), using whichever
// mechanism the engine needs to compare it as an instant rather than as
// text:
//
// RFC3339Nano encoding trims trailing zeros from the fractional seconds
// (time.Time.Format's documented behavior: 0.5s formats as ".5", 0s
// formats with no fractional part at all), so two timestamps that differ
// only in how many digits got trimmed can compare backwards under a raw
// TEXT >=/<= -- e.g. "...:00Z" sorts *after* "...:00.5Z" as plain text,
// even though the first instant is earlier. SQLite's julianday() and
// Postgres' ::timestamptz cast both parse the text into a real,
// comparable value first, so the comparison is numeric and correct
// regardless of trimming. See
// TestListAlertsSinceHandlesTrimmedFractionalSeconds.
//
// Every TEXT timestamp column in this package (alerts.received_at,
// canaries.enrolled_at/last_heartbeat_at, heartbeats.at) goes through
// this one function rather than each growing its own comparison, per
// AGENTS.md's "reuse the mechanism, don't invent a second one".
func timeCompare(engine db.Engine, column, op string) string {
	if engine == db.Postgres {
		return column + "::timestamptz " + op + " ?::timestamptz"
	}
	return "julianday(" + column + ") " + op + " julianday(?)"
}

// receivedAtCompare is timeCompare pinned to alerts.received_at, kept as
// its own name since every call site in this file already reads that
// way.
func receivedAtCompare(engine db.Engine, op string) string {
	return timeCompare(engine, "received_at", op)
}

// ListAlerts returns alerts matching filter, newest first. Ordering is
// "ORDER BY id DESC" rather than by received_at: db.Open forces every
// SQLite access through a single connection (SetMaxOpenConns(1)), so the
// ingest server's inserts are fully serialized and id order already
// agrees with receipt order -- there is no case where a later id has an
// earlier received_at. (Postgres does not share this constraint, but
// nothing here writes concurrently to alerts on either engine, so the
// same ordering argument holds regardless.)
func ListAlerts(ctx context.Context, database *db.DB, filter AlertFilter) ([]Alert, error) {
	limit := NormalizeLimit(filter.Limit)

	var (
		where []string
		args  []any
	)
	if filter.InstanceID != "" {
		where = append(where, "instance_id = ?")
		args = append(args, filter.InstanceID)
	}
	if filter.SourceIP != "" {
		where = append(where, "source_ip = ?")
		args = append(args, filter.SourceIP)
	}
	if filter.Service != "" {
		where = append(where, "service = ?")
		args = append(args, filter.Service)
	}
	if !filter.Since.IsZero() {
		where = append(where, receivedAtCompare(database.Engine, ">="))
		args = append(args, filter.Since.UTC().Format(receivedAtLayout))
	}
	if !filter.Until.IsZero() {
		where = append(where, receivedAtCompare(database.Engine, "<="))
		args = append(args, filter.Until.UTC().Format(receivedAtLayout))
	}
	if filter.Before > 0 {
		where = append(where, "id < ?")
		args = append(args, filter.Before)
	}

	query := "SELECT id, instance_id, source_ip, dest_port, service, raw, received_at FROM alerts"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := database.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query alerts: %w", err)
	}
	defer rows.Close()

	return scanAlerts(rows, make([]Alert, 0, limit))
}

// scanAlerts drains rows (already SELECTed as id, instance_id, source_ip,
// dest_port, service, raw, received_at, in that order) into initial and
// returns it. Shared by ListAlerts and alertsInRange so the
// received_at-parsing and error-wrapping live in one place rather than
// two copies drifting apart. initial carries the caller's own choice of
// starting capacity and nil-ness -- ListAlerts passes a non-nil,
// zero-length slice so a page with no rows still encodes as JSON `[]`,
// not `null`.
func scanAlerts(rows *sql.Rows, initial []Alert) ([]Alert, error) {
	alerts := initial
	for rows.Next() {
		var (
			a          Alert
			receivedAt string
		)
		if err := rows.Scan(&a.ID, &a.InstanceID, &a.SourceIP, &a.DestPort, &a.Service, &a.Raw, &receivedAt); err != nil {
			return nil, fmt.Errorf("scan alert: %w", err)
		}
		t, err := time.Parse(receivedAtLayout, receivedAt)
		if err != nil {
			return nil, fmt.Errorf("parse received_at %q: %w", receivedAt, err)
		}
		a.ReceivedAt = t
		alerts = append(alerts, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate alerts: %w", err)
	}
	return alerts, nil
}

// alertsInRange returns every alert with received_at in [since, until]
// (inclusive both ends, the same bound GetStats' Last24h uses), newest
// first. Unlike ListAlerts, there is no row cap: GET /api/visitors and GET
// /api/trace (issue #35) both classify and aggregate over the *whole*
// range in Go rather than in SQL (per this package's kind-classification
// rule -- see internal/store/visitor.go), so a paginated fetch here would
// silently truncate the very data those computations depend on. Both
// callers apply their own bound afterward instead (visitor cursor paging,
// trace's per-canary maxHitsPerCanary cap).
func alertsInRange(ctx context.Context, database *db.DB, since, until time.Time) ([]Alert, error) {
	query := fmt.Sprintf(`
		SELECT id, instance_id, source_ip, dest_port, service, raw, received_at
		FROM alerts WHERE %s AND %s ORDER BY id DESC`,
		receivedAtCompare(database.Engine, ">="), receivedAtCompare(database.Engine, "<="))

	rows, err := database.QueryContext(ctx, query,
		since.UTC().Format(receivedAtLayout), until.UTC().Format(receivedAtLayout))
	if err != nil {
		return nil, fmt.Errorf("query alerts in range: %w", err)
	}
	defer rows.Close()

	return scanAlerts(rows, []Alert{})
}

// Instance summarizes one instance_id's alert history.
type Instance struct {
	InstanceID string    `json:"instance_id"`
	Count      int64     `json:"count"`
	LastSeen   time.Time `json:"last_seen"`
}

// ListInstances returns one row per distinct instance_id, ordered by
// instance_id, with its total alert count and most recent received_at.
//
// last_seen is read from the highest-id row per instance_id via a
// correlated subquery, not MAX(received_at): MAX on the TEXT column
// would hit the same trailing-zero comparison hazard ListAlerts' julianday
// comparisons avoid (see there). Comparing id directly is safe for the
// reason given in ListAlerts' doc comment: id order already agrees with
// receipt order.
func ListInstances(ctx context.Context, database *db.DB) ([]Instance, error) {
	const query = `
SELECT instance_id, COUNT(*),
    (SELECT received_at FROM alerts newest
        WHERE newest.instance_id = alerts.instance_id
        ORDER BY newest.id DESC LIMIT 1)
FROM alerts
GROUP BY instance_id
ORDER BY instance_id`

	rows, err := database.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query instances: %w", err)
	}
	defer rows.Close()

	instances := []Instance{}
	for rows.Next() {
		var (
			inst     Instance
			lastSeen string
		)
		if err := rows.Scan(&inst.InstanceID, &inst.Count, &lastSeen); err != nil {
			return nil, fmt.Errorf("scan instance: %w", err)
		}
		t, err := time.Parse(receivedAtLayout, lastSeen)
		if err != nil {
			return nil, fmt.Errorf("parse received_at %q: %w", lastSeen, err)
		}
		inst.LastSeen = t
		instances = append(instances, inst)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate instances: %w", err)
	}
	return instances, nil
}

// Stats is the dashboard's top-line summary.
type Stats struct {
	Total           int64 `json:"total"`
	Last24h         int64 `json:"last_24h"`
	DistinctSources int64 `json:"distinct_sources"`
	Instances       int64 `json:"instances"`
}

// GetStats summarizes the whole alerts table as of now, which the caller
// supplies rather than this function reading time.Now() itself, so tests
// can pin it.
func GetStats(ctx context.Context, database *db.DB, now time.Time) (Stats, error) {
	var s Stats
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts`).Scan(&s.Total); err != nil {
		return Stats{}, fmt.Errorf("count total: %w", err)
	}

	// Bounded above by now as well as below by now-24h: a received_at in
	// the future can only be forged (a real receipt time is always
	// birdcage's own time.Now(), per internal/ingest/server.go), and a
	// forged one should not inflate "in the last 24h".
	now = now.UTC()
	cutoff := now.Add(-24 * time.Hour).Format(receivedAtLayout)
	nowStr := now.Format(receivedAtLayout)
	last24hQuery := fmt.Sprintf("SELECT COUNT(*) FROM alerts WHERE %s AND %s",
		receivedAtCompare(database.Engine, ">="), receivedAtCompare(database.Engine, "<="))
	if err := database.QueryRowContext(ctx, last24hQuery, cutoff, nowStr).Scan(&s.Last24h); err != nil {
		return Stats{}, fmt.Errorf("count last 24h: %w", err)
	}

	if err := database.QueryRowContext(ctx, `SELECT COUNT(DISTINCT source_ip) FROM alerts`).Scan(&s.DistinctSources); err != nil {
		return Stats{}, fmt.Errorf("count distinct sources: %w", err)
	}

	if err := database.QueryRowContext(ctx, `SELECT COUNT(DISTINCT instance_id) FROM alerts`).Scan(&s.Instances); err != nil {
		return Stats{}, fmt.Errorf("count instances: %w", err)
	}
	return s, nil
}
