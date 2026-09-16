// Package store is birdcage's query layer backing the dashboard API
// (#3). Reading the alerts table is its main job. This package also owns
// two write paths of its own: the canaries/heartbeats registry (issue
// #34, canary.go) -- POST /api/heartbeat and canary enrollment -- and,
// as of issue #32, InsertAlertIfNew (this file), the sole writer of
// alert rows since slice 7 retired the old UDP syslog listener's own
// direct insert, and the canary_tokens table (token.go) for the
// token-authenticated ingest path that calls it.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// receivedAtLayout is the exact layout InsertAlertIfNew writes to the
// received_at column (time.RFC3339Nano, always UTC). Every read and
// every filter bound in this package uses the same layout, so a value
// round-trips through SQLite unchanged.
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

// AlertInsert is the row InsertAlertIfNew writes: instance_id,
// source_ip, dest_port, service, raw, received_at, plus EventID (issue
// #32), the SHA-256 hex digest of the JSON string OpenCanary emitted
// (#48), or empty for a caller with no event id -- the retired UDP
// syslog listener's own rows stay that way permanently (see
// migrations/*/0004_canary_tokens.sql).
//
// JSON tags (issue #44) are for internal/stream's Hub, which marshals an
// AlertInsert as-is onto GET /api/stream: nothing here decodes an
// AlertInsert from JSON, so adding tags is purely additive.
type AlertInsert struct {
	InstanceID string    `json:"instance_id"`
	SourceIP   string    `json:"source_ip"`
	DestPort   int       `json:"dest_port"`
	Service    string    `json:"service"`
	Raw        string    `json:"raw"`
	ReceivedAt time.Time `json:"received_at"`
	EventID    string    `json:"event_id,omitempty"`
}

// InsertAlertIfNew inserts a into alerts and reports whether it actually
// wrote a new row. This is the insert-or-ignore half of issue #32's
// dedup requirement: the same event delivered twice -- by both the
// agent's loopback road and its log-tail road, or replayed after a
// restart -- arrives with the same a.EventID, and the second call is a
// no-op (stored=false, err=nil), not an error. a.EventID == "" stores
// NULL rather than "": alerts.event_id's unique index treats every NULL
// as distinct (see the migration's own comment), so rows with no event
// id are deliberately never deduplicated against each other, matching
// pre-agent syslog-era rows. Dedup is scoped to one canary: the unique
// index is on (instance_id, event_id), so one canary's event id can
// never suppress another canary's alert (#32 research, 2026-09-15).
func InsertAlertIfNew(ctx context.Context, database *db.DB, a AlertInsert) (stored bool, err error) {
	var eventID any
	if a.EventID != "" {
		eventID = a.EventID
	}
	res, err := database.ExecContext(ctx, `
		INSERT INTO alerts (instance_id, source_ip, dest_port, service, raw, received_at, event_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (instance_id, event_id) DO NOTHING`,
		a.InstanceID, a.SourceIP, a.DestPort, a.Service, a.Raw, a.ReceivedAt.UTC().Format(receivedAtLayout), eventID)
	if err != nil {
		return false, fmt.Errorf("insert alert: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return n > 0, nil
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
	defer func() { _ = rows.Close() }()

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
	defer func() { _ = rows.Close() }()

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
	defer func() { _ = rows.Close() }()

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
