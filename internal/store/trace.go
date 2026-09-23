// The trace (issue #35): GET /api/trace serves everything ADR-0004's band
// draws for one canary line -- its status, its individual heartbeats in
// the stretched last 15 minutes, and its hits -- so the frontend does no
// aggregation of its own.
package store

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// maxHitsPerCanary caps how many of one canary's hits GET /api/trace
// returns, newest kept: the reference data story's repeat knocker (221
// hits from one source) must always arrive whole, while a flood from a
// genuinely busy canary can't make one response unbounded.
const maxHitsPerCanary = 2000

// traceBeatWindow is fixed regardless of the requested Range -- ADR-0004's
// band only ever draws individual heartbeats in the stretched last
// quarter hour, the same reasoning canary.go's heartbeatRetention already
// documents (which is a day, not 15 minutes, only because RecordHeartbeat
// prunes once per beat rather than once per read).
const traceBeatWindow = 15 * time.Minute

// TraceHit is one alert as GET /api/trace's per-canary hit list shows it.
// Field names and JSON shape match frontend/src/lib/types.ts's TraceHit
// exactly. Unlike Visitor.Tried (a deduplicated top-4 list), Tried here is
// the single triedFor summary for this one hit.
type TraceHit struct {
	At      time.Time   `json:"at"`
	Visitor string      `json:"visitor"`
	Kind    VisitorKind `json:"kind"`
	Service string      `json:"service"`
	Tried   string      `json:"tried"`
}

// TraceCanary is one canary's line in the trace. Field names match
// frontend/src/lib/types.ts's TraceCanary exactly.
type TraceCanary struct {
	ID              string      `json:"id"`
	Lane            string      `json:"lane"`
	Status          string      `json:"status"`
	LastHeartbeatAt *time.Time  `json:"last_heartbeat_at"`
	Beats           []time.Time `json:"beats"`
	Hits            []TraceHit  `json:"hits"`
}

// Trace is GET /api/trace's whole response body.
type Trace struct {
	Now      time.Time     `json:"now"`
	Range    string        `json:"range"`
	Canaries []TraceCanary `json:"canaries"`
	// LastHit is the single newest alert in the *whole* alerts table,
	// independent of Range -- nil when the table has no alerts at all.
	// The dashboard's "quiet for N days" sentence needs this: a trace
	// scoped to the requested range can't answer it once the last real
	// hit falls outside every range shorter than N days.
	LastHit *LastHit `json:"last_hit"`
}

// LastHit is Trace.LastHit. Kind is classified against Visitor's own
// *entire* alert history, not just the alerts inside Range -- a source
// last seen three weeks ago that also knocked on three earlier distinct
// days should still show as repeat, which a range-scoped classification
// would miss once the range no longer spans all of those days.
type LastHit struct {
	At      time.Time   `json:"at"`
	Visitor string      `json:"visitor"`
	Canary  string      `json:"canary"`
	Port    int         `json:"port"`
	Service string      `json:"service"`
	Kind    VisitorKind `json:"kind"`
}

// ListTrace assembles Trace for rangeStr (already validated by ParseRange
// into rangeWindow, the same pair GET /api/canaries takes): per-canary
// status and last_heartbeat_at via ListCanaries (reused rather than
// re-querying the canaries table), each canary's beats within
// traceBeatWindow (independent of rangeWindow), and each canary's hits --
// alerts within rangeWindow, newest maxHitsPerCanary kept. A hit's kind is
// classified against every hit its source made anywhere in rangeWindow,
// not just against this one canary -- the same inputs GET /api/visitors
// classifies from, so the two endpoints never disagree about a source's
// kind.
func ListTrace(ctx context.Context, database *db.DB, now time.Time, rangeStr string, rangeWindow time.Duration, internalRanges []*net.IPNet) (Trace, error) {
	now = now.UTC()

	canaries, err := ListCanaries(ctx, database, now, rangeWindow)
	if err != nil {
		return Trace{}, fmt.Errorf("list canaries: %w", err)
	}

	beats, err := beatsByCanary(ctx, database, now, traceBeatWindow)
	if err != nil {
		return Trace{}, fmt.Errorf("list beats: %w", err)
	}

	alerts, err := alertsInRange(ctx, database, now.Add(-rangeWindow), now)
	if err != nil {
		return Trace{}, fmt.Errorf("list alerts: %w", err)
	}

	// alertsInRange returns newest first; bucketing by source and by
	// canary in a single pass over that order each preserve it, which is
	// exactly what maxHitsPerCanary's "keep the front of the slice" cap
	// needs (classifyKind's own input order doesn't matter).
	hitsBySource := map[string][]hitPoint{}
	hitsByCanary := map[string][]Alert{}
	for _, a := range alerts {
		hitsBySource[a.SourceIP] = append(hitsBySource[a.SourceIP], hitPoint{At: a.ReceivedAt, CanaryID: a.InstanceID})
		hitsByCanary[a.InstanceID] = append(hitsByCanary[a.InstanceID], a)
	}

	kindBySource := make(map[string]VisitorKind, len(hitsBySource))
	for ip, hits := range hitsBySource {
		kindBySource[ip] = classifyKind(ip, hits, internalRanges)
	}

	out := make([]TraceCanary, 0, len(canaries))
	for _, c := range canaries {
		canaryHits := hitsByCanary[c.ID]
		if len(canaryHits) > maxHitsPerCanary {
			canaryHits = canaryHits[:maxHitsPerCanary]
		}
		hits := make([]TraceHit, 0, len(canaryHits))
		for _, a := range canaryHits {
			hits = append(hits, TraceHit{
				At:      a.ReceivedAt,
				Visitor: a.SourceIP,
				Kind:    kindBySource[a.SourceIP],
				Service: a.Service,
				Tried:   triedFor(a.Service, a.Raw),
			})
		}
		canaryBeats := beats[c.ID]
		if canaryBeats == nil {
			canaryBeats = []time.Time{}
		}
		out = append(out, TraceCanary{
			ID:              c.ID,
			Lane:            c.Lane,
			Status:          c.Status,
			LastHeartbeatAt: c.LastHeartbeatAt,
			Beats:           canaryBeats,
			Hits:            hits,
		})
	}

	lastHit, err := buildLastHit(ctx, database, internalRanges)
	if err != nil {
		return Trace{}, fmt.Errorf("last hit: %w", err)
	}

	return Trace{Now: now, Range: rangeStr, Canaries: out, LastHit: lastHit}, nil
}

// buildLastHit finds the single newest alert in the whole alerts table
// (unbounded by rangeWindow -- see LastHit's doc comment) and classifies
// it against that source's entire history. Returns nil, nil when the
// table has no alerts at all.
func buildLastHit(ctx context.Context, database *db.DB, internalRanges []*net.IPNet) (*LastHit, error) {
	newest, ok, err := newestAlert(ctx, database)
	if err != nil {
		return nil, fmt.Errorf("query newest alert: %w", err)
	}
	if !ok {
		return nil, nil
	}

	history, err := alertsForSource(ctx, database, newest.SourceIP)
	if err != nil {
		return nil, fmt.Errorf("query alert history for %s: %w", newest.SourceIP, err)
	}
	hits := make([]hitPoint, 0, len(history))
	for _, a := range history {
		hits = append(hits, hitPoint{At: a.ReceivedAt, CanaryID: a.InstanceID})
	}

	return &LastHit{
		At:      newest.ReceivedAt,
		Visitor: newest.SourceIP,
		Canary:  newest.InstanceID,
		Port:    newest.DestPort,
		Service: newest.Service,
		Kind:    classifyKind(newest.SourceIP, hits, internalRanges),
	}, nil
}

// newestAlert returns the single newest row in the alerts table (highest
// id, which -- per ListAlerts' own doc comment -- agrees with received_at
// order), or ok=false when the table is empty.
func newestAlert(ctx context.Context, database *db.DB) (Alert, bool, error) {
	// synthetic = 0 (issue #46 item 2): buildLastHit's "quiet for N
	// days" hero sentence must never be answered by birdcage's own
	// self-test traffic.
	rows, err := database.QueryContext(ctx, `
		SELECT id, instance_id, source_ip, dest_port, service, raw, received_at, synthetic
		FROM alerts WHERE synthetic = 0 ORDER BY id DESC LIMIT 1`)
	if err != nil {
		return Alert{}, false, fmt.Errorf("query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	alerts, err := scanAlerts(rows, []Alert{})
	if err != nil {
		return Alert{}, false, err
	}
	if len(alerts) == 0 {
		return Alert{}, false, nil
	}
	return alerts[0], true, nil
}

// alertsForSource returns every alert ever received from sourceIP, newest
// first, with no time bound -- buildLastHit's own use is the only one
// that needs a source's whole history rather than one range.
func alertsForSource(ctx context.Context, database *db.DB, sourceIP string) ([]Alert, error) {
	// synthetic = 0 (issue #46 item 2): buildLastHit classifies this
	// source's kind (VisitorKind) from its whole history, which must be
	// its whole history of *real* hits.
	rows, err := database.QueryContext(ctx, `
		SELECT id, instance_id, source_ip, dest_port, service, raw, received_at, synthetic
		FROM alerts WHERE source_ip = ? AND synthetic = 0 ORDER BY id DESC`, sourceIP)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanAlerts(rows, []Alert{})
}

// beatsByCanary returns each canary's heartbeat timestamps within window
// of now (inclusive both ends), newest first, keyed by canary_id.
func beatsByCanary(ctx context.Context, database *db.DB, now time.Time, window time.Duration) (map[string][]time.Time, error) {
	since := now.Add(-window).Format(receivedAtLayout)
	nowStr := now.Format(receivedAtLayout)
	query := fmt.Sprintf(`
		SELECT canary_id, at FROM heartbeats
		WHERE %s AND %s
		ORDER BY canary_id, at DESC`,
		timeCompare(database.Engine, "at", ">="), timeCompare(database.Engine, "at", "<="))

	rows, err := database.QueryContext(ctx, query, since, nowStr)
	if err != nil {
		return nil, fmt.Errorf("query heartbeats: %w", err)
	}
	defer func() { _ = rows.Close() }()

	beats := make(map[string][]time.Time)
	for rows.Next() {
		var (
			canaryID string
			at       string
		)
		if err := rows.Scan(&canaryID, &at); err != nil {
			return nil, fmt.Errorf("scan heartbeat: %w", err)
		}
		t, err := time.Parse(receivedAtLayout, at)
		if err != nil {
			return nil, fmt.Errorf("parse heartbeat at %q: %w", at, err)
		}
		beats[canaryID] = append(beats[canaryID], t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate heartbeats: %w", err)
	}
	return beats, nil
}
