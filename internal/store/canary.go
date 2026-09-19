package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// DefaultHeartbeatIntervalS is the heartbeat_interval_s a canary gets
// when InsertCanary's caller doesn't set one, matching migration
// 0003_canaries.sql's own column default.
const DefaultHeartbeatIntervalS = 60

// heartbeatRetention is how long a heartbeat row survives before
// RecordHeartbeat prunes it -- the band only ever draws individual beats
// in the stretched last quarter hour, so nothing older is read (issue
// #34).
const heartbeatRetention = 24 * time.Hour

// silenceThresholdMultiple is how many heartbeat_interval_s a canary can
// go without a beat before its status flips from "ok" to "silent".
const silenceThresholdMultiple = 3

// Canary is one enrolled OpenCanary instance's registry record, together
// with the status/hits snapshot ListCanaries computes as of the time and
// range it was asked for.
type Canary struct {
	ID                 string     `json:"id"`
	Name               string     `json:"name"`
	Lane               string     `json:"lane"`
	Ports              string     `json:"ports"` // display form, e.g. "ssh 22 · http 80 · smb 445"
	HeartbeatIntervalS int        `json:"-"`
	EnrolledAt         time.Time  `json:"-"`
	LastHeartbeatAt    *time.Time `json:"last_heartbeat_at"`

	// AgentLogReadOK is the agent's own last self-reported log-read
	// status (#32 slice 5a, canaries.agent_log_read_ok). nil means no
	// self-report has ever arrived, distinct from an explicit false --
	// see notDelivering's doc comment in health.go.
	AgentLogReadOK *bool `json:"-"`

	// AgentDropped, AgentRejected, AgentEventIDCollisions and
	// AgentPositionFound are the agent's last self-reported values for
	// #48's process-composition note (gap 3): cumulative events dropped
	// from the queue for capacity, cumulative permanently-rejected
	// events, cumulative event-id collisions (expected zero forever),
	// and whether the last tailer resume found the acknowledged position.
	// Each is nil exactly when the agent's most recent heartbeat didn't
	// carry that field -- an agent built before this change, or
	// mid-rollout -- which must never be confused with an explicit zero
	// or false. Same convention as AgentLogReadOK above.
	AgentDropped           *int64 `json:"-"`
	AgentRejected          *int64 `json:"-"`
	AgentEventIDCollisions *int64 `json:"-"`
	AgentPositionFound     *bool  `json:"-"`

	// Status is issue #45's ordered health state -- "token_conflict",
	// "silent", "not_delivering", "throttled", "rotation_stalled" or
	// "ok" -- the worst currently active state, computed by
	// applyStatus/applyHealthState. The field keeps its original JSON
	// name and shape (a plain string) for backward compatibility; only
	// the set of values it carries has widened from the original
	// ok/silent boolean.
	Status string `json:"status"`

	// SilentForS/BeatsMissed are set only when Status is "silent".
	SilentForS  *int64 `json:"silent_for_s,omitempty"`
	BeatsMissed *int64 `json:"beats_missed,omitempty"`

	// NotDelivering, ThrottledForS, RotationStalled* and
	// TokenConflictForS each report one state independently of which one
	// "won" Status -- issue #45: "one state on the tile, the worst; the
	// rest in its detail." Every field here is omitted (omitempty) when
	// its signal isn't currently active.
	NotDelivering            bool   `json:"not_delivering,omitempty"`
	ThrottledForS            *int64 `json:"throttled_for_s,omitempty"`
	RotationStalled          bool   `json:"rotation_stalled,omitempty"`
	RotationStalledForS      *int64 `json:"rotation_stalled_for_s,omitempty"`
	RotationStalledEscalated bool   `json:"rotation_stalled_escalated,omitempty"`
	TokenConflictForS        *int64 `json:"token_conflict_for_s,omitempty"`

	// ActiveStates is every state active on this canary right now,
	// worst first by healthStateRank -- the whole set Status names only
	// the head of. Issue #56's history needs all of it: a canary that
	// is silent and token-conflicted at once spent that time in two
	// states, and recording only the worst would lose the other one
	// exactly while they overlapped. Empty precisely when Status is
	// "ok" (no state active is what "ok" means), so it is omitted from
	// the JSON then, like the detail fields above.
	ActiveStates []string `json:"active_states,omitempty"`

	Hits int64 `json:"hits"`
}

// ErrCanaryNotFound is returned by RecordHeartbeat when canaryID names no
// row in the canaries table -- enrollment (#1) hasn't registered it, or
// it was mistyped. Callers map this to 404.
var ErrCanaryNotFound = errors.New("store: canary not found")

// wellKnownPortNames maps a handful of common OpenCanary module ports to
// the service name shown beside them (e.g. "ssh 22"). birdcage's own
// canaries table stores bare port numbers only (see
// migrations/sqlite/0003_canaries.sql) -- it has no visibility into the
// enrolled instance's own OpenCanary config, which is the only place a
// custom port-to-service mapping could otherwise come from -- so this is
// a static table of the module ports OpenCanary itself defaults to,
// good enough for the dashboard's presentation string. A port this table
// doesn't know is shown bare (just the number), never invented.
var wellKnownPortNames = map[string]string{
	"21":    "ftp",
	"22":    "ssh",
	"23":    "telnet",
	"25":    "smtp",
	"69":    "tftp",
	"80":    "http",
	"110":   "pop3",
	"123":   "ntp",
	"143":   "imap",
	"161":   "snmp",
	"389":   "ldap",
	"443":   "https",
	"445":   "smb",
	"1433":  "mssql",
	"3306":  "mysql",
	"3389":  "rdp",
	"5060":  "sip",
	"5432":  "postgresql",
	"5900":  "vnc",
	"6379":  "redis",
	"8080":  "http",
	"27017": "mongodb",
}

// portsDisplay formats raw (canaries.ports, a comma-separated list of
// bare port numbers, e.g. "22,80,445") into the "service port · service
// port" presentation string ADR-0004's tiles show, e.g.
// "ssh 22 · http 80 · smb 445". See wellKnownPortNames' doc comment for
// where the service names come from and its limits.
func portsDisplay(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, ",")
	display := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if name, ok := wellKnownPortNames[p]; ok {
			display = append(display, name+" "+p)
		} else {
			display = append(display, p)
		}
	}
	return strings.Join(display, " · ")
}

// InsertCanary registers a new canary. It is the write path both
// cmd/birdcage's `canary add` subcommand and a future enrollment flow
// (#1) go through. c.HeartbeatIntervalS <= 0 defaults to
// DefaultHeartbeatIntervalS; c.EnrolledAt must be set by the caller
// (time.Now().UTC() in practice) since InsertCanary does not default it,
// matching internal/audit.Append's stance on CreatedAt.
//
// database is db.Conn, not *db.DB (issue #47 slice 3): store.Provision
// calls this from inside its own transaction, the same reason
// MintCanaryToken and audit.Append already take the narrower interface.
// Every existing caller passes a *db.DB, which satisfies db.Conn
// unchanged.
func InsertCanary(ctx context.Context, database db.Conn, c Canary) error {
	interval := c.HeartbeatIntervalS
	if interval <= 0 {
		interval = DefaultHeartbeatIntervalS
	}
	if c.EnrolledAt.IsZero() {
		return fmt.Errorf("store: InsertCanary: EnrolledAt is zero; callers must set it")
	}
	_, err := database.ExecContext(ctx, `
		INSERT INTO canaries (id, name, lane, ports, heartbeat_interval_s, enrolled_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		c.ID, c.Name, c.Lane, c.Ports, interval, c.EnrolledAt.UTC().Format(receivedAtLayout))
	if err != nil {
		return fmt.Errorf("insert canary: %w", err)
	}
	return nil
}

// RecordHeartbeat records that canaryID phoned home at at (POST
// /api/heartbeat): it updates canaries.last_heartbeat_at, inserts a
// heartbeats row, and prunes that canary's heartbeats older than
// heartbeatRetention. Returns ErrCanaryNotFound if canaryID isn't
// registered -- no heartbeat row is inserted for an unknown canary.
func RecordHeartbeat(ctx context.Context, database *db.DB, canaryID string, at time.Time) error {
	at = at.UTC()
	atStr := at.Format(receivedAtLayout)

	res, err := database.ExecContext(ctx, `UPDATE canaries SET last_heartbeat_at = ? WHERE id = ?`, atStr, canaryID)
	if err != nil {
		return fmt.Errorf("update last_heartbeat_at: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return ErrCanaryNotFound
	}

	if _, err := database.ExecContext(ctx,
		`INSERT INTO heartbeats (canary_id, at) VALUES (?, ?)`, canaryID, atStr); err != nil {
		return fmt.Errorf("insert heartbeat: %w", err)
	}

	cutoff := at.Add(-heartbeatRetention).Format(receivedAtLayout)
	pruneQuery := fmt.Sprintf(`DELETE FROM heartbeats WHERE canary_id = ? AND %s`,
		timeCompare(database.Engine, "at", "<"))
	if _, err := database.ExecContext(ctx, pruneQuery, canaryID, cutoff); err != nil {
		return fmt.Errorf("prune heartbeats: %w", err)
	}
	return nil
}

// AgentHeartbeat is the self-report a canary's agent (#48) sends with
// every heartbeat over the ingest token (issue #32 slice 5a) -- queue
// depth, whether its OpenCanary log read is healthy, the last event id
// it has seen, and its own version. #45's "not delivering" state stands
// on this, since birdcage never connects to the agent to check on it
// directly; RecordCanaryAgentHeartbeat only stores it, showing it on the
// dashboard is #45's job.
//
// Dropped, Rejected, EventIDCollisions and PositionFound (#48's
// process-composition note, gap 3) are pointers: nil means this
// heartbeat didn't carry the field at all (an agent built before this
// change, or mid-rollout), which RecordCanaryAgentHeartbeat must persist
// as SQL NULL, not zero -- see this function's own comment.
type AgentHeartbeat struct {
	QueueDepth        int
	LogReadOK         bool
	LastEventID       string
	AgentVersion      string
	Dropped           *int64
	Rejected          *int64
	EventIDCollisions *int64
	PositionFound     *bool
}

// RecordCanaryAgentHeartbeat records that canaryID's agent phoned home at
// at -- exactly RecordHeartbeat's own contract, including
// ErrCanaryNotFound for an unregistered canary -- and additionally
// stores report against the canaries row. Like RecordHeartbeat itself,
// this is two separate statements, not one transaction: matching that
// function's own existing shape rather than introducing a second
// convention for multi-statement writes in this file.
//
// report.Dropped, Rejected and EventIDCollisions are passed through to
// the driver as *int64, and PositionFound is converted to a nullable
// 0/1 *int64 below (matching agent_log_read_ok's own INTEGER
// convention): a nil pointer binds to SQL NULL, a non-nil pointer binds
// to its value including zero. That is what keeps "the agent didn't
// report this field" (NULL) distinct from "the agent reported zero"
// (see AgentHeartbeat's doc comment above).
func RecordCanaryAgentHeartbeat(ctx context.Context, database *db.DB, canaryID string, at time.Time, report AgentHeartbeat) error {
	if err := RecordHeartbeat(ctx, database, canaryID, at); err != nil {
		return err
	}

	logReadOK := 0
	if report.LogReadOK {
		logReadOK = 1
	}
	var positionFound *int64
	if report.PositionFound != nil {
		v := int64(0)
		if *report.PositionFound {
			v = 1
		}
		positionFound = &v
	}
	if _, err := database.ExecContext(ctx, `
		UPDATE canaries
		SET agent_version = ?, agent_queue_depth = ?, agent_log_read_ok = ?, agent_last_event_id = ?,
			agent_dropped = ?, agent_rejected = ?, agent_event_id_collisions = ?, agent_position_found = ?
		WHERE id = ?`,
		report.AgentVersion, report.QueueDepth, logReadOK, report.LastEventID,
		report.Dropped, report.Rejected, report.EventIDCollisions, positionFound, canaryID); err != nil {
		return fmt.Errorf("update agent self-report: %w", err)
	}
	return nil
}

// rangeDurations maps every Range GET /api/canaries (and #35's
// GET /api/trace) accept to the window ListCanaries' hits count looks
// back over. Kept as the one place both handlers and tests read it from.
var rangeDurations = map[string]time.Duration{
	"15m": 15 * time.Minute,
	"1h":  time.Hour,
	"24h": 24 * time.Hour,
	"14d": 14 * 24 * time.Hour,
	"90d": 90 * 24 * time.Hour,
}

// DefaultRange is the range GET /api/canaries uses when ?range= is
// omitted.
const DefaultRange = "14d"

// ParseRange resolves s (a Range string, e.g. "14d") to the time.Duration
// ListCanaries should look back over. An empty s resolves to
// DefaultRange; any other unrecognized value is an error the caller
// reports as 400.
func ParseRange(s string) (time.Duration, error) {
	if s == "" {
		s = DefaultRange
	}
	d, ok := rangeDurations[s]
	if !ok {
		return 0, fmt.Errorf("unknown range %q", s)
	}
	return d, nil
}

// ListCanaries returns every registered canary with its ordered health
// state (issue #45: applyStatus's "ok"/"silent" as before, then
// applyHealthState folds in throttled, not-delivering, rotation-stalled
// and token-conflict, keeping whichever is worst), state detail, and
// hits (alerts rows for that canary's instance_id received within
// rangeWindow of now).
func ListCanaries(ctx context.Context, database *db.DB, now time.Time, rangeWindow time.Duration) ([]Canary, error) {
	now = now.UTC()

	rows, err := database.QueryContext(ctx, `
		SELECT id, name, lane, ports, heartbeat_interval_s, enrolled_at, last_heartbeat_at, agent_log_read_ok,
			agent_dropped, agent_rejected, agent_event_id_collisions, agent_position_found
		FROM canaries ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("query canaries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	canaries := []Canary{}
	for rows.Next() {
		var (
			c                  Canary
			portsRaw           string
			enrolledAt         string
			lastHeartbeatAt    *string
			agentLogReadOK     *int64
			agentPositionFound *int64
		)
		if err := rows.Scan(&c.ID, &c.Name, &c.Lane, &portsRaw, &c.HeartbeatIntervalS, &enrolledAt, &lastHeartbeatAt, &agentLogReadOK,
			&c.AgentDropped, &c.AgentRejected, &c.AgentEventIDCollisions, &agentPositionFound); err != nil {
			return nil, fmt.Errorf("scan canary: %w", err)
		}
		c.Ports = portsDisplay(portsRaw)
		t, err := time.Parse(receivedAtLayout, enrolledAt)
		if err != nil {
			return nil, fmt.Errorf("parse enrolled_at %q: %w", enrolledAt, err)
		}
		c.EnrolledAt = t
		if lastHeartbeatAt != nil {
			t, err := time.Parse(receivedAtLayout, *lastHeartbeatAt)
			if err != nil {
				return nil, fmt.Errorf("parse last_heartbeat_at %q: %w", *lastHeartbeatAt, err)
			}
			c.LastHeartbeatAt = &t
		}
		if agentLogReadOK != nil {
			ok := *agentLogReadOK != 0
			c.AgentLogReadOK = &ok
		}
		if agentPositionFound != nil {
			found := *agentPositionFound != 0
			c.AgentPositionFound = &found
		}
		applyStatus(&c, now)
		canaries = append(canaries, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate canaries: %w", err)
	}

	hits, err := hitsSinceByInstance(ctx, database, now, rangeWindow)
	if err != nil {
		return nil, err
	}
	for i := range canaries {
		canaries[i].Hits = hits[canaries[i].ID]

		throttledSince, err := latestAuditSince(ctx, database, "ingest.rate_limited", canaries[i].ID, now.Add(-throttledWindow))
		if err != nil {
			return nil, fmt.Errorf("throttled signal for %s: %w", canaries[i].ID, err)
		}
		tokenConflictSince, err := latestAuditSince(ctx, database, "ingest.token_conflict", canaries[i].ID, now.Add(-tokenConflictQuietPeriod))
		if err != nil {
			return nil, fmt.Errorf("token-conflict signal for %s: %w", canaries[i].ID, err)
		}
		rotationStalled, rotationEscalated, rotationSinceS, err := rotationSignal(ctx, database, canaries[i].ID, now)
		if err != nil {
			return nil, fmt.Errorf("rotation signal for %s: %w", canaries[i].ID, err)
		}
		applyHealthState(&canaries[i], notDelivering(canaries[i]), throttledSince, rotationStalled, rotationEscalated, rotationSinceS, tokenConflictSince, now)
	}
	return canaries, nil
}

// applyStatus fills c.Status and, when silent, c.SilentForS/c.BeatsMissed
// from c.LastHeartbeatAt (or c.EnrolledAt, for a canary that has never
// beaten) as of now.
func applyStatus(c *Canary, now time.Time) {
	threshold := time.Duration(silenceThresholdMultiple*c.HeartbeatIntervalS) * time.Second
	if c.LastHeartbeatAt != nil && !now.Before(*c.LastHeartbeatAt) && now.Sub(*c.LastHeartbeatAt) <= threshold {
		c.Status = "ok"
		return
	}

	c.Status = "silent"
	since := c.EnrolledAt
	if c.LastHeartbeatAt != nil {
		since = *c.LastHeartbeatAt
	}
	silentFor := int64(0)
	if now.After(since) {
		silentFor = int64(now.Sub(since).Seconds())
	}
	c.SilentForS = &silentFor

	missed := int64(0)
	if c.HeartbeatIntervalS > 0 {
		missed = silentFor / int64(c.HeartbeatIntervalS)
	}
	c.BeatsMissed = &missed
}

// hitsSinceByInstance counts alerts rows per instance_id received within
// rangeWindow of now (inclusive both ends, matching GetStats' Last24h
// bound), keyed by instance_id so ListCanaries can look its own
// canaries' counts up directly -- an instance_id with no alerts in the
// window is simply absent from the map, which a zero-value map lookup
// already reads back as 0.
func hitsSinceByInstance(ctx context.Context, database *db.DB, now time.Time, rangeWindow time.Duration) (map[string]int64, error) {
	since := now.Add(-rangeWindow).Format(receivedAtLayout)
	nowStr := now.Format(receivedAtLayout)
	query := fmt.Sprintf(`
		SELECT instance_id, COUNT(*) FROM alerts
		WHERE %s AND %s
		GROUP BY instance_id`,
		receivedAtCompare(database.Engine, ">="), receivedAtCompare(database.Engine, "<="))

	rows, err := database.QueryContext(ctx, query, since, nowStr)
	if err != nil {
		return nil, fmt.Errorf("query hits per instance: %w", err)
	}
	defer func() { _ = rows.Close() }()

	hits := make(map[string]int64)
	for rows.Next() {
		var (
			instanceID string
			count      int64
		)
		if err := rows.Scan(&instanceID, &count); err != nil {
			return nil, fmt.Errorf("scan hits per instance: %w", err)
		}
		hits[instanceID] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate hits per instance: %w", err)
	}
	return hits, nil
}
