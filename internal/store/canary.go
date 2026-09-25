package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
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
	ID                 string         `json:"id"`
	Name               string         `json:"name"`
	Lane               string         `json:"lane"`
	Kind               agentkind.Kind `json:"kind"`
	Ports              string         `json:"ports"` // display form, e.g. "ssh 22 · http 80 · smb 445"
	HeartbeatIntervalS int            `json:"-"`
	EnrolledAt         time.Time      `json:"-"`
	LastHeartbeatAt    *time.Time     `json:"last_heartbeat_at"`

	// RegisteredAt (issue #47 steps 7-9) is when this canary's first
	// self-test round trip passed (store.SettlePending), or nil while it
	// is still pending (#45 state 5): provisioned, but not yet proven to
	// work end to end. Read back by ListCanaries; never set directly by
	// a caller -- see Pending below for how InsertCanary decides it.
	RegisteredAt *time.Time `json:"-"`

	// Pending is InsertCanary's own instruction, not a read-back value
	// (RegisteredAt above is that): true leaves registered_at NULL, i.e.
	// this canary starts out pending. The zero value (false) is
	// "register immediately", so store.Provision -- the only caller that
	// ever sets it true -- is the only path onto #45's pending state;
	// `birdcage canary add`, cmd/seed-story and every existing test
	// fixture built before this field existed keep registering
	// immediately, unchanged.
	Pending bool `json:"-"`

	// AgentLogReadOK is the agent's own last self-reported log-read
	// status (#32 slice 5a, canaries.agent_log_read_ok). nil means no
	// self-report has ever arrived, distinct from an explicit false --
	// see notDelivering's doc comment in health.go.
	AgentLogReadOK *bool `json:"-"`

	// AgentVersion is the agent's own last self-reported version
	// (canaries.agent_version, written by RecordCanaryAgentHeartbeat and
	// RecordCanaryCommonHeartbeat). nil means no heartbeat has ever
	// carried one -- a pre-agent canary, or one enrolled but never yet
	// heard from. Issue #118's canary page names it in the facts column;
	// the fleet dashboard has never needed it, which is why it arrives
	// here only now.
	AgentVersion *string `json:"agent_version,omitempty"`

	// PoisonerNames is the bait names this canary last reported asking for
	// (canaries.poisoner_names, written by RecordCanaryAgentHeartbeat, #86
	// slice D), comma-separated. nil for a canary that has reported none --
	// the poisoner road off, an agent built before the field existed, or any
	// kind but a honeypot.
	PoisonerNames *string `json:"poisoner_names,omitempty"`

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

	// LastSeenAddr (issue #46 item 1) is the peer host of this canary's
	// most recent accepted ingest heartbeat, set by
	// store.SetCanaryLastSeenAddr from internal/ingest/heartbeat.go's
	// own net.SplitHostPort(r.RemoteAddr) -- never a payload value. nil
	// means no ingest-token heartbeat has ever arrived. This is the
	// address internal/selftestsched probes (#46 settled decision 2:
	// probing the LAN address, not loopback, also proves each service
	// is bound to the network).
	LastSeenAddr *string `json:"-"`

	// LastSelfTestAt and LastSelfTestPassed (issue #46 item 6) are the
	// most recently *completed* self-test run's completed_at and
	// passed, or nil/nil when no run has ever completed for this
	// canary. SelfTestFailedServices names the targets that never
	// matched ("service dest_port" strings), populated only when
	// LastSelfTestPassed is false -- see ListCanaries' own self-test
	// section and health.go's StateTestFailed.
	LastSelfTestAt         *time.Time `json:"last_self_test_at,omitempty"`
	LastSelfTestPassed     *bool      `json:"last_self_test_passed,omitempty"`
	SelfTestFailedServices []string   `json:"self_test_failed_services,omitempty"`

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

	// Issue #130 (ADR-0012 B2/B4) detail, each present only while its
	// state is active. CredentialConflict names the two addresses and/or
	// the two agent builds seen on one certificate (credential_conflict).
	// RenewalStalled/RenewalStalledForS are renewal_stalled, the seconds
	// counted from the certificate's half-life. CertificateExpired says
	// why not_delivering is on when the agent's own report did not say
	// so: the certificate it was using has expired.
	CredentialConflict *CredentialConflict `json:"credential_conflict,omitempty"`
	RenewalStalled     bool                `json:"renewal_stalled,omitempty"`
	RenewalStalledForS *int64              `json:"renewal_stalled_for_s,omitempty"`
	CertificateExpired bool                `json:"certificate_expired,omitempty"`

	// dualUse is the raw credential_dual_use_* columns, read by
	// ListCanaries and turned into CredentialConflict by
	// applyCredentialHealth. Never serialised.
	dualUse dualUseColumns

	// Run, LastRun and DBRefresh are a scanner's proof and database
	// refresh (issue #116, ADR-0012 decisions 6, 9-11). Run is present
	// only while a scan run is open, LastRun names the most recently
	// completed one, DBRefresh is present only while the refresh is
	// failing. Never the run id. Nil for every other kind.
	Run       *ScanRunOpen      `json:"run,omitempty"`
	LastRun   *ScanRunLast      `json:"last_run,omitempty"`
	DBRefresh *DBRefreshFailure `json:"db_refresh,omitempty"`

	// dbRefreshFailingSince and dbRefreshError are the raw
	// canaries.db_refresh_* columns, turned into DBRefresh and db_stale
	// by applyDBRefreshHealth.
	dbRefreshFailingSince *time.Time
	dbRefreshError        string

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

// DBRefreshFailure is a scanner's failing database refresh, as birdcage
// saw it: FailingSince is birdcage's own clock at the first failing
// report since the last success.
type DBRefreshFailure struct {
	FailingSince time.Time `json:"failing_since"`
	LastError    string    `json:"last_error"`
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

// WellKnownServiceForPort exposes wellKnownPortNames to
// internal/selftestsched (issue #46 item 5), which must derive one
// self-test target's service name per raw port the same way
// portsDisplay does, without either duplicating this table or being
// handed portsDisplay's already-joined human string.
func WellKnownServiceForPort(port int) (string, bool) {
	name, ok := wellKnownPortNames[strconv.Itoa(port)]
	return name, ok
}

// SelfTestCanary is the minimal projection internal/selftestsched needs
// to mint a self-test command (issue #46 item 5): a honeypot's id, raw
// ports (not portsDisplay's joined display string) and last-seen
// address. A nil LastSeenAddr or empty Ports means the scheduler must
// skip this canary -- see ListHoneypotCanariesForSelfTest and
// SelfTestCanaryByID's own doc comments.
type SelfTestCanary struct {
	ID           string
	Kind         agentkind.Kind
	Ports        []int
	LastSeenAddr *string
	// Pending is true while registered_at is NULL (issue #47 step 9):
	// the canary's first self-test round trip has not passed yet, so
	// the scheduler keeps re-minting one for it until it does.
	Pending bool
}

// parsePorts parses canaries.ports (a comma-separated list of bare port
// numbers, e.g. "22,80,445" -- see 0003_canaries.sql) the same way
// portsDisplay does, but into ints rather than a display string.
// Malformed entries (should never happen; this column is only ever
// written by this package) are skipped rather than failing the whole
// row.
func parsePorts(raw string) []int {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	ports := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			continue
		}
		ports = append(ports, n)
	}
	return ports
}

// ListHoneypotCanariesForSelfTest returns every kind-honeypot canary's
// SelfTestCanary projection (issue #46 item 5b), for the scheduler's
// per-minute tick to filter down to the ones with a LastSeenAddr and at
// least one port.
func ListHoneypotCanariesForSelfTest(ctx context.Context, database *db.DB) ([]SelfTestCanary, error) {
	rows, err := database.QueryContext(ctx, `SELECT id, ports, last_seen_addr, registered_at FROM agents WHERE kind = ?`, string(agentkind.Honeypot))
	if err != nil {
		return nil, fmt.Errorf("query honeypot canaries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []SelfTestCanary
	for rows.Next() {
		var (
			sc           SelfTestCanary
			portsRaw     string
			registeredAt *string
		)
		if err := rows.Scan(&sc.ID, &portsRaw, &sc.LastSeenAddr, &registeredAt); err != nil {
			return nil, fmt.Errorf("scan honeypot canary: %w", err)
		}
		sc.Kind = agentkind.Honeypot
		sc.Pending = registeredAt == nil
		sc.Ports = parsePorts(portsRaw)
		out = append(out, sc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate honeypot canaries: %w", err)
	}
	return out, nil
}

// ListPendingCanariesForSelfTest returns every pending canary
// (registered_at NULL) of every kind (issue #116, ADR-0012 decision 5):
// internal/selftestsched's pending retry re-mints each one's proof, by
// kind, until it passes.
func ListPendingCanariesForSelfTest(ctx context.Context, database *db.DB) ([]SelfTestCanary, error) {
	rows, err := database.QueryContext(ctx, `SELECT id, kind, ports, last_seen_addr FROM agents WHERE registered_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("query pending canaries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []SelfTestCanary
	for rows.Next() {
		var (
			sc       SelfTestCanary
			kind     string
			portsRaw string
		)
		if err := rows.Scan(&sc.ID, &kind, &portsRaw, &sc.LastSeenAddr); err != nil {
			return nil, fmt.Errorf("scan pending canary: %w", err)
		}
		sc.Kind = agentkind.Kind(kind)
		sc.Pending = true
		sc.Ports = parsePorts(portsRaw)
		out = append(out, sc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending canaries: %w", err)
	}
	return out, nil
}

// SelfTestCanaryByID is ListHoneypotCanariesForSelfTest narrowed to one
// canary regardless of kind, for internal/selftestsched's
// rotation-coupled path (issue #46 item 5c): the rotation success hook
// already knows which canary just rotated and needs only that one row,
// not a full table scan. ok is false when canaryID names no row.
func SelfTestCanaryByID(ctx context.Context, database *db.DB, canaryID string) (sc SelfTestCanary, ok bool, err error) {
	var (
		portsRaw     string
		kind         string
		registeredAt *string
	)
	row := database.QueryRowContext(ctx, `SELECT id, kind, ports, last_seen_addr, registered_at FROM agents WHERE id = ?`, canaryID)
	if err := row.Scan(&sc.ID, &kind, &portsRaw, &sc.LastSeenAddr, &registeredAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SelfTestCanary{}, false, nil
		}
		return SelfTestCanary{}, false, fmt.Errorf("scan canary %s: %w", canaryID, err)
	}
	sc.Kind = agentkind.Kind(kind)
	sc.Pending = registeredAt == nil
	sc.Ports = parsePorts(portsRaw)
	return sc, true, nil
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
//
// c.Kind must be a registered agentkind.Kind (issue #105) -- refused
// here, at the write, the same stance MintEnrolmentSession takes on its
// own kind parameter. Every caller (store.Provision, `birdcage canary
// add`, cmd/seed-story) must set it explicitly; there is no default,
// unlike HeartbeatIntervalS below, because a silently-defaulted kind on
// a direct-insert path would be exactly the "invented kind" this
// package's read paths are built never to do.
func InsertCanary(ctx context.Context, database db.Conn, c Canary) error {
	interval := c.HeartbeatIntervalS
	if interval <= 0 {
		interval = DefaultHeartbeatIntervalS
	}
	if c.EnrolledAt.IsZero() {
		return fmt.Errorf("store: InsertCanary: EnrolledAt is zero; callers must set it")
	}
	if !agentkind.Valid(c.Kind) {
		return fmt.Errorf("store: InsertCanary: unregistered kind %q", c.Kind)
	}
	// registeredAt is NULL exactly when c.Pending is set -- see Pending's
	// own doc comment. Every existing caller leaves Pending at its zero
	// value (false) and so keeps registering immediately, byte-for-byte
	// what this INSERT did before registered_at existed.
	var registeredAt *string
	if !c.Pending {
		s := c.EnrolledAt.UTC().Format(receivedAtLayout)
		registeredAt = &s
	}
	_, err := database.ExecContext(ctx, `
		INSERT INTO agents (id, name, lane, kind, ports, heartbeat_interval_s, enrolled_at, registered_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.Name, c.Lane, string(c.Kind), c.Ports, interval, c.EnrolledAt.UTC().Format(receivedAtLayout), registeredAt)
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

	res, err := database.ExecContext(ctx, `UPDATE agents SET last_heartbeat_at = ? WHERE id = ?`, atStr, canaryID)
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
		`INSERT INTO heartbeats (agent_id, at) VALUES (?, ?)`, canaryID, atStr); err != nil {
		return fmt.Errorf("insert heartbeat: %w", err)
	}

	cutoff := at.Add(-heartbeatRetention).Format(receivedAtLayout)
	pruneQuery := fmt.Sprintf(`DELETE FROM heartbeats WHERE agent_id = ? AND %s`,
		timeCompare(database.Engine, "at", "<"))
	if _, err := database.ExecContext(ctx, pruneQuery, canaryID, cutoff); err != nil {
		return fmt.Errorf("prune heartbeats: %w", err)
	}
	return nil
}

// SetCanaryLastSeenAddr records the peer host of canaryID's most recent
// accepted ingest heartbeat (issue #46 item 1) -- canaries.last_seen_addr,
// the address internal/selftestsched probes. Called from
// internal/ingest/heartbeat.go's two handlers with
// net.SplitHostPort(r.RemoteAddr)'s host, never a payload value, on
// both the honeypot and the common heartbeat shape. Separate from
// RecordHeartbeat/RecordCanaryAgentHeartbeat/RecordCanaryCommonHeartbeat
// above: those are also reached from the dashboard's own POST
// /api/heartbeat (issue #34), which has no peer address worth recording
// here, so this is its own narrow write rather than a parameter added to
// three existing functions one of whose callers could never supply it.
func SetCanaryLastSeenAddr(ctx context.Context, database *db.DB, canaryID, addr string) error {
	res, err := database.ExecContext(ctx, `UPDATE agents SET last_seen_addr = ? WHERE id = ?`, addr, canaryID)
	if err != nil {
		return fmt.Errorf("update last_seen_addr: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return ErrCanaryNotFound
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

	// PoisonerNames is the bait names the canary reported asking for (#86
	// slice D), comma-separated. Empty means the agent reported none -- the
	// poisoner road off, or an agent built before the field existed -- and
	// is stored as NULL, so "reports no bait names" stays distinct from a
	// stored empty list the facts column would then have to render.
	PoisonerNames string
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
	// An empty PoisonerNames binds to SQL NULL rather than to '', for the
	// reason AgentHeartbeat.PoisonerNames states.
	var poisonerNames *string
	if report.PoisonerNames != "" {
		poisonerNames = &report.PoisonerNames
	}
	if _, err := database.ExecContext(ctx, `
		UPDATE agents
		SET agent_version = ?, agent_queue_depth = ?, agent_log_read_ok = ?, agent_last_event_id = ?,
			agent_dropped = ?, agent_rejected = ?, agent_event_id_collisions = ?, agent_position_found = ?,
			poisoner_names = ?
		WHERE id = ?`,
		report.AgentVersion, report.QueueDepth, logReadOK, report.LastEventID,
		report.Dropped, report.Rejected, report.EventIDCollisions, positionFound,
		poisonerNames, canaryID); err != nil {
		return fmt.Errorf("update agent self-report: %w", err)
	}
	return nil
}

// RecordCanaryCommonHeartbeat records that canaryID's agent phoned home
// at at, with only the common self-report every agent kind can send
// (issue #106, ADR-0009: "the small common part -- agent version, last
// contact -- is shared; the rest belongs to the kind") -- exactly
// RecordHeartbeat's own contract, including ErrCanaryNotFound, plus
// agent_version. It never touches agent_queue_depth, agent_log_read_ok,
// agent_last_event_id, agent_dropped, agent_rejected,
// agent_event_id_collisions or agent_position_found -- the log-tailer
// columns RecordCanaryAgentHeartbeat writes -- so a scanner's heartbeat
// never zeroes them out from under a real Honeypot; a canary that has
// never sent a log-tailer self-report at all (a scanner, always) simply
// leaves those columns at whatever they already were (NULL, for a
// canary that was always this kind), never a fabricated zero that would
// read as a healthy, empty log tailer.
func RecordCanaryCommonHeartbeat(ctx context.Context, database *db.DB, canaryID string, at time.Time, agentVersion string) error {
	if err := RecordHeartbeat(ctx, database, canaryID, at); err != nil {
		return err
	}
	if _, err := database.ExecContext(ctx, `UPDATE agents SET agent_version = ? WHERE id = ?`, agentVersion, canaryID); err != nil {
		return fmt.Errorf("update agent version: %w", err)
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
		SELECT id, name, lane, kind, ports, heartbeat_interval_s, enrolled_at, last_heartbeat_at, agent_log_read_ok,
			agent_dropped, agent_rejected, agent_event_id_collisions, agent_position_found, last_seen_addr, registered_at,
			agent_version, poisoner_names,
			credential_dual_use_addrs, credential_dual_use_addrs_at,
			credential_dual_use_versions, credential_dual_use_versions_at,
			db_refresh_failing_since, db_refresh_error
		FROM agents ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("query canaries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	canaries := []Canary{}
	for rows.Next() {
		var (
			c                  Canary
			kind               string
			portsRaw           string
			enrolledAt         string
			lastHeartbeatAt    *string
			agentLogReadOK     *int64
			agentPositionFound *int64
			lastSeenAddr       *string
			registeredAt       *string
			agentVersion       *string
			poisonerNames      *string
			dbFailingSince     *string
			dbRefreshError     *string
		)
		if err := rows.Scan(&c.ID, &c.Name, &c.Lane, &kind, &portsRaw, &c.HeartbeatIntervalS, &enrolledAt, &lastHeartbeatAt, &agentLogReadOK,
			&c.AgentDropped, &c.AgentRejected, &c.AgentEventIDCollisions, &agentPositionFound, &lastSeenAddr, &registeredAt,
			&agentVersion, &poisonerNames,
			&c.dualUse.addrs, &c.dualUse.addrsAt, &c.dualUse.versions, &c.dualUse.versionsAt,
			&dbFailingSince, &dbRefreshError); err != nil {
			return nil, fmt.Errorf("scan canary: %w", err)
		}
		if c.dbRefreshFailingSince, err = parseNullableTime(dbFailingSince, "db_refresh_failing_since"); err != nil {
			return nil, err
		}
		if dbRefreshError != nil {
			c.dbRefreshError = *dbRefreshError
		}
		c.LastSeenAddr = lastSeenAddr
		c.AgentVersion = agentVersion
		c.PoisonerNames = poisonerNames
		// c.Kind is opaque on read, like scanEnrolmentSession's own kind
		// field -- see that function's doc comment.
		c.Kind = agentkind.Kind(kind)
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
		if registeredAt != nil {
			t, err := time.Parse(receivedAtLayout, *registeredAt)
			if err != nil {
				return nil, fmt.Errorf("parse registered_at %q: %w", *registeredAt, err)
			}
			c.RegisteredAt = &t
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
		// Issue #130: token_conflict widens to a superseded certificate
		// too; the newer of the two signals is the one the quiet period
		// counts from.
		certConflictSince, err := latestAuditSince(ctx, database, "ingest.cert_conflict", canaries[i].ID, now.Add(-tokenConflictQuietPeriod))
		if err != nil {
			return nil, fmt.Errorf("cert-conflict signal for %s: %w", canaries[i].ID, err)
		}
		if certConflictSince != nil && (tokenConflictSince == nil || certConflictSince.After(*tokenConflictSince)) {
			tokenConflictSince = certConflictSince
		}
		rotationStalled, rotationEscalated, rotationSinceS, err := rotationSignal(ctx, database, canaries[i].ID, now)
		if err != nil {
			return nil, fmt.Errorf("rotation signal for %s: %w", canaries[i].ID, err)
		}

		testFailed, err := applySelfTestState(ctx, database, &canaries[i])
		if err != nil {
			return nil, fmt.Errorf("self-test state for %s: %w", canaries[i].ID, err)
		}
		if canaries[i].Kind == agentkind.Scanner {
			if testFailed, err = applyScanRunState(ctx, database, &canaries[i], testFailed, now); err != nil {
				return nil, fmt.Errorf("scan run state for %s: %w", canaries[i].ID, err)
			}
		}

		// Issue #47 step 9: RegisteredAt nil is #45 state 5, computed
		// straight off the column ListCanaries already scanned above --
		// no further query needed, the same shape testFailed's own signal
		// takes.
		pending := canaries[i].RegisteredAt == nil

		applyHealthState(&canaries[i], notDelivering(canaries[i]), throttledSince, rotationStalled, rotationEscalated, rotationSinceS, tokenConflictSince, testFailed, pending, now)

		cert, err := certificateSignal(ctx, database, canaries[i].ID, now)
		if err != nil {
			return nil, fmt.Errorf("certificate signal for %s: %w", canaries[i].ID, err)
		}
		if err := applyCredentialHealth(&canaries[i], cert, now); err != nil {
			return nil, fmt.Errorf("credential state for %s: %w", canaries[i].ID, err)
		}
		applyDBRefreshHealth(&canaries[i], now)
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
	// synthetic = 0 (issue #46 item 2): this is the Hits count
	// ListCanaries attaches to every tile, which must never count
	// birdcage's own scheduled self-test as a hit.
	since := now.Add(-rangeWindow).Format(receivedAtLayout)
	nowStr := now.Format(receivedAtLayout)
	query := fmt.Sprintf(`
		SELECT instance_id, COUNT(*) FROM alerts
		WHERE %s AND %s AND synthetic = 0
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
