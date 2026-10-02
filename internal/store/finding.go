// Package store: this file is issue #109's findings store (ADR-0010
// decisions 4 and 5, migration 0028) -- the standing-condition sibling
// of scan_snapshots' moment-in-time receipts. internal/ingest's scan
// handler calls ApplyFindingSnapshot with exactly the finding set it
// just validated and counted (internal/ingest/scans.go, which still
// never persists a finding body on its own); this file is the one place
// that body is ever written down.
//
// The server-side diff ADR-0010 decision 5 describes -- "each scan
// posts its complete current finding set, the server diffs against the
// last one" -- is deliberately not a diff against the previous
// scan_snapshots row. It is a diff against this table's own current
// open/accepted rows for the agent: a snapshot never needs replaying
// because the findings table already *is* "what the last successful
// scan said was true", continuously maintained. A failed or dropped
// scan never calls ApplyFindingSnapshot at all (internal/ingest only
// calls it for status == ok), so the previous live rows simply sit
// unmoved -- "a dropped or failed scan ... never resolves anything" per
// the issue, satisfied by this function never running rather than by
// any flag on the findings themselves.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// FindingState is the closed set findings.state holds -- kept in Go for
// the same reason every other closed-set column in this schema is
// (0006_canary_commands.sql's kind, 0013_agent_kinds.sql's kind,
// 0010_canary_state_periods.sql's own state column).
type FindingState string

const (
	// FindingOpen is a finding birdcage's most recent complete snapshot
	// for this agent still reports and no operator has accepted.
	FindingOpen FindingState = "open"
	// FindingAccepted is an operator decision (AcceptFinding) that
	// survives rescans: a finding stays accepted while it keeps being
	// reported, per the issue's own acceptance bullet.
	FindingAccepted FindingState = "accepted"
	// FindingFixed is a finding absent from the most recent complete
	// snapshot -- resolved without the agent saying anything beyond its
	// new snapshot, per ADR-0010 decision 5.
	FindingFixed FindingState = "fixed"
)

// ErrFindingNotFound is AcceptFinding's error when no open or accepted
// finding matches the given identity.
var ErrFindingNotFound = errors.New("store: finding not found")

// Finding is one row of findings -- a standing condition, not an event:
// see this file's package comment and ADR-0010 decision 4.
type Finding struct {
	ID               int64        `json:"id"`
	AgentID          string       `json:"agent_id"`
	Target           string       `json:"target"`
	VulnerabilityID  string       `json:"vulnerability_id"`
	Severity         string       `json:"severity"`
	InstalledVersion string       `json:"installed_version"`
	FixingVersion    string       `json:"fixing_version"`
	FirstSeen        time.Time    `json:"first_seen"`
	LastSeen         time.Time    `json:"last_seen"`
	State            FindingState `json:"state"`
	AcceptedBy       string       `json:"accepted_by,omitempty"`
	AcceptedAt       *time.Time   `json:"accepted_at,omitempty"`
}

// ObservedFinding is one entry of a posted, validated scan snapshot's
// finding set -- internal/ingest's own ingestScanFinding, reduced to
// what this file needs to diff and store. Target is already the
// composite "<type>:<package>" identity migration 0028's own comment
// describes (BuildFindingTarget below builds it); this file never sees
// internal/scan.Finding or ingestScanFinding themselves, matching
// ingest's own "mirrored, never imported" stance toward internal/scan
// (ADR-0009 decision 6's fence) -- store, same as ingest, stays on its
// own side of that fence.
type ObservedFinding struct {
	Target           string
	VulnerabilityID  string
	Severity         string
	InstalledVersion string
	FixingVersion    string
}

// BuildFindingTarget joins a Grype artifact type and package name into
// findings.target's composite identity (migration 0028's own comment:
// a bare package name is not unique once #113 adds other ecosystems).
func BuildFindingTarget(artifactType, pkg string) string {
	return artifactType + ":" + pkg
}

// findingConn is what this file's functions take: db.Conn's
// Exec/QueryRow plus QueryContext, the same historyConn/certConn shape
// (internal/store/history.go, internal/store/clientcert.go) so a
// caller's existing transaction (internal/ingest/scans.go's storeScan)
// can drive the whole scan-snapshot-plus-findings write as one unit.
// Both *db.DB and *db.Tx satisfy it.
type findingConn interface {
	db.Conn
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

const findingColumns = `id, agent_id, target, vulnerability_id, severity, installed_version, fixing_version, first_seen, last_seen, state, accepted_by, accepted_at`

// ApplyFindingSnapshot is the sole writer of findings, called once per
// complete ok scan snapshot (ADR-0010 decision 5). It loads every
// existing row for agentID, then for each observed finding:
//
//   - unseen before: inserted as FindingOpen, first_seen == last_seen ==
//     observedAt.
//   - seen before, currently open or accepted: last_seen and the
//     reported metadata (severity, installed_version, fixing_version)
//     are refreshed; state is untouched -- "rescanning unchanged input
//     changes last_seen and nothing else" and "an accepted finding stays
//     accepted across rescans" are both exactly this branch.
//   - seen before, currently fixed: reopened as FindingOpen with
//     last_seen refreshed and first_seen kept (the condition has a
//     continuous history even though it briefly cleared), and any prior
//     acceptance cleared -- a vulnerability that went away and came back
//     is not the one an operator accepted, possibly at a different
//     installed version, so it is asked about again rather than
//     silently re-covered. This case is not in the issue's acceptance
//     bullets; it is the natural reading of "state reflects what is
//     currently true" applied to the one transition the bullets do not
//     name.
//
// Every existing row for agentID in FindingOpen or FindingAccepted that
// is *not* in the observed set is marked FindingFixed, last_seen left as
// it was (the last time it actually was seen) -- "removing a vulnerable
// package resolves the finding without the agent telling the server
// anything except its new snapshot."
//
// observedAt is the snapshot's own ReceivedAt (birdcage's clock, never
// the agent's TakenAt) -- see migration 0028's comment.
func ApplyFindingSnapshot(ctx context.Context, conn findingConn, agentID string, observed []ObservedFinding, observedAt time.Time) error {
	if agentID == "" {
		return errors.New("store: ApplyFindingSnapshot: agentID is empty")
	}
	if observedAt.IsZero() {
		return errors.New("store: ApplyFindingSnapshot: observedAt is zero; callers must set it")
	}

	existing, err := findingsForAgent(ctx, conn, agentID)
	if err != nil {
		return fmt.Errorf("load existing findings for %s: %w", agentID, err)
	}
	byKey := make(map[findingKey]Finding, len(existing))
	for _, f := range existing {
		byKey[findingKey{f.Target, f.VulnerabilityID}] = f
	}

	seen := make(map[findingKey]bool, len(observed))
	for _, o := range observed {
		if o.Target == "" || o.VulnerabilityID == "" {
			return fmt.Errorf("store: ApplyFindingSnapshot: observed finding has empty target or vulnerability id: %+v", o)
		}
		key := findingKey{o.Target, o.VulnerabilityID}
		seen[key] = true

		if existingRow, ok := byKey[key]; ok {
			if existingRow.State == FindingFixed {
				if err := reopenFinding(ctx, conn, existingRow.ID, o, observedAt); err != nil {
					return err
				}
			} else if err := refreshFinding(ctx, conn, existingRow.ID, o, observedAt); err != nil {
				return err
			}
			continue
		}
		if err := insertFinding(ctx, conn, agentID, o, observedAt); err != nil {
			return err
		}
	}

	for key, f := range byKey {
		if seen[key] {
			continue
		}
		if f.State == FindingFixed {
			continue
		}
		if _, err := conn.ExecContext(ctx, `UPDATE findings SET state = ? WHERE id = ?`, string(FindingFixed), f.ID); err != nil {
			return fmt.Errorf("mark finding %d fixed: %w", f.ID, err)
		}
	}
	return nil
}

// findingKey is one finding's identity within an agent -- the issue's
// own (target, vulnerability id) half of the (agent, target,
// vulnerability id) key, agent_id already fixed by ApplyFindingSnapshot's
// own caller-scoped queries.
type findingKey struct {
	target          string
	vulnerabilityID string
}

func insertFinding(ctx context.Context, conn findingConn, agentID string, o ObservedFinding, observedAt time.Time) error {
	ts := observedAt.UTC().Format(receivedAtLayout)
	_, err := conn.ExecContext(ctx, `
		INSERT INTO findings (agent_id, target, vulnerability_id, severity, installed_version, fixing_version, first_seen, last_seen, state)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		agentID, o.Target, o.VulnerabilityID, o.Severity, o.InstalledVersion, o.FixingVersion, ts, ts, string(FindingOpen))
	if err != nil {
		return fmt.Errorf("insert finding %s/%s: %w", o.Target, o.VulnerabilityID, err)
	}
	return nil
}

func refreshFinding(ctx context.Context, conn findingConn, id int64, o ObservedFinding, observedAt time.Time) error {
	_, err := conn.ExecContext(ctx, `
		UPDATE findings SET last_seen = ?, severity = ?, installed_version = ?, fixing_version = ? WHERE id = ?`,
		observedAt.UTC().Format(receivedAtLayout), o.Severity, o.InstalledVersion, o.FixingVersion, id)
	if err != nil {
		return fmt.Errorf("refresh finding %d: %w", id, err)
	}
	return nil
}

func reopenFinding(ctx context.Context, conn findingConn, id int64, o ObservedFinding, observedAt time.Time) error {
	_, err := conn.ExecContext(ctx, `
		UPDATE findings SET state = ?, last_seen = ?, severity = ?, installed_version = ?, fixing_version = ?, accepted_by = NULL, accepted_at = NULL WHERE id = ?`,
		string(FindingOpen), observedAt.UTC().Format(receivedAtLayout), o.Severity, o.InstalledVersion, o.FixingVersion, id)
	if err != nil {
		return fmt.Errorf("reopen finding %d: %w", id, err)
	}
	return nil
}

// AcceptFinding is the operator's acceptance decision (ADR-0010 decision
// 4: "acceptance carries who and when and survives rescans"). Store
// method only -- no dashboard route: the dashboard API stays read-only
// until login exists (#134, the same rule agentsettings.go's own
// comment states), and no CLI pattern reaches a single finding the way
// `birdcage agent settings` reaches a named key, so cmd/birdcage/finding.go
// adds the minimal `birdcage findings accept` CLI this method needs
// rather than inventing a settings-shaped key for it.
//
// Refuses (ErrFindingNotFound) a target/vulnerability pair this agent
// does not currently report as open -- an already-accepted finding is
// accepted again idempotently (same by/at overwritten), but a fixed or
// never-seen finding has nothing for an operator to be accepting.
func AcceptFinding(ctx context.Context, conn db.Conn, agentID, target, vulnerabilityID, acceptedBy string, now time.Time) error {
	switch {
	case agentID == "":
		return errors.New("store: AcceptFinding: agentID is empty")
	case target == "":
		return errors.New("store: AcceptFinding: target is empty")
	case vulnerabilityID == "":
		return errors.New("store: AcceptFinding: vulnerabilityID is empty")
	case acceptedBy == "":
		return errors.New("store: AcceptFinding: acceptedBy is empty")
	case now.IsZero():
		return errors.New("store: AcceptFinding: now is zero; callers must set it")
	}

	res, err := conn.ExecContext(ctx, `
		UPDATE findings SET state = ?, accepted_by = ?, accepted_at = ?
		WHERE agent_id = ? AND target = ? AND vulnerability_id = ? AND state IN (?, ?)`,
		string(FindingAccepted), acceptedBy, now.UTC().Format(receivedAtLayout),
		agentID, target, vulnerabilityID, string(FindingOpen), string(FindingAccepted))
	if err != nil {
		return fmt.Errorf("accept finding %s/%s/%s: %w", agentID, target, vulnerabilityID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("accept finding %s/%s/%s: rows affected: %w", agentID, target, vulnerabilityID, err)
	}
	if n == 0 {
		return ErrFindingNotFound
	}
	return nil
}

// FindingFilter narrows ListFindings. An empty AgentID means every
// agent, matching ListScanSnapshots' own "no filter" shape until the
// read side grows more than this.
type FindingFilter struct {
	AgentID string
}

// ListFindings returns findings matching filter, newest-last-seen
// first. Used by GET /api/findings (read-only, same posture as GET
// /api/scans) and `birdcage findings list`.
func ListFindings(ctx context.Context, database *db.DB, filter FindingFilter) ([]Finding, error) {
	query := `SELECT ` + findingColumns + ` FROM findings`
	var args []any
	if filter.AgentID != "" {
		query += ` WHERE agent_id = ?`
		args = append(args, filter.AgentID)
	}
	query += ` ORDER BY last_seen DESC, id DESC`

	rows, err := database.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanFindingRows(rows)
}

// AgentScanStatus is the staleness fact one agent's findings carry --
// issue #109's "a dropped or failed scan leaves the previous snapshot
// in place, marked stale" bullet. Stale is true exactly when the
// agent's most recently received scan_snapshots row is a failed scan:
// there is no fresher successful finding set standing behind whatever
// is on record, so it is shown as unconfirmed rather than silently
// treated as current. LastOKScan is that agent's most recently
// received ok scan's ReceivedAt, nil if it has never completed one.
//
// Deliberately not a time-based threshold ("no scan in N hours") --
// that is a ranking/exposure call (#110's own ground, ADR-0010 decision
// 6), not this store's. This is the smallest fact the issue's own
// wording asks for: whether the most recent attempt succeeded.
type AgentScanStatus struct {
	Stale      bool       `json:"stale"`
	LastOKScan *time.Time `json:"last_ok_scan,omitempty"`
}

// FindingsStaleness computes AgentScanStatus for every agent that has
// at least one scan_snapshots row, or for a single agentID when given.
// It loads every snapshot (ListScanSnapshots' existing "whole fleet"
// shape -- #108's own scan_snapshots table has no per-agent filter, and
// this schema's fleets are small, same reasoning scanrun.go's
// listScanRuns gives for loading a node's runs whole) and finds each
// agent's most recent row and most recent ok row by comparing parsed
// ReceivedAt values in Go, never by SQL ordering on the stored text --
// the same trap 0010_canary_state_periods.sql's own comment and
// RevokeCanaryTokensSupersededBy warn about.
func FindingsStaleness(ctx context.Context, database *db.DB, agentID string) (map[string]AgentScanStatus, error) {
	snapshots, err := ListScanSnapshots(ctx, database)
	if err != nil {
		return nil, fmt.Errorf("findings staleness: %w", err)
	}

	type latest struct {
		any *ScanSnapshot
		ok  *ScanSnapshot
	}
	byAgent := make(map[string]*latest)
	for i := range snapshots {
		s := &snapshots[i]
		if agentID != "" && s.CanaryID != agentID {
			continue
		}
		l, ok := byAgent[s.CanaryID]
		if !ok {
			l = &latest{}
			byAgent[s.CanaryID] = l
		}
		if l.any == nil || s.ReceivedAt.After(l.any.ReceivedAt) {
			l.any = s
		}
		if s.Status == ScanStatusOK && (l.ok == nil || s.ReceivedAt.After(l.ok.ReceivedAt)) {
			l.ok = s
		}
	}

	out := make(map[string]AgentScanStatus, len(byAgent))
	for agent, l := range byAgent {
		status := AgentScanStatus{Stale: l.any.Status == ScanStatusFailed}
		if l.ok != nil {
			t := l.ok.ReceivedAt
			status.LastOKScan = &t
		}
		out[agent] = status
	}
	return out, nil
}

// findingsForAgent loads every finding row for agentID, whatever its
// state -- ApplyFindingSnapshot's own full read side of the diff.
func findingsForAgent(ctx context.Context, conn findingConn, agentID string) ([]Finding, error) {
	rows, err := conn.QueryContext(ctx, `SELECT `+findingColumns+` FROM findings WHERE agent_id = ?`, agentID)
	if err != nil {
		return nil, fmt.Errorf("query findings for %s: %w", agentID, err)
	}
	defer func() { _ = rows.Close() }()
	return scanFindingRows(rows)
}

func scanFindingRows(rows *sql.Rows) ([]Finding, error) {
	findings := []Finding{}
	for rows.Next() {
		var (
			f                   Finding
			state               string
			firstSeen, lastSeen string
			acceptedBy          *string
			acceptedAt          *string
		)
		if err := rows.Scan(&f.ID, &f.AgentID, &f.Target, &f.VulnerabilityID, &f.Severity, &f.InstalledVersion, &f.FixingVersion,
			&firstSeen, &lastSeen, &state, &acceptedBy, &acceptedAt); err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		f.State = FindingState(state)
		var err error
		if f.FirstSeen, err = time.Parse(receivedAtLayout, firstSeen); err != nil {
			return nil, fmt.Errorf("parse finding first_seen %q: %w", firstSeen, err)
		}
		if f.LastSeen, err = time.Parse(receivedAtLayout, lastSeen); err != nil {
			return nil, fmt.Errorf("parse finding last_seen %q: %w", lastSeen, err)
		}
		if acceptedBy != nil {
			f.AcceptedBy = *acceptedBy
		}
		if f.AcceptedAt, err = parseNullableTime(acceptedAt, "accepted_at"); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate findings: %w", err)
	}
	return findings, nil
}
