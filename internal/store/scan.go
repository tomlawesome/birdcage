// scan.go is issue #108 slice 1's server-side half of the Nightjar
// scanner: the write and read path for scan_snapshots (migration 0014),
// a receipt of one scan -- who, when, which engine and database, what
// it found (as a count, never the findings themselves) and which host
// paths it could not see. #109's findings store hangs off this table's
// id; nothing here persists a finding's own contents.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// ScanStatusOK and ScanStatusFailed are the closed set of values
// ScanSnapshot.Status carries -- kept in Go, not a SQL CHECK constraint,
// the same reasoning CommandKind and EnrolmentState already use in this
// package. They deliberately mirror internal/scan.StatusOK/StatusFailed
// letter for letter rather than importing that package: this package is
// server-side and internal/scan is fenced to the scanner binary alone
// (scripts/agent-deps-check.sh, ADR-0009 decision 6), so the two sides
// can only ever agree by construction, not by a shared import.
const (
	ScanStatusOK     = "ok"
	ScanStatusFailed = "failed"
)

// ScanSnapshot is one row of scan_snapshots.
//
// DBBuiltAt is nil exactly when the agent never loaded a vulnerability
// database at all -- internal/scan.Result's own doc comment on a run
// that failed before producing any document. EngineName/EngineVersion
// carry the same "unknown" case as a plain empty string instead, since
// unlike a timestamp an empty string cannot be confused with a real
// value (mirrors Canary.AgentVersion's own convention).
//
// MaskedPaths is the host paths the scanner's read-only root mount
// covered over before this scan ran (design decision on #108, 2026-09-22, on top
// of the "Scanner agent, slice 1" plan) -- present on both an ok and a
// failed snapshot, since the blind spot exists either way. Never nil
// once read back: ListScanSnapshots always returns a non-nil (possibly
// empty) slice, so the JSON API encodes it as `[]`, never `null`.
type ScanSnapshot struct {
	ID            int64      `json:"id"`
	CanaryID      string     `json:"canary_id"`
	TakenAt       time.Time  `json:"taken_at"`
	ReceivedAt    time.Time  `json:"received_at"`
	EngineName    string     `json:"engine_name"`
	EngineVersion string     `json:"engine_version"`
	DBBuiltAt     *time.Time `json:"db_built_at,omitempty"`
	Status        string     `json:"status"`
	Reason        string     `json:"reason,omitempty"`
	FindingCount  int        `json:"finding_count"`
	MaskedPaths   []string   `json:"masked_paths"`
}

// scanSnapshotColumns is the one SELECT list ListScanSnapshots reads,
// kept in one place the way approvalColumns already is for this
// package's approvals table.
const scanSnapshotColumns = `id, canary_id, taken_at, received_at, engine_name, engine_version, db_built_at, status, reason, finding_count, masked_paths`

// RecordScanSnapshot inserts one receipt of a Nightjar scan. It is the
// sole writer of scan_snapshots -- POST /ingest/scans' handler is its
// only caller in this slice -- and re-checks the invariants that
// handler already enforces on the wire, the same defense-in-depth
// RecordApproval's own switch gives its table: a caller that reaches
// this function some other way (a test, or a future direct caller)
// cannot write a row the wire contract would have refused.
//
// s.ID is ignored (both engines generate it).
func RecordScanSnapshot(ctx context.Context, database db.Conn, s ScanSnapshot) error {
	switch {
	case s.CanaryID == "":
		return errors.New("store: RecordScanSnapshot: CanaryID is empty")
	case s.TakenAt.IsZero():
		return errors.New("store: RecordScanSnapshot: TakenAt is zero; callers must set it")
	case s.ReceivedAt.IsZero():
		return errors.New("store: RecordScanSnapshot: ReceivedAt is zero; callers must set it")
	case s.Status != ScanStatusOK && s.Status != ScanStatusFailed:
		return fmt.Errorf("store: RecordScanSnapshot: unknown status %q", s.Status)
	case s.Status == ScanStatusFailed && s.Reason == "":
		return errors.New("store: RecordScanSnapshot: Reason is required when Status is failed")
	case s.Status == ScanStatusOK && s.Reason != "":
		return errors.New("store: RecordScanSnapshot: Reason must be empty when Status is ok")
	case s.Status == ScanStatusFailed && s.FindingCount != 0:
		return errors.New("store: RecordScanSnapshot: FindingCount must be zero when Status is failed")
	case s.FindingCount < 0:
		return errors.New("store: RecordScanSnapshot: FindingCount must not be negative")
	}
	for _, p := range s.MaskedPaths {
		if !isAbsolutePath(p) {
			return fmt.Errorf("store: RecordScanSnapshot: MaskedPaths entry %q is not an absolute path", p)
		}
	}

	maskedPaths, err := marshalMaskedPaths(s.MaskedPaths)
	if err != nil {
		return fmt.Errorf("marshal masked paths: %w", err)
	}

	_, err = database.ExecContext(ctx, `
		INSERT INTO scan_snapshots (canary_id, taken_at, received_at, engine_name, engine_version, db_built_at, status, reason, finding_count, masked_paths)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.CanaryID, s.TakenAt.UTC().Format(receivedAtLayout), s.ReceivedAt.UTC().Format(receivedAtLayout),
		s.EngineName, s.EngineVersion, nullableTime(s.DBBuiltAt), s.Status, s.Reason, s.FindingCount, maskedPaths)
	if err != nil {
		return fmt.Errorf("insert scan snapshot: %w", err)
	}
	return nil
}

// ListScanSnapshots returns every recorded scan receipt, newest first --
// the minimal read-back GET /api/scans serves for slice 1. Filtering and
// paging are left to #109, once there is a findings table worth either
// over.
func ListScanSnapshots(ctx context.Context, database *db.DB) ([]ScanSnapshot, error) {
	rows, err := database.QueryContext(ctx, `SELECT `+scanSnapshotColumns+` FROM scan_snapshots ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("query scan snapshots: %w", err)
	}
	defer func() { _ = rows.Close() }()

	snapshots := []ScanSnapshot{}
	for rows.Next() {
		var (
			s                   ScanSnapshot
			takenAt, receivedAt string
			dbBuiltAt           *string
			maskedPaths         string
		)
		if err := rows.Scan(&s.ID, &s.CanaryID, &takenAt, &receivedAt, &s.EngineName, &s.EngineVersion,
			&dbBuiltAt, &s.Status, &s.Reason, &s.FindingCount, &maskedPaths); err != nil {
			return nil, fmt.Errorf("scan scan snapshot: %w", err)
		}
		if s.TakenAt, err = time.Parse(receivedAtLayout, takenAt); err != nil {
			return nil, fmt.Errorf("parse scan snapshot taken_at %q: %w", takenAt, err)
		}
		if s.ReceivedAt, err = time.Parse(receivedAtLayout, receivedAt); err != nil {
			return nil, fmt.Errorf("parse scan snapshot received_at %q: %w", receivedAt, err)
		}
		if s.DBBuiltAt, err = parseNullableTime(dbBuiltAt, "db_built_at"); err != nil {
			return nil, err
		}
		if s.MaskedPaths, err = unmarshalMaskedPaths(maskedPaths); err != nil {
			return nil, fmt.Errorf("parse scan snapshot masked_paths %q: %w", maskedPaths, err)
		}
		snapshots = append(snapshots, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scan snapshots: %w", err)
	}
	return snapshots, nil
}

// isAbsolutePath reports whether p looks like an absolute filesystem
// path -- the same minimal check POST /ingest/scans' handler applies to
// each entry on the wire, re-applied here so this function's own
// invariant holds regardless of caller.
func isAbsolutePath(p string) bool {
	return len(p) > 0 && p[0] == '/'
}

// marshalMaskedPaths and unmarshalMaskedPaths are masked_paths' JSON
// text round trip (migration 0014's own comment: chosen to match
// canary_commands.params' precedent for a structured/list-valued
// column, since a path -- unlike canaries.ports' bare port numbers --
// is free text that could itself contain a comma). A nil slice
// marshals as "[]", never "null": every snapshot has an opinion about
// what it could not see, including the empty case.
func marshalMaskedPaths(paths []string) (string, error) {
	if paths == nil {
		paths = []string{}
	}
	b, err := json.Marshal(paths)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func unmarshalMaskedPaths(raw string) ([]string, error) {
	paths := []string{}
	if raw == "" {
		return paths, nil
	}
	if err := json.Unmarshal([]byte(raw), &paths); err != nil {
		return nil, err
	}
	if paths == nil {
		paths = []string{}
	}
	return paths, nil
}
