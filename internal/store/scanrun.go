// Package store: this file is issue #116's scanner proof (ADR-0012
// decisions 1-6, 9-11). A scanner run is a self_test_runs row with one
// self_test_targets row (service "scan", no marker), minted alongside a
// CommandScan command; the scanner answers it with a snapshot on POST
// /ingest/scans carrying the run's id, and MatchScanRun settles it.
// Between mint and answer the run reports where it is (stage), so a run
// that goes quiet says where it stopped.
//
// Every time comparison that decides anything is made in Go on parsed
// values, never in SQL on the stored text (docs/flakes.md: the two
// engines compare text timestamps at different resolutions).
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/hostmask"
)

// ScanRunTrigger says who ordered a run: the enrolment proof (and, for a
// honeypot row, the schedule or first contact -- the column default), or
// an admin (ADR-0012 decision 7; nothing mints one yet). A manual run's
// pass never calls SettlePending.
type ScanRunTrigger string

const (
	TriggerProof  ScanRunTrigger = "proof"
	TriggerManual ScanRunTrigger = "manual"
)

// ScanStage is where an ordered scan has got to (ADR-0012 decision 9).
// Birdcage sets ordered (mint), collected (claim) and answered (the
// snapshot); the scanner reports the three between on its heartbeat.
type ScanStage string

const (
	StageOrdered       ScanStage = "ordered"
	StageCollected     ScanStage = "collected"
	StageMountsChecked ScanStage = "mounts_checked"
	StageDBRefreshed   ScanStage = "db_refreshed"
	StageScanning      ScanStage = "scanning"
	StageAnswered      ScanStage = "answered"
)

// stageRank is the stages' order. Stages only move forward.
var stageRank = map[ScanStage]int{
	StageOrdered:       0,
	StageCollected:     1,
	StageMountsChecked: 2,
	StageDBRefreshed:   3,
	StageScanning:      4,
	StageAnswered:      5,
}

// AgentReportableStage reports whether s is one of the three stages a
// scanner may report on its heartbeat. Every other string, including
// the three birdcage sets itself, is refused on the wire.
func AgentReportableStage(s string) bool {
	switch ScanStage(s) {
	case StageMountsChecked, StageDBRefreshed, StageScanning:
		return true
	}
	return false
}

// ScanService is the one self_test_targets.service a scan run carries.
// No marker: like portscan and poisoner, nothing is planted.
const ScanService = "scan"

// ScanDBMaxAge is Grype's own max-allowed-built-age (ADR-0012 research:
// 120h), re-checked server side as the backstop for every snapshot.
const ScanDBMaxAge = 5 * 24 * time.Hour

// Reasons a scan run did not pass, stored on self_test_runs.reason and
// shown in the runs list. A run that failed on the scanner's own
// "failed" status carries ReasonScanFailed followed by ": " and the
// snapshot's reason text.
const (
	ReasonScanFailed        = "scan_failed"
	ReasonTakenBeforeIssued = "taken_before_issued"
	ReasonDBTooOld          = "db_too_old"
	ReasonDBRefreshFailed   = "db_refresh_failed"
	ReasonMasksIncomplete   = "masks_incomplete"
)

// runReasonMaxLen bounds the agent's own text carried into a run's
// reason.
const runReasonMaxLen = 500

// ScanParams is CommandScan's params: the run id and nothing else.
type ScanParams struct {
	RunID string `json:"run_id"`
}

// ErrScanRunOpen is MintScanCommand's refusal when the node already has
// an open scan run (one run in flight per scanner).
var ErrScanRunOpen = errors.New("store: a scan run is already open for this canary")

// ErrNotScanner is MintScanCommand's refusal for a canary that is not a
// registered scanner-kind node.
var ErrNotScanner = errors.New("store: canary is not a scanner")

// ScanDBTooOld reports whether a vulnerability database built at builtAt
// was past ScanDBMaxAge when the scan was taken -- Grype's own rule,
// which judges the database's age at scan time, re-applied server side.
// Measured against taken_at rather than receipt so a snapshot delivered
// late is not failed for the delay; for an ordered run taken_at is
// itself bounded below by the run's issued_at. A nil builtAt is too old:
// there is no database to vouch for.
func ScanDBTooOld(builtAt *time.Time, takenAt time.Time) bool {
	return builtAt == nil || takenAt.Sub(*builtAt) > ScanDBMaxAge
}

// MintScanCommand queues one scan command for canaryID and its run, in
// one transaction: the canary_commands row, the self_test_runs row
// (trigger, stage "ordered") and its single self_test_targets row. The
// command expires at the run's deadline. Refused with ErrScanRunOpen
// while the node has an open scan run -- checked here and enforced by
// migration 0022's partial unique index, so two racing mints cannot both
// win -- and with ErrNotScanner for any canary that is not a scanner.
func MintScanCommand(ctx context.Context, database *db.DB, canaryID string, trigger ScanRunTrigger, now, deadline time.Time) (CanaryCommand, error) {
	if trigger != TriggerProof && trigger != TriggerManual {
		return CanaryCommand{}, fmt.Errorf("store: MintScanCommand: unknown trigger %q", trigger)
	}
	runID, err := randomHex(commandIDBytes)
	if err != nil {
		return CanaryCommand{}, fmt.Errorf("generate scan run id: %w", err)
	}
	raw, err := json.Marshal(ScanParams{RunID: runID})
	if err != nil {
		return CanaryCommand{}, fmt.Errorf("marshal scan params: %w", err)
	}

	tx, err := database.Begin(ctx)
	if err != nil {
		return CanaryCommand{}, fmt.Errorf("begin scan mint transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var kind string
	if err := tx.QueryRowContext(ctx, `SELECT kind FROM agents WHERE id = ?`, canaryID).Scan(&kind); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CanaryCommand{}, fmt.Errorf("%w: %s not found", ErrNotScanner, canaryID)
		}
		return CanaryCommand{}, fmt.Errorf("look up canary kind: %w", err)
	}
	if agentkind.Kind(kind) != agentkind.Scanner {
		return CanaryCommand{}, fmt.Errorf("%w: %s is kind %q", ErrNotScanner, canaryID, kind)
	}

	var open int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM self_test_runs
		WHERE agent_id = ? AND completed_at IS NULL AND stage IS NOT NULL`, canaryID).Scan(&open); err != nil {
		return CanaryCommand{}, fmt.Errorf("count open scan runs: %w", err)
	}
	if open > 0 {
		return CanaryCommand{}, ErrScanRunOpen
	}

	cmd, err := MintCanaryCommand(ctx, tx, canaryID, CommandScan, string(raw), now, deadline)
	if err != nil {
		return CanaryCommand{}, err
	}
	createdAt := cmd.CreatedAt.Format(receivedAtLayout)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO self_test_runs (command_id, agent_id, run_id, issued_at, deadline_at, "trigger", stage, stage_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		cmd.ID, canaryID, runID, createdAt, cmd.ExpiresAt.Format(receivedAtLayout),
		string(trigger), string(StageOrdered), createdAt); err != nil {
		return CanaryCommand{}, fmt.Errorf("insert scan self_test_runs: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO self_test_targets (command_id, service, dest_port, marker_hash, grade)
		VALUES (?, ?, 0, '', ?)`,
		cmd.ID, ScanService, string(gradeForService(ScanService))); err != nil {
		return CanaryCommand{}, fmt.Errorf("insert scan self_test_targets: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return CanaryCommand{}, fmt.Errorf("commit scan mint transaction: %w", err)
	}
	committed = true
	return cmd, nil
}

// scanRunRow is one scan run as MatchScanRun and AdvanceRunStage read it.
type scanRunRow struct {
	commandID   string
	issuedAt    time.Time
	deadlineAt  time.Time
	completedAt *time.Time
	trigger     ScanRunTrigger
	stage       ScanStage
}

// lookupScanRun resolves runID for canaryID -- the posting node, from its
// token -- among scan runs only (stage set). ok is false for a run that
// does not exist, belongs to another node, or is a honeypot run.
func lookupScanRun(ctx context.Context, conn db.Conn, canaryID, runID string) (r scanRunRow, ok bool, err error) {
	var (
		issuedAt, deadlineAt, trigger, stage string
		completedAt                          *string
	)
	err = conn.QueryRowContext(ctx, `
		SELECT command_id, issued_at, deadline_at, completed_at, "trigger", stage
		FROM self_test_runs
		WHERE run_id = ? AND agent_id = ? AND stage IS NOT NULL`, runID, canaryID).
		Scan(&r.commandID, &issuedAt, &deadlineAt, &completedAt, &trigger, &stage)
	if errors.Is(err, sql.ErrNoRows) {
		return scanRunRow{}, false, nil
	}
	if err != nil {
		return scanRunRow{}, false, fmt.Errorf("look up scan run: %w", err)
	}
	if r.issuedAt, err = time.Parse(receivedAtLayout, issuedAt); err != nil {
		return scanRunRow{}, false, fmt.Errorf("parse issued_at %q: %w", issuedAt, err)
	}
	if r.deadlineAt, err = time.Parse(receivedAtLayout, deadlineAt); err != nil {
		return scanRunRow{}, false, fmt.Errorf("parse deadline_at %q: %w", deadlineAt, err)
	}
	if r.completedAt, err = parseNullableTime(completedAt, "completed_at"); err != nil {
		return scanRunRow{}, false, err
	}
	r.trigger = ScanRunTrigger(trigger)
	r.stage = ScanStage(stage)
	return r, true, nil
}

// open reports whether r can still be answered or advanced as of now.
func (r scanRunRow) open(now time.Time) bool {
	return r.completedAt == nil && now.Before(r.deadlineAt)
}

// ScanRunOutcome is what MatchScanRun decided.
type ScanRunOutcome int

const (
	// ScanRunUnknown: no such run for this node. The caller refuses the
	// whole request and stores nothing.
	ScanRunUnknown ScanRunOutcome = iota
	// ScanRunStale: the run is already completed or past its deadline.
	// The snapshot is stored (it is real data) and settles nothing.
	ScanRunStale
	// ScanRunFail: the run completed with passed = 0; Reason says why.
	ScanRunFail
	// ScanRunPass: the run completed with passed = 1.
	ScanRunPass
)

// ScanRunMatch is MatchScanRun's result. CommandID is the settled run's
// key, for the snapshot's self_test_run_id; empty unless Outcome is
// ScanRunPass or ScanRunFail.
type ScanRunMatch struct {
	Outcome   ScanRunOutcome
	CommandID string
	Reason    string
}

// MatchScanRun settles canaryID's run runID against snap, inside the
// caller's transaction (the snapshot's own): ADR-0012 decision 4.
//
//   - Unknown run, or another node's: ScanRunUnknown, nothing written.
//   - Completed, or at or past its deadline: ScanRunStale, nothing written.
//   - Otherwise the run completes now, stage "answered". It fails, with a
//     reason, on a failed status, a snapshot taken before the run was
//     issued, a database older than ScanDBMaxAge (at scan time), a
//     refresh not at or after issued_at, or masked_paths missing any of
//     hostmask.Paths(); it passes otherwise. A proof run's pass calls
//     SettlePending; a manual run's never does.
//
// The caller then stores snap with SelfTestRunID = CommandID.
func MatchScanRun(ctx context.Context, conn db.Conn, canaryID, runID string, snap ScanSnapshot, now time.Time) (ScanRunMatch, error) {
	now = now.UTC()
	run, ok, err := lookupScanRun(ctx, conn, canaryID, runID)
	if err != nil {
		return ScanRunMatch{}, err
	}
	if !ok {
		return ScanRunMatch{Outcome: ScanRunUnknown}, nil
	}
	if !run.open(now) {
		return ScanRunMatch{Outcome: ScanRunStale}, nil
	}

	reason := scanRunFailure(run, snap)
	passed := 0
	outcome := ScanRunFail
	if reason == "" {
		passed = 1
		outcome = ScanRunPass
	}
	nowStr := now.Format(receivedAtLayout)
	res, err := conn.ExecContext(ctx, `
		UPDATE self_test_runs SET completed_at = ?, passed = ?, stage = ?, stage_at = ?, reason = ?
		WHERE command_id = ? AND completed_at IS NULL`,
		nowStr, passed, string(StageAnswered), nowStr, emptyToNull(reason), run.commandID)
	if err != nil {
		return ScanRunMatch{}, fmt.Errorf("complete scan run: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return ScanRunMatch{}, fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		// Completed between the read and here (the sweep, or a second
		// answer): the snapshot answered a spent run.
		return ScanRunMatch{Outcome: ScanRunStale}, nil
	}
	if outcome == ScanRunPass {
		if _, err := conn.ExecContext(ctx, `
			UPDATE self_test_targets SET matched_at = ? WHERE command_id = ? AND matched_at IS NULL`,
			nowStr, run.commandID); err != nil {
			return ScanRunMatch{}, fmt.Errorf("mark scan target matched: %w", err)
		}
		if run.trigger == TriggerProof {
			if err := SettlePending(ctx, conn, canaryID, now); err != nil {
				return ScanRunMatch{}, err
			}
		}
	}
	return ScanRunMatch{Outcome: outcome, CommandID: run.commandID, Reason: reason}, nil
}

// scanRunFailure is decision 4's pass rule: "" when snap passes run, the
// reason otherwise.
func scanRunFailure(run scanRunRow, snap ScanSnapshot) string {
	switch {
	case snap.Status != ScanStatusOK:
		return truncateReason(ReasonScanFailed + ": " + snap.Reason)
	case snap.TakenAt.Before(run.issuedAt):
		return ReasonTakenBeforeIssued
	case ScanDBTooOld(snap.DBBuiltAt, snap.TakenAt):
		return ReasonDBTooOld
	case snap.DBRefreshedAt == nil || snap.DBRefreshedAt.Before(run.issuedAt):
		return ReasonDBRefreshFailed
	case !masksComplete(snap.MaskedPaths):
		return ReasonMasksIncomplete
	}
	return ""
}

// masksComplete reports whether reported covers every path in
// hostmask.Paths() -- the whole owner-ratified set. A path reported on
// top of it is more blind spot, not less proof, so it does not fail.
func masksComplete(reported []string) bool {
	have := make(map[string]bool, len(reported))
	for _, p := range reported {
		have[p] = true
	}
	for _, p := range hostmask.Paths() {
		if !have[p] {
			return false
		}
	}
	return true
}

func truncateReason(s string) string {
	if len(s) <= runReasonMaxLen {
		return s
	}
	return s[:runReasonMaxLen]
}

// StageResult is what AdvanceRunStage did.
type StageResult int

const (
	// StageStale: not this node's run, not open, or an earlier stage than
	// the one recorded. Ignored; the caller audits selftest.stage_stale.
	StageStale StageResult = iota
	// StageUnchanged: the stage already recorded, repeated (the scanner
	// repeats its current stage on every heartbeat tick). Not an error.
	StageUnchanged
	// StageAdvanced: the run moved forward to stage.
	StageAdvanced
)

// AdvanceRunStage moves canaryID's open scan run runID forward to stage
// as of now (ADR-0012 decision 9): own node, open run, forward only. An
// unknown stage string is an error -- the caller has already refused it
// on the wire. It never extends the deadline.
func AdvanceRunStage(ctx context.Context, conn db.Conn, canaryID, runID string, stage ScanStage, now time.Time) (StageResult, error) {
	rank, known := stageRank[stage]
	if !known {
		return StageStale, fmt.Errorf("store: AdvanceRunStage: unknown stage %q", stage)
	}
	now = now.UTC()
	run, ok, err := lookupScanRun(ctx, conn, canaryID, runID)
	if err != nil {
		return StageStale, err
	}
	if !ok || !run.open(now) {
		return StageStale, nil
	}
	current := stageRank[run.stage]
	if rank == current {
		return StageUnchanged, nil
	}
	if rank < current {
		return StageStale, nil
	}
	res, err := conn.ExecContext(ctx, `
		UPDATE self_test_runs SET stage = ?, stage_at = ?
		WHERE command_id = ? AND completed_at IS NULL AND stage = ?`,
		string(stage), now.Format(receivedAtLayout), run.commandID, string(run.stage))
	if err != nil {
		return StageStale, fmt.Errorf("advance scan run stage: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return StageStale, fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		// Moved or completed between the read and here; whatever won
		// is at least as far along.
		return StageStale, nil
	}
	return StageAdvanced, nil
}

// SetCanaryDBRefresh records canaryID's database refresh state (ADR-0012
// decision 10). failing records lastError and, only if not already
// failing, birdcage's own now as failing_since -- never the agent's
// clock. !failing clears both columns.
func SetCanaryDBRefresh(ctx context.Context, conn db.Conn, canaryID string, failing bool, lastError string, now time.Time) error {
	var err error
	if failing {
		_, err = conn.ExecContext(ctx, `
			UPDATE agents
			SET db_refresh_failing_since = COALESCE(db_refresh_failing_since, ?), db_refresh_error = ?
			WHERE id = ?`, now.UTC().Format(receivedAtLayout), truncateReason(lastError), canaryID)
	} else {
		_, err = conn.ExecContext(ctx, `
			UPDATE agents SET db_refresh_failing_since = NULL, db_refresh_error = NULL WHERE id = ?`, canaryID)
	}
	if err != nil {
		return fmt.Errorf("update db refresh state for %s: %w", canaryID, err)
	}
	return nil
}

// ScanRunOpen is the dashboard's view of a scanner's open run: who
// ordered it, where it is, since when. Never the run id.
type ScanRunOpen struct {
	Trigger  ScanRunTrigger `json:"trigger"`
	Stage    ScanStage      `json:"stage"`
	StageAt  time.Time      `json:"stage_at"`
	IssuedAt time.Time      `json:"issued_at"`
}

// Verdicts a completed scan run carries on the dashboard. expired is a
// run the deadline sweep closed: nothing answered it.
const (
	VerdictPass    = "pass"
	VerdictFail    = "fail"
	VerdictExpired = "expired"
)

// ScanRunLast is the dashboard's view of a scanner's most recently
// completed run.
type ScanRunLast struct {
	Verdict   string    `json:"verdict"`
	LastStage ScanStage `json:"last_stage"`
	Reason    string    `json:"reason,omitempty"`
	EndedAt   time.Time `json:"ended_at"`
}

// ScanRunSummary is one completed run in GET /api/canaries/{id}/runs.
// SnapshotID is the snapshot that settled it, nil for an expired run.
type ScanRunSummary struct {
	Trigger    ScanRunTrigger `json:"trigger"`
	IssuedAt   time.Time      `json:"issued_at"`
	EndedAt    time.Time      `json:"ended_at"`
	Verdict    string         `json:"verdict"`
	LastStage  ScanStage      `json:"last_stage"`
	Reason     string         `json:"reason,omitempty"`
	SnapshotID *int64         `json:"snapshot_id,omitempty"`
}

// scanRunRecord is one scan run row, read whole for the read model.
type scanRunRecord struct {
	commandID   string
	trigger     ScanRunTrigger
	issuedAt    time.Time
	deadlineAt  time.Time
	completedAt *time.Time
	passed      *bool
	stage       ScanStage
	stageAt     time.Time
	reason      string
}

func (r scanRunRecord) verdict() string {
	switch {
	case r.passed != nil && *r.passed:
		return VerdictPass
	case r.stage == StageAnswered:
		return VerdictFail
	default:
		return VerdictExpired
	}
}

// listScanRuns loads every scan run of canaryID (stage set). One node's
// runs are few -- one per 30 minutes while pending, then only on an
// admin's order -- so they are loaded whole and ordered in Go.
func listScanRuns(ctx context.Context, conn historyConn, canaryID string) ([]scanRunRecord, error) {
	rows, err := conn.QueryContext(ctx, `
		SELECT command_id, "trigger", issued_at, deadline_at, completed_at, passed, stage, stage_at, reason
		FROM self_test_runs WHERE agent_id = ? AND stage IS NOT NULL`, canaryID)
	if err != nil {
		return nil, fmt.Errorf("query scan runs for %s: %w", canaryID, err)
	}
	defer func() { _ = rows.Close() }()

	var out []scanRunRecord
	for rows.Next() {
		var (
			r                             scanRunRecord
			trigger, issuedAt, deadlineAt string
			stage                         string
			completedAt, stageAt, reason  *string
			passed                        *int64
		)
		if err := rows.Scan(&r.commandID, &trigger, &issuedAt, &deadlineAt, &completedAt, &passed, &stage, &stageAt, &reason); err != nil {
			return nil, fmt.Errorf("scan scan run: %w", err)
		}
		r.trigger = ScanRunTrigger(trigger)
		r.stage = ScanStage(stage)
		if r.issuedAt, err = time.Parse(receivedAtLayout, issuedAt); err != nil {
			return nil, fmt.Errorf("parse issued_at %q: %w", issuedAt, err)
		}
		if r.deadlineAt, err = time.Parse(receivedAtLayout, deadlineAt); err != nil {
			return nil, fmt.Errorf("parse deadline_at %q: %w", deadlineAt, err)
		}
		if r.completedAt, err = parseNullableTime(completedAt, "completed_at"); err != nil {
			return nil, err
		}
		r.stageAt = r.issuedAt
		if stageAt != nil {
			if r.stageAt, err = time.Parse(receivedAtLayout, *stageAt); err != nil {
				return nil, fmt.Errorf("parse stage_at %q: %w", *stageAt, err)
			}
		}
		if passed != nil {
			p := *passed != 0
			r.passed = &p
		}
		if reason != nil {
			r.reason = *reason
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scan runs for %s: %w", canaryID, err)
	}
	return out, nil
}

// DefaultScanRunsLimit bounds GET /api/canaries/{id}/runs.
const DefaultScanRunsLimit = 50

// ListScannerRuns returns canaryID's completed scan runs, newest issued
// first, at most limit of them (limit <= 0 means DefaultScanRunsLimit):
// decision 11's Runs list. Never the run id. ErrCanaryNotFound when
// canaryID names no canary; an empty, non-nil list for one with no scan
// runs.
func ListScannerRuns(ctx context.Context, database *db.DB, canaryID string, limit int) ([]ScanRunSummary, error) {
	if limit <= 0 {
		limit = DefaultScanRunsLimit
	}
	_, found, err := SelfTestCanaryByID(ctx, database, canaryID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrCanaryNotFound
	}
	runs, err := listScanRuns(ctx, database, canaryID)
	if err != nil {
		return nil, err
	}
	completed := runs[:0]
	for _, r := range runs {
		if r.completedAt != nil {
			completed = append(completed, r)
		}
	}
	sort.SliceStable(completed, func(i, j int) bool { return completed[i].issuedAt.After(completed[j].issuedAt) })
	if len(completed) > limit {
		completed = completed[:limit]
	}

	snapshots, err := snapshotsByRun(ctx, database, canaryID)
	if err != nil {
		return nil, err
	}
	out := make([]ScanRunSummary, len(completed))
	for i, r := range completed {
		out[i] = ScanRunSummary{
			Trigger:   r.trigger,
			IssuedAt:  r.issuedAt,
			EndedAt:   *r.completedAt,
			Verdict:   r.verdict(),
			LastStage: r.stage,
			Reason:    r.reason,
		}
		if id, ok := snapshots[r.commandID]; ok {
			out[i].SnapshotID = &id
		}
	}
	return out, nil
}

// snapshotsByRun maps each settled run's command id to the snapshot that
// settled it.
func snapshotsByRun(ctx context.Context, database *db.DB, canaryID string) (map[string]int64, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT id, self_test_run_id FROM scan_snapshots
		WHERE agent_id = ? AND self_test_run_id IS NOT NULL`, canaryID)
	if err != nil {
		return nil, fmt.Errorf("query run snapshots for %s: %w", canaryID, err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int64{}
	for rows.Next() {
		var (
			id    int64
			runID string
		)
		if err := rows.Scan(&id, &runID); err != nil {
			return nil, fmt.Errorf("scan run snapshot: %w", err)
		}
		out[runID] = id
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate run snapshots for %s: %w", canaryID, err)
	}
	return out, nil
}

// latestOKSnapshotReceivedAt returns when canaryID's newest status-ok
// snapshot was received, or nil if it has none. Compared in Go.
func latestOKSnapshotReceivedAt(ctx context.Context, database *db.DB, canaryID string) (*time.Time, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT received_at FROM scan_snapshots WHERE agent_id = ? AND status = ?`, canaryID, ScanStatusOK)
	if err != nil {
		return nil, fmt.Errorf("query ok snapshots for %s: %w", canaryID, err)
	}
	defer func() { _ = rows.Close() }()
	var latest *time.Time
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan ok snapshot received_at: %w", err)
		}
		t, err := time.Parse(receivedAtLayout, raw)
		if err != nil {
			return nil, fmt.Errorf("parse received_at %q: %w", raw, err)
		}
		if latest == nil || t.After(*latest) {
			latest = &t
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ok snapshots for %s: %w", canaryID, err)
	}
	return latest, nil
}

// applyScanRunState fills a scanner's Run (open run) and LastRun (most
// recent completed run), and decides whether the self_test_failed that
// applySelfTestState reported still stands: for a scanner it clears on
// any status-ok snapshot received after the failed run ended
// (ADR-0012 decision 6) -- the tile clears, the record does not.
func applyScanRunState(ctx context.Context, database *db.DB, c *Canary, testFailed bool, now time.Time) (bool, error) {
	runs, err := listScanRuns(ctx, database, c.ID)
	if err != nil {
		return false, err
	}
	var open, last *scanRunRecord
	for i := range runs {
		r := &runs[i]
		if r.completedAt == nil {
			if now.Before(r.deadlineAt) && (open == nil || r.issuedAt.After(open.issuedAt)) {
				open = r
			}
			continue
		}
		if last == nil || r.completedAt.After(*last.completedAt) {
			last = r
		}
	}
	if open != nil {
		c.Run = &ScanRunOpen{Trigger: open.trigger, Stage: open.stage, StageAt: open.stageAt, IssuedAt: open.issuedAt}
	}
	if last != nil {
		c.LastRun = &ScanRunLast{Verdict: last.verdict(), LastStage: last.stage, Reason: last.reason, EndedAt: *last.completedAt}
	}
	if !testFailed || c.LastSelfTestAt == nil {
		return testFailed, nil
	}
	okAt, err := latestOKSnapshotReceivedAt(ctx, database, c.ID)
	if err != nil {
		return false, err
	}
	if okAt != nil && okAt.After(*c.LastSelfTestAt) {
		return false, nil
	}
	return true, nil
}
