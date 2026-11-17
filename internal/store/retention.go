// Package store: this file is issue #213's age-based retention for one
// agent's fixed findings and scan snapshots (owner question 39, answered
// b: configurable, BIRDCAGE_FINDINGS_RETENTION_DAYS, default 90, 0 keeps
// for good). Standard pattern: prune-on-write, bounded to the agent
// whose snapshot was just written, the same shape pruneFixedFindings and
// RecordHeartbeat use, so there is no background job to schedule.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/audit"
)

// AuditActionRetentionPruned is the audit_log action PruneByAge writes,
// once per run that removed anything, target the agent id.
const AuditActionRetentionPruned = "findings.retention_pruned"

// PruneCounts is what one PruneByAge run removed.
type PruneCounts struct {
	Findings  int64
	Snapshots int64
}

// maxRetentionDays is about 1,000 years: any longer window removes
// nothing, the same as 0.
const maxRetentionDays = 366000

// pruneDeleteChunk bounds how many ids one DELETE ... IN (...) names.
const pruneDeleteChunk = 500

// PruneByAge removes agentID's fixed findings whose last_seen, and scan
// snapshots whose received_at, is more than retentionDays days before
// now. Open and accepted findings are never removed by age. The agent's
// newest snapshot is always kept, so FindingsStaleness can still say
// whether the last scan failed; an ok snapshot older than the window
// does go, so LastOKScan reads as none once no ok scan is left in it.
// retentionDays 0 removes nothing; negative is an error.
// A run that removes anything writes one audit row with both counts.
//
// The cutoff is compared in SQL against the stored RFC3339Nano UTC text
// by its whole-second prefix ("2006-01-02T15:04:05", no fraction, no
// zone): a stored value sorts below that prefix exactly when its own
// second is earlier, whatever fraction it carries, so the trimmed-
// fraction trap 0010_canary_state_periods.sql describes cannot misorder
// it. Rows in the cutoff's own second are kept, never removed early.
// Every stored value shares the prefix's punctuation positions, so the
// order holds under Postgres' default (non-C) collation as well.
// Both predicates are served by migration 0030's indexes.
//
// conn is the scan ingest transaction in production, so the removal and
// its audit row commit with the snapshot that triggered them.
func PruneByAge(ctx context.Context, conn findingConn, agentID string, retentionDays int, now time.Time) (PruneCounts, error) {
	if agentID == "" {
		return PruneCounts{}, errors.New("store: PruneByAge: agentID is empty")
	}
	if retentionDays < 0 {
		return PruneCounts{}, fmt.Errorf("store: PruneByAge: retention of %d days is negative", retentionDays)
	}
	// 0 keeps for good. So does a window longer than any stored row can
	// be old: a day count large enough to overflow AddDate would wrap
	// the cutoff into the future and remove everything.
	if retentionDays == 0 || retentionDays > maxRetentionDays {
		return PruneCounts{}, nil
	}
	if now.IsZero() {
		return PruneCounts{}, errors.New("store: PruneByAge: now is zero; callers must set it")
	}
	cutoffAt := now.UTC().AddDate(0, 0, -retentionDays).Truncate(time.Second)
	cutoff := cutoffAt.Format("2006-01-02T15:04:05")

	var counts PruneCounts
	res, err := conn.ExecContext(ctx, `
		DELETE FROM findings WHERE agent_id = ? AND state = ? AND last_seen < ?`,
		agentID, string(FindingFixed), cutoff)
	if err != nil {
		return PruneCounts{}, fmt.Errorf("prune old fixed findings for %s: %w", agentID, err)
	}
	if counts.Findings, err = res.RowsAffected(); err != nil {
		return PruneCounts{}, fmt.Errorf("count pruned fixed findings for %s: %w", agentID, err)
	}

	if counts.Snapshots, err = pruneOldSnapshots(ctx, conn, agentID, cutoff, cutoffAt); err != nil {
		return PruneCounts{}, err
	}

	if counts == (PruneCounts{}) {
		return counts, nil
	}
	if _, err := audit.Append(ctx, conn, audit.Entry{
		Action: AuditActionRetentionPruned,
		Target: agentID,
		Reason: fmt.Sprintf("removed %d fixed findings and %d scan snapshots older than %d days (BIRDCAGE_FINDINGS_RETENTION_DAYS)",
			counts.Findings, counts.Snapshots, retentionDays),
		TriggeredBy: "retention",
		CreatedAt:   now,
	}); err != nil {
		return PruneCounts{}, fmt.Errorf("record retention audit entry for %s: %w", agentID, err)
	}
	return counts, nil
}

// pruneOldSnapshots removes agentID's snapshots received before cutoff
// (a whole-second prefix; see PruneByAge), keeping the agent's newest
// snapshot when it is among them. Only the old rows are read, so a run
// reads what accumulated since the last one.
func pruneOldSnapshots(ctx context.Context, conn findingConn, agentID, cutoff string, cutoffAt time.Time) (int64, error) {
	type snap struct {
		id         int64
		receivedAt time.Time
	}
	rows, err := conn.QueryContext(ctx, `
		SELECT id, received_at FROM scan_snapshots WHERE agent_id = ? AND received_at < ?`,
		agentID, cutoff)
	if err != nil {
		return 0, fmt.Errorf("query old scan snapshots for %s: %w", agentID, err)
	}
	var old []snap
	for rows.Next() {
		var (
			s   snap
			raw string
		)
		if err := rows.Scan(&s.id, &raw); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("scan old scan snapshot: %w", err)
		}
		if s.receivedAt, err = time.Parse(receivedAtLayout, raw); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("parse scan snapshot received_at %q: %w", raw, err)
		}
		old = append(old, s)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("iterate old scan snapshots for %s: %w", agentID, err)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close old scan snapshots for %s: %w", agentID, err)
	}
	if len(old) == 0 {
		return 0, nil
	}

	hasNewer, err := snapshotExistsSince(ctx, conn, agentID, cutoffAt)
	if err != nil {
		return 0, err
	}
	// Newest by parsed received_at, then id: never by SQL order on the
	// stored text (FindingsStaleness picks the same row the same way).
	keep := int64(-1)
	if !hasNewer {
		newest := old[0]
		for _, s := range old[1:] {
			if s.receivedAt.After(newest.receivedAt) || (s.receivedAt.Equal(newest.receivedAt) && s.id > newest.id) {
				newest = s
			}
		}
		keep = newest.id
	}

	var doomed []any
	for _, s := range old {
		if s.id != keep {
			doomed = append(doomed, s.id)
		}
	}
	var removed int64
	for start := 0; start < len(doomed); start += pruneDeleteChunk {
		end := min(start+pruneDeleteChunk, len(doomed))
		chunk := doomed[start:end]
		args := append([]any{agentID}, chunk...)
		res, err := conn.ExecContext(ctx,
			`DELETE FROM scan_snapshots WHERE agent_id = ? AND id IN (`+placeholders(len(chunk))+`)`, args...)
		if err != nil {
			return 0, fmt.Errorf("prune old scan snapshots for %s: %w", agentID, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("count pruned scan snapshots for %s: %w", agentID, err)
		}
		removed += n
	}
	return removed, nil
}

// snapshotExistsSince reports whether agentID has a snapshot received at
// or after cutoff. MAX on the leading-agent_id index is one index probe
// on both engines; the value is then compared in Go, by parsed time.
func snapshotExistsSince(ctx context.Context, conn findingConn, agentID string, cutoff time.Time) (bool, error) {
	var latest sql.NullString
	if err := conn.QueryRowContext(ctx, `
		SELECT MAX(received_at) FROM scan_snapshots WHERE agent_id = ?`, agentID).Scan(&latest); err != nil {
		return false, fmt.Errorf("query latest scan snapshot for %s: %w", agentID, err)
	}
	if !latest.Valid {
		return false, nil
	}
	t, err := time.Parse(receivedAtLayout, latest.String)
	if err != nil {
		return false, fmt.Errorf("parse scan snapshot received_at %q: %w", latest.String, err)
	}
	return !t.Before(cutoff), nil
}

// placeholders returns n comma-separated "?" for an IN list; db.DB and
// db.Tx rebind them for Postgres.
func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}
