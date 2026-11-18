// Package store: this file is issue #213's age-based retention for one
// agent's fixed findings and scan snapshots (owner question 39, answered
// b: configurable, BIRDCAGE_FINDINGS_RETENTION_DAYS, default 90, 0 keeps
// for good). Standard pattern: prune-on-write, bounded to the agent
// whose snapshot was just written, the same shape pruneFixedFindings and
// RecordHeartbeat use, so there is no background job to schedule.
package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

// PruneByAge removes agentID's fixed findings whose last_seen, and scan
// snapshots whose received_at, is more than retentionDays days before
// now. Open and accepted findings are never removed by age. The agent's
// newest snapshot and its newest ok snapshot are always kept, so
// FindingsStaleness still reads Stale and LastOKScan after any window.
// A snapshot whose received_at does not parse is skipped and logged.
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
	cutoff := now.UTC().AddDate(0, 0, -retentionDays).Format("2006-01-02T15:04:05")

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

	if counts.Snapshots, err = pruneOldSnapshots(ctx, conn, agentID, cutoff); err != nil {
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
// (a whole-second prefix; see PruneByAge). It keeps the agent's newest
// snapshot and its newest ok snapshot when either is among the old rows:
// FindingsStaleness reads Stale from the first and LastOKScan from the
// second, and losing the second would make an agent that has only failed
// for longer than the window read as never having scanned at all.
//
// Old rows are read pruneBatch at a time, in (received_at, id) order
// from the index, and each batch's removals are deleted before the next
// read, so neither memory nor one statement grows with the backlog. The
// candidates for keeping are tracked across batches: one displaced by a
// newer row is deleted with the batch that displaced it.
//
// A row whose received_at does not parse is skipped and logged, never
// removed and never an error: one bad row must not block every later
// scan from the agent.
func pruneOldSnapshots(ctx context.Context, conn findingConn, agentID, cutoff string) (int64, error) {
	hasNewer, err := snapshotSince(ctx, conn, agentID, cutoff, false)
	if err != nil {
		return 0, err
	}
	hasNewerOK, err := snapshotSince(ctx, conn, agentID, cutoff, true)
	if err != nil {
		return 0, err
	}

	// keepNewest and keepOK are the old rows currently held back; nil
	// when a row in the window already plays that part.
	var keepNewest, keepOK *snapRow
	held := func(id int64) bool {
		return (keepNewest != nil && keepNewest.id == id) || (keepOK != nil && keepOK.id == id)
	}

	var removed int64
	cursorAt, cursorID := "", int64(0)
	for {
		batch, err := readSnapshotBatch(ctx, conn, agentID, `received_at < ?`, []any{cutoff}, cursorAt, cursorID)
		if err != nil {
			return 0, err
		}
		var doomed []any
		for _, r := range batch.rows {
			var displaced []*snapRow
			if !hasNewer && (keepNewest == nil || r.newerThan(*keepNewest)) {
				displaced = append(displaced, keepNewest)
				keepNewest = &r
			}
			if !hasNewerOK && r.ok && (keepOK == nil || r.newerThan(*keepOK)) {
				displaced = append(displaced, keepOK)
				keepOK = &r
			}
			for _, d := range displaced {
				if d != nil && !held(d.id) {
					doomed = append(doomed, d.id)
				}
			}
			if !held(r.id) {
				doomed = append(doomed, r.id)
			}
		}
		if len(doomed) > 0 {
			args := append([]any{agentID}, doomed...)
			res, err := conn.ExecContext(ctx,
				`DELETE FROM scan_snapshots WHERE agent_id = ? AND id IN (`+placeholders(len(doomed))+`)`, args...)
			if err != nil {
				return 0, fmt.Errorf("prune old scan snapshots for %s: %w", agentID, err)
			}
			n, err := res.RowsAffected()
			if err != nil {
				return 0, fmt.Errorf("count pruned scan snapshots for %s: %w", agentID, err)
			}
			removed += n
		}
		if !batch.more {
			return removed, nil
		}
		cursorAt, cursorID = batch.lastAt, batch.lastID
	}
}

// pruneBatch is how many snapshot rows one retention read returns. Each
// batch's deletes also name at most this many ids (two displaced keep
// candidates can add to a batch, so the bound is pruneBatch+2).
const pruneBatch = 500

// snapRow is one parsed scan_snapshots row as retention reads it.
type snapRow struct {
	id int64
	at time.Time
	ok bool
}

// newerThan orders by parsed received_at, then id: never by SQL order on
// the stored text (FindingsStaleness picks the same rows the same way).
func (r snapRow) newerThan(o snapRow) bool {
	if !r.at.Equal(o.at) {
		return r.at.After(o.at)
	}
	return r.id > o.id
}

// snapshotBatch is one keyset page: the rows that parsed, whether a
// full page came back, and the cursor (raw text, id) to continue from.
type snapshotBatch struct {
	rows   []snapRow
	more   bool
	lastAt string
	lastID int64
}

// readSnapshotBatch reads up to pruneBatch of agentID's snapshots
// matching where, after the (received_at, id) cursor, in that order.
// Unparseable received_at values are logged and left out of rows.
func readSnapshotBatch(ctx context.Context, conn findingConn, agentID, where string, whereArgs []any, cursorAt string, cursorID int64) (snapshotBatch, error) {
	args := append([]any{agentID}, whereArgs...)
	args = append(args, cursorAt, cursorAt, cursorID, pruneBatch)
	rows, err := conn.QueryContext(ctx, `
		SELECT id, received_at, status FROM scan_snapshots
		WHERE agent_id = ? AND `+where+` AND (received_at > ? OR (received_at = ? AND id > ?))
		ORDER BY received_at, id LIMIT ?`, args...)
	if err != nil {
		return snapshotBatch{}, fmt.Errorf("query scan snapshots for retention, %s: %w", agentID, err)
	}
	var b snapshotBatch
	n := 0
	for rows.Next() {
		var (
			id          int64
			raw, status string
		)
		if err := rows.Scan(&id, &raw, &status); err != nil {
			_ = rows.Close()
			return snapshotBatch{}, fmt.Errorf("scan scan snapshot for retention: %w", err)
		}
		n++
		b.lastAt, b.lastID = raw, id
		at, err := time.Parse(receivedAtLayout, raw)
		if err != nil {
			slog.Warn("store: retention skipped a scan snapshot whose received_at does not parse",
				"agent", agentID, "snapshot_id", id, "received_at", raw, "err", err)
			continue
		}
		b.rows = append(b.rows, snapRow{id: id, at: at, ok: status == ScanStatusOK})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return snapshotBatch{}, fmt.Errorf("iterate scan snapshots for retention, %s: %w", agentID, err)
	}
	if err := rows.Close(); err != nil {
		return snapshotBatch{}, fmt.Errorf("close scan snapshots for retention, %s: %w", agentID, err)
	}
	b.more = n == pruneBatch
	return b, nil
}

// snapshotSince reports whether agentID has a snapshot (an ok one when
// okOnly) received at or after cutoff whose received_at parses. It reads
// up from the cutoff in index order and normally stops at the first row;
// an unparseable value (which can sort anywhere) is skipped.
func snapshotSince(ctx context.Context, conn findingConn, agentID, cutoff string, okOnly bool) (bool, error) {
	where, whereArgs := `received_at >= ?`, []any{cutoff}
	if okOnly {
		where += ` AND status = ?`
		whereArgs = append(whereArgs, ScanStatusOK)
	}
	cursorAt, cursorID := "", int64(0)
	for {
		b, err := readSnapshotBatch(ctx, conn, agentID, where, whereArgs, cursorAt, cursorID)
		if err != nil {
			return false, err
		}
		if len(b.rows) > 0 {
			return true, nil
		}
		if !b.more {
			return false, nil
		}
		cursorAt, cursorID = b.lastAt, b.lastID
	}
}

// placeholders returns n comma-separated "?" for an IN list; db.DB and
// db.Tx rebind them for Postgres.
func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}
