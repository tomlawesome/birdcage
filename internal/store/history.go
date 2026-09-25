// Package store: this file is the read/write path for
// canary_state_periods (issue #56, migration 0010) -- how long each
// canary spent in each of issue #45's health states. #45 derives those
// states fresh on every GET /api/canaries and keeps nothing, so
// "throttled for eleven minutes last night" had nowhere to come from.
//
// Nothing here derives a state. internal/history's recorder reads what
// ListCanaries already computed (health.go's ActiveStates) and calls
// these functions to open, close and reopen spans; this file only
// stores and reads them back. That split is deliberate: a second copy
// of #45's precedence living down here would drift from the one on the
// dashboard.
//
// Every timestamp is RFC3339Nano text (receivedAtLayout), compared as an
// instant and never as text -- range filters go through timeCompare, and
// every ordering and every max below is computed in Go on parsed
// time.Time values. SQL ORDER BY or MAX on these columns would
// reintroduce the trimmed-fractional-second bug token.go's
// RevokeCanaryTokensSupersededBy documents.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// StateUnobserved is the one state in canary_state_periods that is not a
// canary's own: it is the span in which birdcage was not running, so
// nothing could be observed about that canary at all. Deliberately
// recorded rather than left as a gap the dashboard would draw as healthy
// (issue #56). ListCanaries never derives it -- internal/history's
// Recorder.Start is its only writer -- which is why it sits here and not
// in health.go's healthStateRank.
const StateUnobserved HealthState = "unobserved"

// The closed set of end_reason values (migration 0010's comment). Why a
// span ended, not merely that it did: "cleared" is the state simply no
// longer being active, "quiet_period" is token_conflict's own clearing
// rule (#45: conflicts stopping is the only resolution birdcage can
// see, so the state ends after a quiet period rather than by being
// fixed), and "unobserved" means birdcage was down and the span was
// closed at the last tick it recorded rather than at a time it watched.
// Closed here in Go, like SettingKey and CommandKind, rather than by a
// per-engine CHECK constraint.
const (
	EndReasonCleared     = "cleared"
	EndReasonQuietPeriod = "quiet_period"
	EndReasonUnobserved  = "unobserved"
)

// endReasons is CloseStatePeriod's allow-list, so an unrecognized reason
// fails at the call rather than becoming a value no reader understands.
var endReasons = map[string]bool{
	EndReasonCleared:     true,
	EndReasonQuietPeriod: true,
	EndReasonUnobserved:  true,
}

// StatePeriod is one span a canary spent continuously in one state. It
// carries GET /api/history's own JSON shape directly, the way store.Trace
// does for GET /api/trace, so the handler has no parallel struct to keep
// in step.
//
// EndedAt nil is the whole definition of "still active"; EndReason is
// nil exactly when EndedAt is. CanaryName is filled only by
// ListStatePeriods (which joins the canaries table for it) and is empty
// for a period whose canary row has since been deleted -- the recorder's
// own reads never need it and leave it empty.
type StatePeriod struct {
	ID         int64      `json:"-"`
	CanaryID   string     `json:"canary_id"`
	CanaryName string     `json:"canary_name"`
	State      string     `json:"state"`
	StartedAt  time.Time  `json:"started_at"`
	EndedAt    *time.Time `json:"ended_at"`
	FlapCount  int64      `json:"flap_count"`
	EndReason  *string    `json:"end_reason"`
}

// StateSummary is one canary's totals for one state over a window: how
// many spans overlapped it, the longest, and the sum -- each clipped to
// the window (see SummarizeStatePeriods).
type StateSummary struct {
	CanaryID   string `json:"canary_id"`
	CanaryName string `json:"canary_name"`
	State      string `json:"state"`
	Count      int64  `json:"count"`
	LongestS   int64  `json:"longest_s"`
	TotalS     int64  `json:"total_s"`
}

// historyConn is what this file's recorder-facing functions take:
// db.Conn's Exec/QueryRow plus QueryContext, so one tick's reads and
// writes all run on the same *db.Tx. Both *db.DB and *db.Tx satisfy it
// (see db.Tx.QueryContext's doc comment for why that method had to be
// shadowed).
type historyConn interface {
	db.Conn
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// stateSortRank orders the states a period can hold: healthStateRank for
// the five ListCanaries derives, then StateUnobserved (and anything
// unknown) after them. Separate from healthStateRank rather than added
// to it, so issue #45's ratified precedence is not renumbered by a state
// that is not a canary's own condition at all.
func stateSortRank(state string) int {
	if rank, ok := healthStateRank[HealthState(state)]; ok {
		return rank
	}
	return len(healthStateRank)
}

// GET /api/history used to keep its own 24h/7d/30d range list, separate
// from the dashboard's 15m/1h/24h/14d/90d chips -- the mismatch made the
// range picker and the history section disagree about what window was
// showing. It now takes the same Range through ParseRange and
// DefaultRange (canary.go) as every other range-scoped handler, so
// there is exactly one place that set lives.

// OpenStatePeriods returns every span that is still open (ended_at IS
// NULL) -- the whole input to one reconcile pass. CanaryName is not
// filled (see StatePeriod's doc comment).
func OpenStatePeriods(ctx context.Context, database historyConn) ([]StatePeriod, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT id, agent_id, state, started_at, flap_count
		FROM agent_state_periods
		WHERE ended_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("query open state periods: %w", err)
	}
	defer func() { _ = rows.Close() }()

	periods := []StatePeriod{}
	for rows.Next() {
		var (
			p         StatePeriod
			startedAt string
		)
		if err := rows.Scan(&p.ID, &p.CanaryID, &p.State, &startedAt, &p.FlapCount); err != nil {
			return nil, fmt.Errorf("scan open state period: %w", err)
		}
		t, err := time.Parse(receivedAtLayout, startedAt)
		if err != nil {
			return nil, fmt.Errorf("parse state period started_at %q: %w", startedAt, err)
		}
		p.StartedAt = t
		periods = append(periods, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate open state periods: %w", err)
	}
	return periods, nil
}

// OpenStatePeriod inserts p. Normally that is an open span (p.EndedAt
// nil), but an already-closed one is equally valid and is how
// Recorder.Start writes the unobserved span it can only describe after
// the fact -- both ends of it are already in the past by the time
// birdcage is running again. p.ID is ignored: both engines generate it.
// p.FlapCount <= 0 stores 1, matching the column's own default.
func OpenStatePeriod(ctx context.Context, database db.Conn, p StatePeriod) error {
	if p.StartedAt.IsZero() {
		return fmt.Errorf("store: OpenStatePeriod: StartedAt is zero; callers must set it")
	}
	if p.EndReason != nil && !endReasons[*p.EndReason] {
		return fmt.Errorf("store: OpenStatePeriod: unknown end reason %q", *p.EndReason)
	}
	if (p.EndedAt == nil) != (p.EndReason == nil) {
		return fmt.Errorf("store: OpenStatePeriod: ended_at and end_reason must be set or unset together")
	}
	flapCount := p.FlapCount
	if flapCount <= 0 {
		flapCount = 1
	}
	var endedAt any
	if p.EndedAt != nil {
		endedAt = p.EndedAt.UTC().Format(receivedAtLayout)
	}
	var endReason any
	if p.EndReason != nil {
		endReason = *p.EndReason
	}
	_, err := database.ExecContext(ctx, `
		INSERT INTO agent_state_periods (agent_id, state, started_at, ended_at, flap_count, end_reason)
		VALUES (?, ?, ?, ?, ?, ?)`,
		p.CanaryID, p.State, p.StartedAt.UTC().Format(receivedAtLayout), endedAt, flapCount, endReason)
	if err != nil {
		return fmt.Errorf("insert state period: %w", err)
	}
	return nil
}

// CloseStatePeriod closes the open span id at endedAt, recording reason.
// The "AND ended_at IS NULL" guard makes it a no-op on a span already
// closed rather than silently moving an end time that was already
// written -- the recorder never wants to close the same span twice, and
// if it ever tries, the first (earlier, actually observed) end stands.
func CloseStatePeriod(ctx context.Context, database db.Conn, id int64, endedAt time.Time, reason string) error {
	if !endReasons[reason] {
		return fmt.Errorf("store: CloseStatePeriod: unknown end reason %q", reason)
	}
	if endedAt.IsZero() {
		return fmt.Errorf("store: CloseStatePeriod: endedAt is zero; callers must set it")
	}
	_, err := database.ExecContext(ctx, `
		UPDATE agent_state_periods
		SET ended_at = ?, end_reason = ?
		WHERE id = ? AND ended_at IS NULL`,
		endedAt.UTC().Format(receivedAtLayout), reason, id)
	if err != nil {
		return fmt.Errorf("close state period %d: %w", id, err)
	}
	return nil
}

// ReopenStatePeriod reopens the closed span id -- ended_at and end_reason
// back to NULL, flap_count incremented -- which is how a state re-entered
// inside internal/history's collapse window continues its existing span
// instead of inserting another row. started_at deliberately keeps its
// original value: the span is the same one, and flap_count is what
// records that it was re-entered.
func ReopenStatePeriod(ctx context.Context, database db.Conn, id int64) error {
	_, err := database.ExecContext(ctx, `
		UPDATE agent_state_periods
		SET ended_at = NULL, end_reason = NULL, flap_count = flap_count + 1
		WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("reopen state period %d: %w", id, err)
	}
	return nil
}

// LatestClosedStatePeriod returns the most recently closed span for
// canaryID in state whose ended_at is at or after notBefore, or nil if
// there is none. This is the flap-collapse lookup: internal/history
// passes now minus its collapse window as notBefore.
//
// notBefore narrows the scan in SQL through timeCompare (the same
// engine-portable mechanism latestAuditSince uses), but "most recent" is
// decided in Go on parsed timestamps -- an ORDER BY ended_at DESC LIMIT 1
// here would compare the raw RFC3339Nano text and could pick the wrong
// row (see this file's package comment).
func LatestClosedStatePeriod(ctx context.Context, database historyConn, engine db.Engine, canaryID, state string, notBefore time.Time) (*StatePeriod, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT id, started_at, ended_at, flap_count
		FROM agent_state_periods
		WHERE agent_id = ? AND state = ? AND ended_at IS NOT NULL AND `+timeCompare(engine, "ended_at", ">=")+`
		`, canaryID, state, notBefore.UTC().Format(receivedAtLayout))
	if err != nil {
		return nil, fmt.Errorf("query closed state periods for %s/%s: %w", canaryID, state, err)
	}
	defer func() { _ = rows.Close() }()

	var latest *StatePeriod
	for rows.Next() {
		var (
			p         StatePeriod
			startedAt string
			endedAt   string
		)
		if err := rows.Scan(&p.ID, &startedAt, &endedAt, &p.FlapCount); err != nil {
			return nil, fmt.Errorf("scan closed state period: %w", err)
		}
		started, err := time.Parse(receivedAtLayout, startedAt)
		if err != nil {
			return nil, fmt.Errorf("parse state period started_at %q: %w", startedAt, err)
		}
		ended, err := time.Parse(receivedAtLayout, endedAt)
		if err != nil {
			return nil, fmt.Errorf("parse state period ended_at %q: %w", endedAt, err)
		}
		p.CanaryID = canaryID
		p.State = state
		p.StartedAt = started
		p.EndedAt = &ended
		if latest == nil || ended.After(*latest.EndedAt) {
			winner := p
			latest = &winner
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate closed state periods for %s/%s: %w", canaryID, state, err)
	}
	return latest, nil
}

// ListStatePeriods returns every span overlapping [since, until],
// including spans still open and spans that started before since, for
// canaryID or -- when canaryID is empty -- every canary. Ordered by
// canary name, then start time, then id, so the dashboard's rows are
// stable across calls.
//
// The overlap test is "started at or before until, and either still open
// or ended at or after since". Both bounds go through timeCompare; the
// ordering is done in Go, on parsed timestamps.
//
// A canary name is whatever the operator (or, for an enrolled canary,
// whoever named it) typed: attacker-influenced text. It is carried
// through to the API as a plain JSON string, neither stripped nor
// rewritten here -- escaping is the frontend's job at the point of
// display (SECURITY.md, "Output escaping").
func ListStatePeriods(ctx context.Context, database *db.DB, since, until time.Time, canaryID string) ([]StatePeriod, error) {
	query := `
		SELECT p.id, p.agent_id, COALESCE(c.name, ''), p.state, p.started_at, p.ended_at, p.flap_count, p.end_reason
		FROM agent_state_periods p
		LEFT JOIN agents c ON c.id = p.agent_id
		WHERE ` + timeCompare(database.Engine, "p.started_at", "<=") +
		` AND (p.ended_at IS NULL OR ` + timeCompare(database.Engine, "p.ended_at", ">=") + `)`
	args := []any{
		until.UTC().Format(receivedAtLayout),
		since.UTC().Format(receivedAtLayout),
	}
	if canaryID != "" {
		query += ` AND p.agent_id = ?`
		args = append(args, canaryID)
	}

	rows, err := database.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query state periods: %w", err)
	}
	defer func() { _ = rows.Close() }()

	periods := []StatePeriod{}
	for rows.Next() {
		var (
			p         StatePeriod
			startedAt string
			endedAt   *string
		)
		if err := rows.Scan(&p.ID, &p.CanaryID, &p.CanaryName, &p.State, &startedAt, &endedAt, &p.FlapCount, &p.EndReason); err != nil {
			return nil, fmt.Errorf("scan state period: %w", err)
		}
		started, err := time.Parse(receivedAtLayout, startedAt)
		if err != nil {
			return nil, fmt.Errorf("parse state period started_at %q: %w", startedAt, err)
		}
		p.StartedAt = started
		if endedAt != nil {
			ended, err := time.Parse(receivedAtLayout, *endedAt)
			if err != nil {
				return nil, fmt.Errorf("parse state period ended_at %q: %w", *endedAt, err)
			}
			p.EndedAt = &ended
		}
		periods = append(periods, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate state periods: %w", err)
	}

	sort.SliceStable(periods, func(i, j int) bool {
		if periods[i].CanaryName != periods[j].CanaryName {
			return periods[i].CanaryName < periods[j].CanaryName
		}
		if !periods[i].StartedAt.Equal(periods[j].StartedAt) {
			return periods[i].StartedAt.Before(periods[j].StartedAt)
		}
		return periods[i].ID < periods[j].ID
	})
	return periods, nil
}

// SummarizeStatePeriods totals periods per canary per state over
// [since, until]: how many spans, the longest, and the sum of them all.
// Ordered by canary name, then by state rank (worst state first), so the
// summary reads in the same order as the dashboard's own tiles.
//
// Every span is clipped to the window before it is measured: one that
// started before since counts only from since, and one still open (or
// ending after until) counts only to until. Without that, a 30-day
// window would report a canary silent since the day it was enrolled as
// silent for longer than the window it was asked about. Count is per
// overlapping span, though -- a span clipped at both ends still
// happened once.
func SummarizeStatePeriods(periods []StatePeriod, since, until time.Time) []StateSummary {
	type key struct{ canaryID, state string }
	totals := map[key]*StateSummary{}
	order := []key{}

	for _, p := range periods {
		start := p.StartedAt
		if start.Before(since) {
			start = since
		}
		end := until
		if p.EndedAt != nil && p.EndedAt.Before(until) {
			end = *p.EndedAt
		}
		seconds := int64(0)
		if end.After(start) {
			seconds = int64(end.Sub(start).Seconds())
		}

		k := key{p.CanaryID, p.State}
		sum, ok := totals[k]
		if !ok {
			sum = &StateSummary{CanaryID: p.CanaryID, CanaryName: p.CanaryName, State: p.State}
			totals[k] = sum
			order = append(order, k)
		}
		sum.Count++
		sum.TotalS += seconds
		if seconds > sum.LongestS {
			sum.LongestS = seconds
		}
	}

	summaries := make([]StateSummary, 0, len(order))
	for _, k := range order {
		summaries = append(summaries, *totals[k])
	}
	sort.SliceStable(summaries, func(i, j int) bool {
		if summaries[i].CanaryName != summaries[j].CanaryName {
			return summaries[i].CanaryName < summaries[j].CanaryName
		}
		if summaries[i].CanaryID != summaries[j].CanaryID {
			return summaries[i].CanaryID < summaries[j].CanaryID
		}
		return stateSortRank(summaries[i].State) < stateSortRank(summaries[j].State)
	})
	return summaries
}
