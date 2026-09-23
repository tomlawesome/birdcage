// selftest_runs.go is the read side of one canary's self-test history:
// every run in a window, not just the latest completed one
// (LatestCompletedSelfTestRun in selftest.go). Issue #118's canary page
// draws one hollow tick under the line per run and a filled tick with
// words for a run that failed, so it needs the runs themselves, not the
// summary the tile reads.
package store

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// SelfTestRunDetail is one run as the canary page reads it: the run row
// plus, for a failed run, the targets that never matched -- the same
// "service dest_port" strings SelfTestTargetsUnmatched returns and
// health.go's StateTestFailed already speaks. A passing or still-running
// run carries none.
type SelfTestRunDetail struct {
	SelfTestRun
	FailedServices []string
}

// ListSelfTestRuns returns canaryID's self-test runs issued within
// [since, until], newest first, each with its unmatched targets when it
// failed.
//
// Loaded whole and filtered in Go rather than bounded by an SQL range on
// the TEXT issued_at column, for the reason LatestCompletedSelfTestRun's
// doc comment gives: stored timestamps have their fractional seconds
// trimmed, so a text comparison is not the same comparison time.Time
// makes, and one canary's self-test history is small (at most a handful
// a day, kept for as long as the runs table is).
func ListSelfTestRuns(ctx context.Context, database *db.DB, canaryID string, since, until time.Time) ([]SelfTestRunDetail, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT command_id, canary_id, run_id, issued_at, deadline_at, completed_at, passed
		FROM self_test_runs WHERE canary_id = ?`, canaryID)
	if err != nil {
		return nil, fmt.Errorf("query self_test_runs for %s: %w", canaryID, err)
	}
	defer func() { _ = rows.Close() }()

	runs := []SelfTestRunDetail{}
	for rows.Next() {
		r, err := scanSelfTestRun(rows)
		if err != nil {
			return nil, err
		}
		if r.IssuedAt.Before(since) || r.IssuedAt.After(until) {
			continue
		}
		runs = append(runs, SelfTestRunDetail{SelfTestRun: r})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate self_test_runs for %s: %w", canaryID, err)
	}

	sort.Slice(runs, func(i, j int) bool { return runs[i].IssuedAt.After(runs[j].IssuedAt) })

	for i := range runs {
		if runs[i].Passed == nil || *runs[i].Passed {
			continue
		}
		unmatched, err := SelfTestTargetsUnmatched(ctx, database, runs[i].CommandID)
		if err != nil {
			return nil, fmt.Errorf("unmatched targets for run %s: %w", runs[i].CommandID, err)
		}
		runs[i].FailedServices = unmatched
	}
	return runs, nil
}
