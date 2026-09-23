// Package store: this file resolves #46 slice 2's "attributed" grade
// (ntp, portscan, llmnr) -- the two services that log nothing
// attacker-supplied at all, so a target for them can only be claimed by
// correlating an arriving event's address and timing against the run
// birdcage itself issued, never by content (notes 19855, 19897, 20740).
//
// # Why this runs at the deadline sweep, and updates alerts.synthetic
//
// 0016_alerts_synthetic.sql's own comment states the rule every other
// grade follows: synthetic is "written once, at insert... never updated
// afterward". Attribution is the one deliberate exception, for a reason
// that grade alone forces: the exactly-one rule (note 19855) can only be
// judged once the run's whole window has closed, because a second
// candidate event can arrive at any point up to the deadline and would
// have to flip an already-claimed alert back to real. Deciding at
// arrival time, the way every marked or challenge-marked grade decides,
// would mean either guessing before the window closes (risking exactly
// the "hidden intrusion" failure the whole design exists to prevent) or
// never attributing anything at all.
//
// So this package waits: an attributed-service alert is stored real, the
// same as any other event this build cannot yet explain, right up until
// resolveAttributedTargets runs -- SweepExpiredSelfTestRuns' own call,
// made only once the run's deadline has provably passed. From there the
// move is one-directional and made exactly once per target, guarded by
// self_test_targets.matched_at IS NULL: a row this package has already
// resolved is never revisited, and nothing here ever sets synthetic back
// to false. That keeps the one property the original comment protects --
// an alert already shown as real is never hidden -- while adding the one
// case that comment did not anticipate: an alert not yet shown as
// anything, because the window it would be judged in has not closed yet.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// resolveAttributedTargets evaluates every still-unmatched
// GradeAttributed target of commandID (issued to canaryID between
// issuedAt and deadlineAt) and claims the ones whose service has exactly
// one candidate event in that window, from the canary's own reported
// address, that is not already claimed by something else. Zero or two-or-
// more candidates leaves the target unmatched and every candidate real --
// note 19855's exactly-one rule, chosen precisely because it fails
// toward real rather than toward hidden.
//
// A canary with no LastSeenAddr on record has nothing to attribute
// against (there is no "the canary's own address" to require), so every
// attributed target for it is left unmatched -- fail closed, the same
// answer store.MatchSelfTest gives an unknown canary.
func resolveAttributedTargets(ctx context.Context, database *db.DB, commandID, canaryID string, issuedAt, deadlineAt, now time.Time) error {
	sc, ok, err := SelfTestCanaryByID(ctx, database, canaryID)
	if err != nil {
		return fmt.Errorf("look up canary %s for attribution: %w", canaryID, err)
	}
	if !ok || sc.LastSeenAddr == nil || *sc.LastSeenAddr == "" {
		return nil
	}

	targets, err := unmatchedAttributedTargets(ctx, database, commandID)
	if err != nil {
		return err
	}

	for _, tgt := range targets {
		candidates, err := attributionCandidates(ctx, database, canaryID, tgt.service, *sc.LastSeenAddr, issuedAt, deadlineAt)
		if err != nil {
			return fmt.Errorf("find attribution candidates for %s: %w", tgt.service, err)
		}
		if len(candidates) != 1 {
			// Zero: nothing arrived to claim. Two or more: none of them
			// is distinguishable from the others, so none is claimed --
			// an intruder's real hit sharing the window with this run's
			// own probe must never be the one left hidden.
			continue
		}
		if err := markAlertSynthetic(ctx, database, candidates[0]); err != nil {
			return fmt.Errorf("mark attributed alert synthetic (%s): %w", tgt.service, err)
		}
		// recordSelfTestMatch (selftest.go, not edited by this slice --
		// another change to this file was already in flight when this
		// slice started) is the same call store.MatchSelfTest makes for
		// every other grade: it sets matched_at and, if every target of
		// commandID is now matched, marks the run passed.
		if err := recordSelfTestMatch(ctx, database, tgt.markerHash, now.UTC()); err != nil {
			return fmt.Errorf("record attribution match for %s: %w", tgt.service, err)
		}
	}
	return nil
}

// attributedTarget is one row unmatchedAttributedTargets reads back --
// enough for resolveAttributedTargets to find candidates and, on a
// match, call recordSelfTestMatch without a second query.
type attributedTarget struct {
	service    string
	markerHash string
}

// unmatchedAttributedTargets returns commandID's GradeAttributed targets
// that have not yet matched.
func unmatchedAttributedTargets(ctx context.Context, database *db.DB, commandID string) ([]attributedTarget, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT service, marker_hash FROM self_test_targets
		WHERE command_id = ? AND grade = ? AND matched_at IS NULL`,
		commandID, string(GradeAttributed))
	if err != nil {
		return nil, fmt.Errorf("query attributed self_test_targets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []attributedTarget
	for rows.Next() {
		var t attributedTarget
		if err := rows.Scan(&t.service, &t.markerHash); err != nil {
			return nil, fmt.Errorf("scan attributed self_test_target: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate attributed self_test_targets: %w", err)
	}
	return out, nil
}

// attributionCandidates returns the alerts.id of every real (not already
// synthetic), not-yet-claimed alert of service, from sourceIP, received
// inside [since, until] -- the exactly-one rule's candidate set. Bounded
// the same way MatchSelfTest's own candidate set is bounded: one run's
// window, one canary, one service, never the whole alerts table.
func attributionCandidates(ctx context.Context, database *db.DB, canaryID, service, sourceIP string, since, until time.Time) ([]int64, error) {
	query := fmt.Sprintf(`
		SELECT id FROM alerts
		WHERE instance_id = ? AND service = ? AND source_ip = ? AND synthetic = 0
		AND %s AND %s`,
		receivedAtCompare(database.Engine, ">="), receivedAtCompare(database.Engine, "<="))
	rows, err := database.QueryContext(ctx, query,
		canaryID, service, sourceIP,
		since.UTC().Format(receivedAtLayout), until.UTC().Format(receivedAtLayout))
	if err != nil {
		return nil, fmt.Errorf("query attribution candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan attribution candidate: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate attribution candidates: %w", err)
	}
	return ids, nil
}

// markAlertSynthetic flips one alert row from real to synthetic -- see
// this file's own doc comment for why this is the one place in the
// schema that updates alerts.synthetic after insert. The "AND synthetic
// = 0" guard makes a duplicate call a no-op rather than a second write:
// this package never has a reason to call it twice for the same row, but
// idempotence costs nothing and matches recordSelfTestMatch's own
// "AND matched_at IS NULL" guard one column over.
func markAlertSynthetic(ctx context.Context, database *db.DB, alertID int64) error {
	if _, err := database.ExecContext(ctx, `
		UPDATE alerts SET synthetic = 1 WHERE id = ? AND synthetic = 0`, alertID); err != nil {
		return fmt.Errorf("update alert %d synthetic: %w", alertID, err)
	}
	return nil
}
