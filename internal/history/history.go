// Package history keeps issue #56's record of how long each canary spent
// in each of issue #45's health states. #45 derives those states fresh on
// every GET /api/canaries and keeps nothing, so the dashboard could say
// "throttled" but never "throttled for eleven minutes last night, twice".
//
// The Recorder does not derive anything itself. Every tick it asks
// store.ListCanaries for the states it has already computed
// (internal/store/health.go's ActiveStates), compares that set against
// the spans currently open in canary_state_periods, and writes only the
// difference: a state now active with no open span opens one, an open
// span whose state is no longer active is closed. One copy of #45's
// precedence, on the dashboard's side, is the point -- a second one here
// would drift.
//
// Three rules shape what gets written:
//
//   - Flap collapse. A state re-entered within collapseWindow of the
//     moment it cleared continues its existing span (flap_count goes up)
//     instead of inserting another row. This is the table's growth
//     bound, and it is a security property, not tidiness: several of
//     #45's states are driven by signals an attacker can pace -- cross
//     the rate limit every few seconds and the row count would be theirs
//     to choose.
//   - Never resolve toward healthy. Every error propagates to the
//     caller and the whole tick is rolled back. A tick that cannot read
//     the current states writes nothing at all, rather than closing
//     spans as though the states had cleared.
//   - Nothing is assumed about the time birdcage was not running. The
//     gap between the last recorded tick and start-up is written down as
//     an "unobserved" span per canary (see Start), and the spans that
//     were open when it stopped are closed at that last tick -- the last
//     moment birdcage actually observed anything -- not at start-up.
package history

import (
	"context"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

const (
	// collapseWindow is how soon a state must be re-entered after
	// clearing for the two spans to be recorded as one. Ten minutes is
	// the volume bound on this table against attacker-paced
	// transitions: without it, anyone able to make a signal start and
	// stop -- crossing the ingest rate limit, say -- would decide how
	// many rows birdcage writes per hour. With it, one canary in one
	// state can add at most six rows an hour however fast the
	// underlying signal flaps, and the flapping itself is still visible
	// as flap_count rather than being thrown away.
	//
	// The boundary is inclusive: a re-entry exactly collapseWindow after
	// the span closed still collapses into it.
	collapseWindow = 10 * time.Minute

	// unobservedAfter is how large the gap between the last recorded
	// tick and start-up has to be before Start writes an "unobserved"
	// span for it. Ticks are historyTickInterval (30s) apart, so a
	// normal restart leaves a gap of roughly that; 90s is three of them,
	// far enough above the interval that an ordinary restart or a slow
	// boot is not recorded as a blind spot, and short enough that a real
	// outage is.
	unobservedAfter = 90 * time.Second
)

// Recorder reconciles canary_state_periods against the states
// store.ListCanaries derives. One per process: cmd/birdcage constructs
// it after the database is open and migrated, calls Start once, then
// Tick on a ticker.
type Recorder struct {
	db *db.DB
}

// New returns a Recorder writing to database.
func New(database *db.DB) *Recorder {
	return &Recorder{db: database}
}

// Start is called once at boot, before the tick loop. It reads the last
// tick this database recorded and, if that was more than unobservedAfter
// ago, writes down the gap rather than letting it pass as healthy: every
// span still open is closed at the last tick (end_reason "unobserved" --
// birdcage stopped observing then, it did not see the state clear), and
// each canary gets one closed "unobserved" span covering last tick to
// now. It then runs a normal Tick, which re-opens whatever is genuinely
// active now.
//
// A last tick in the future (a clock moved backwards) records nothing:
// the gap is negative, so there is no span to describe.
func (r *Recorder) Start(ctx context.Context, now time.Time) error {
	now = now.UTC()

	raw, err := store.GetSetting(ctx, r.db, store.SettingHistoryLastTick)
	if err != nil {
		return fmt.Errorf("read %s: %w", store.SettingHistoryLastTick, err)
	}
	if raw != "" {
		lastTick, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return fmt.Errorf("parse %s %q: %w", store.SettingHistoryLastTick, raw, err)
		}
		lastTick = lastTick.UTC()
		if now.Sub(lastTick) > unobservedAfter {
			if err := r.recordUnobserved(ctx, lastTick, now); err != nil {
				return err
			}
		}
	}

	return r.Tick(ctx, now)
}

// Tick reconciles every canary's active states against the spans open in
// canary_state_periods, and records that it ran. All of the writing
// happens in one transaction: a tick either lands whole or not at all,
// so a failure halfway through can never leave a state closed without
// its successor opened.
func (r *Recorder) Tick(ctx context.Context, now time.Time) error {
	now = now.UTC()

	// Derived before the transaction opens, deliberately. On SQLite
	// every access shares one connection (db.Open's SetMaxOpenConns(1)),
	// so a *db.DB query issued while this function held a transaction on
	// that same connection would wait for a transaction that is waiting
	// for it.
	canaries, err := r.activeStates(ctx, now)
	if err != nil {
		return err
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin history tick: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op once Commit has run

	if err := r.reconcile(ctx, tx, canaries, now); err != nil {
		return err
	}
	// Written inside the same transaction as the reconcile it describes:
	// a last tick recorded for work that was then rolled back would
	// shrink the next start-up's unobserved span to cover less than the
	// time actually unobserved.
	if err := store.SetSetting(ctx, tx, store.SettingHistoryLastTick, now.Format(time.RFC3339Nano), now); err != nil {
		return fmt.Errorf("record %s: %w", store.SettingHistoryLastTick, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit history tick: %w", err)
	}
	return nil
}

// activeStates returns every canary with its ActiveStates filled in.
// The range window is zero because a hit count is irrelevant here: this
// call wants the health states ListCanaries derives, and a zero window
// leaves its alert count looking at the empty [now, now] range instead
// of scanning a real one.
func (r *Recorder) activeStates(ctx context.Context, now time.Time) ([]store.Canary, error) {
	canaries, err := store.ListCanaries(ctx, r.db, now, 0)
	if err != nil {
		return nil, fmt.Errorf("derive canary states: %w", err)
	}
	return canaries, nil
}

// spanKey identifies one span: a canary and one state it can be in. At
// most one span per key is ever open.
type spanKey struct {
	canaryID string
	state    string
}

// reconcile is one tick's whole decision, on tx: open what is newly
// active (collapsing onto a recent span where the rule applies), close
// what no longer is.
func (r *Recorder) reconcile(ctx context.Context, tx *db.Tx, canaries []store.Canary, now time.Time) error {
	open, err := store.OpenStatePeriods(ctx, tx)
	if err != nil {
		return err
	}
	openByKey := make(map[spanKey]store.StatePeriod, len(open))
	for _, p := range open {
		openByKey[spanKey{p.CanaryID, p.State}] = p
	}

	active := map[spanKey]bool{}
	for _, c := range canaries {
		for _, state := range c.ActiveStates {
			active[spanKey{c.ID, state}] = true
		}
	}

	// Newly active states, in ListCanaries' own order (canary id, then
	// worst state first) so a tick's inserts are deterministic.
	for _, c := range canaries {
		for _, state := range c.ActiveStates {
			if _, alreadyOpen := openByKey[spanKey{c.ID, state}]; alreadyOpen {
				continue
			}
			if err := r.openOrCollapse(ctx, tx, c.ID, state, now); err != nil {
				return err
			}
		}
	}

	// States that have stopped. token_conflict is the one state #45 does
	// not clear by being resolved -- birdcage cannot tell a fixed cause
	// from a cloned box that went quiet, so the state simply ends after
	// a quiet period with no new conflicts, and the row says so rather
	// than claiming the conflict cleared.
	for _, p := range open {
		if active[spanKey{p.CanaryID, p.State}] {
			continue
		}
		reason := store.EndReasonCleared
		if p.State == string(store.StateTokenConflict) {
			reason = store.EndReasonQuietPeriod
		}
		if err := store.CloseStatePeriod(ctx, tx, p.ID, now, reason); err != nil {
			return err
		}
	}
	return nil
}

// openOrCollapse starts canaryID's span in state -- either by reopening
// the span that closed within collapseWindow of now (flap collapse; see
// the constant's doc comment for why the bound exists) or, if there is
// none, by inserting a new one starting at now.
func (r *Recorder) openOrCollapse(ctx context.Context, tx *db.Tx, canaryID, state string, now time.Time) error {
	recent, err := store.LatestClosedStatePeriod(ctx, tx, r.db.Engine, canaryID, state, now.Add(-collapseWindow))
	if err != nil {
		return err
	}
	if recent != nil {
		return store.ReopenStatePeriod(ctx, tx, recent.ID)
	}
	return store.OpenStatePeriod(ctx, tx, store.StatePeriod{
		CanaryID:  canaryID,
		State:     state,
		StartedAt: now,
	})
}

// recordUnobserved writes down the stretch between lastTick and now, in
// which birdcage was not running: every span left open is closed at
// lastTick with end_reason "unobserved", and every canary gets one
// closed "unobserved" span covering the gap. Both in one transaction,
// for the same reason a tick is one.
//
// The spans are closed at lastTick rather than at now because that is
// the last moment anything was actually observed -- closing them at
// start-up would claim birdcage watched a state hold through an outage
// it slept through.
func (r *Recorder) recordUnobserved(ctx context.Context, lastTick, now time.Time) error {
	// Outside the transaction, for the SQLite single-connection reason
	// Tick's own comment gives. Only the ids are used here.
	canaries, err := r.activeStates(ctx, now)
	if err != nil {
		return err
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin unobserved span: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	open, err := store.OpenStatePeriods(ctx, tx)
	if err != nil {
		return err
	}
	for _, p := range open {
		if err := store.CloseStatePeriod(ctx, tx, p.ID, lastTick, store.EndReasonUnobserved); err != nil {
			return err
		}
	}

	endedAt := now
	reason := store.EndReasonUnobserved
	for _, c := range canaries {
		if err := store.OpenStatePeriod(ctx, tx, store.StatePeriod{
			CanaryID:  c.ID,
			State:     string(store.StateUnobserved),
			StartedAt: lastTick,
			EndedAt:   &endedAt,
			EndReason: &reason,
		}); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit unobserved span: %w", err)
	}
	return nil
}
