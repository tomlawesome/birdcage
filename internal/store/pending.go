// Package store: this file is issue #47 step 9's registration flip --
// the one place a pending canary (#45 state 5, canaries.registered_at
// NULL) is ever moved to registered. recordSelfTestMatch
// (internal/store/selftest.go) calls settlePendingForCommand with a
// single added line the moment a run's last target matches; nothing else
// in this codebase writes registered_at once InsertCanary has left it
// NULL for a provisioned canary (store.Canary.Pending).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// SettlePending marks canaryID registered as of at -- the moment its
// first self-test round trip passed (issue #47 "Only then is the canary
// registered"). Idempotent and silent on a canary that is already
// registered or does not exist: the WHERE clause only ever touches a row
// currently NULL, so a duplicate call (the same run's last target
// matching twice, in principle impossible per selftest.go's own
// idempotency guard, but not relied on here) updates zero rows rather
// than clobbering the first, genuine registration timestamp with a later
// one.
func SettlePending(ctx context.Context, database db.Conn, canaryID string, at time.Time) error {
	if _, err := database.ExecContext(ctx, `
		UPDATE agents SET registered_at = ?
		WHERE id = ? AND registered_at IS NULL`,
		at.UTC().Format(receivedAtLayout), canaryID); err != nil {
		return fmt.Errorf("settle pending canary %s: %w", canaryID, err)
	}
	return nil
}

// settlePendingForCommand is recordSelfTestMatch's own entry point into
// this file: at the point a run finishes passing, that function already
// has commandID in scope, not canaryID, so this is the one extra lookup
// (self_test_runs.canary_id, written by MintSelfTestCommand for every
// run it mints) rather than growing recordSelfTestMatch's own query --
// see this build's report for why the call there is exactly one line.
// commandID naming no run is not an error here: recordSelfTestMatch only
// ever reaches this point after resolving commandID from
// self_test_targets, which MintSelfTestCommand always writes alongside
// the owning self_test_runs row in the same transaction, so this should
// never happen in practice; failing softly rather than surfacing a wiring
// bug as a self-test-match error is the same conservative stance
// MatchSelfTest's own doc comment already takes on this path.
func settlePendingForCommand(ctx context.Context, database db.Conn, commandID string, at time.Time) error {
	var canaryID string
	err := database.QueryRowContext(ctx, `SELECT agent_id FROM self_test_runs WHERE command_id = ?`, commandID).Scan(&canaryID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("look up canary for self-test command %s: %w", commandID, err)
	}
	return SettlePending(ctx, database, canaryID, at)
}
