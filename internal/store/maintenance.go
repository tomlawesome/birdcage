package store

import (
	"context"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/db"
)

// Audit actions for a canary's maintenance window (#227).
const (
	AuditMaintenanceSet     = "canary.maintenance.set"
	AuditMaintenanceCleared = "canary.maintenance.cleared"
)

// SetCanaryMaintenance puts canaryID in maintenance until until (scheduled
// downtime, #227): while now < until its health warnings -- silent and a
// failed self-test -- are quiet. Hits are untouched. The column is
// birdcage-side state, not an agent setting, so the settings hash does not
// move. The write and its audit row (canary.maintenance.set, target the
// canary id, triggeredBy the caller) share one transaction. An unknown
// canary is ErrCanaryNotFound and writes nothing.
func SetCanaryMaintenance(ctx context.Context, database *db.DB, canaryID string, until, now time.Time, triggeredBy string) error {
	untilStr := until.UTC().Format(receivedAtLayout)
	return writeMaintenance(ctx, database, canaryID, &untilStr, now, triggeredBy, AuditMaintenanceSet,
		"maintenance until "+until.UTC().Format(time.RFC3339))
}

// ClearCanaryMaintenance ends canaryID's maintenance now, so its warnings
// return on the next health check. Same transaction, audit and
// ErrCanaryNotFound rules as SetCanaryMaintenance
// (canary.maintenance.cleared).
func ClearCanaryMaintenance(ctx context.Context, database *db.DB, canaryID string, now time.Time, triggeredBy string) error {
	return writeMaintenance(ctx, database, canaryID, nil, now, triggeredBy, AuditMaintenanceCleared, "maintenance ended")
}

func writeMaintenance(ctx context.Context, database *db.DB, canaryID string, until *string, now time.Time, triggeredBy, action, reason string) error {
	tx, err := database.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin maintenance transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op once committed

	var arg any
	if until != nil {
		arg = *until
	}
	res, err := tx.ExecContext(ctx, `UPDATE agents SET maintenance_until = ? WHERE id = ?`, arg, canaryID)
	if err != nil {
		return fmt.Errorf("update maintenance_until: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return ErrCanaryNotFound
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Action: action, Target: canaryID, Reason: reason, TriggeredBy: triggeredBy, CreatedAt: now,
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit maintenance transaction: %w", err)
	}
	return nil
}

// applyMaintenance fills c.MaintenanceUntil while now < the stored end
// time and, then, removes the health warnings maintenance quiets: silent
// (so also its missed-heartbeat detail) and self-test failed. Every other
// state, and hits, are left exactly as computed. Runs last in
// ListCanaries so it sees the full state set.
func applyMaintenance(c *Canary, now time.Time) {
	if c.maintenanceUntil == nil || !now.Before(*c.maintenanceUntil) {
		return
	}
	until := *c.maintenanceUntil
	c.MaintenanceUntil = &until

	kept := make([]string, 0, len(c.ActiveStates))
	for _, s := range c.ActiveStates {
		if s == string(StateSilent) || s == string(StateTestFailed) {
			continue
		}
		kept = append(kept, s)
	}
	c.SilentForS, c.BeatsMissed = nil, nil
	c.ActiveStates = kept
	if len(kept) == 0 {
		c.ActiveStates = nil
		c.Status = string(StateOK)
		return
	}
	c.Status = kept[0]
}
