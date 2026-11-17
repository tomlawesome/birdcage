package store

import (
	"context"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/poisoner"
	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/db"
)

// ClampLegacyPaceSettings raises every stored pace_floor/pace_ceiling
// below poisoner.MinCeilingGap (1s) to exactly that minimum, in one
// transaction, and returns how many rows it changed.
//
// Why: v0.1.0 accepted sub-1s pace values, which validatePaceDuration
// and the canary itself now both refuse (issue #213). Left alone, such a
// row would make every later `birdcage agent settings set` for that
// canary fail validation on re-write, and the canary would reject the
// push. Each change bumps version and updated_at exactly as
// upsertCanarySetting does, so the next heartbeat pushes the new value,
// and writes one audit entry naming the canary, key, old and new value
// (pace values are not secret, unlike bait_names).
//
// Values that do not parse as a Go duration, empty values, values of at
// least 1s and every other key are left untouched; a second run changes
// nothing. cmd/birdcage calls this at start-up, right after migrations.
func ClampLegacyPaceSettings(ctx context.Context, database *db.DB, now time.Time) (int, error) {
	if now.IsZero() {
		return 0, fmt.Errorf("store: ClampLegacyPaceSettings: now must be set by the caller")
	}
	minimum := poisoner.MinCeilingGap.String()

	tx, err := database.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin pace clamp transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	type legacyRow struct{ agent, key, value string }
	rows, err := tx.QueryContext(ctx, `
		SELECT agent_id, key, value FROM canary_settings
		WHERE key IN (?, ?) ORDER BY agent_id, key`,
		string(CanarySettingPaceFloor), string(CanarySettingPaceCeiling))
	if err != nil {
		return 0, fmt.Errorf("query pace settings: %w", err)
	}
	// Collected first and closed before any write: SQLite's single
	// connection cannot run an UPDATE while this result set is open.
	var legacy []legacyRow
	for rows.Next() {
		var r legacyRow
		if err := rows.Scan(&r.agent, &r.key, &r.value); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("scan pace setting: %w", err)
		}
		d, err := time.ParseDuration(r.value)
		if err != nil || d >= poisoner.MinCeilingGap {
			continue
		}
		legacy = append(legacy, r)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("iterate pace settings: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close pace settings: %w", err)
	}
	if len(legacy) == 0 {
		return 0, nil
	}

	updatedAt := now.UTC().Format(receivedAtLayout)
	for _, r := range legacy {
		if _, err := tx.ExecContext(ctx, `
			UPDATE canary_settings SET value = ?, version = version + 1, updated_at = ?
			WHERE agent_id = ? AND key = ? AND value = ?`,
			minimum, updatedAt, r.agent, r.key, r.value); err != nil {
			return 0, fmt.Errorf("clamp %s %s: %w", r.agent, r.key, err)
		}
		if _, err := audit.Append(ctx, tx, audit.Entry{
			Action:      "canary_settings.clamped",
			Target:      r.agent,
			Reason:      fmt.Sprintf("raised %s from %s to %s (v0.1.0 value below the minimum, #213)", r.key, r.value, minimum),
			TriggeredBy: "upgrade",
			CreatedAt:   now,
		}); err != nil {
			return 0, fmt.Errorf("record pace clamp audit entry: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit pace clamp transaction: %w", err)
	}
	committed = true
	return len(legacy), nil
}
