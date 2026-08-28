// Package audit provides the write path for birdcage's append-only audit
// log.
//
// The audit trail is "required, not optional" per ADR-0001. The audit_log
// table is append-only at two levels: this package deliberately exposes no
// function that can update or delete an entry (Append is the only exported
// write), and migration 0002 adds BEFORE UPDATE / BEFORE DELETE triggers
// that abort any such statement at the database level, so the guarantee
// does not depend on application discipline alone.
package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Entry is a single audit log entry.
//
// Action, Target, and Reason are persisted verbatim: do not pass
// credentials or other secrets into them (SECURITY.md's "never logged"
// rule is a caller responsibility, not something this package scrubs).
type Entry struct {
	Action      string
	Target      string
	Reason      string
	TriggeredBy string
	CreatedAt   time.Time
}

// ErrZeroCreatedAt is returned when Append is called with a zero
// CreatedAt. Callers are responsible for setting it (e.g.
// time.Now().UTC()); Append does not default it.
var ErrZeroCreatedAt = errors.New("audit: CreatedAt is zero; callers must set it (e.g. time.Now().UTC())")

// Append validates e, inserts it into the audit_log table, and returns the
// new row's id.
//
// Action, Target, Reason, and TriggeredBy must each be non-empty after
// trimming whitespace, and CreatedAt must be non-zero; otherwise Append
// returns an error and inserts nothing (fail-closed: an incomplete audit
// row is never stored). CreatedAt is stored as RFC 3339 UTC text.
func Append(ctx context.Context, db *sql.DB, e Entry) (id int64, err error) {
	var blank []string
	if strings.TrimSpace(e.Action) == "" {
		blank = append(blank, "Action")
	}
	if strings.TrimSpace(e.Target) == "" {
		blank = append(blank, "Target")
	}
	if strings.TrimSpace(e.Reason) == "" {
		blank = append(blank, "Reason")
	}
	if strings.TrimSpace(e.TriggeredBy) == "" {
		blank = append(blank, "TriggeredBy")
	}
	if len(blank) > 0 {
		return 0, fmt.Errorf("audit: refusing to append entry with blank field(s): %s", strings.Join(blank, ", "))
	}
	if e.CreatedAt.IsZero() {
		return 0, ErrZeroCreatedAt
	}

	result, err := db.ExecContext(ctx,
		`INSERT INTO audit_log (action, target, reason, triggered_by, created_at)
         VALUES (?, ?, ?, ?, ?)`,
		e.Action, e.Target, e.Reason, e.TriggeredBy, e.CreatedAt.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("audit: insert: %w", err)
	}
	id, err = result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("audit: last insert id: %w", err)
	}
	return id, nil
}
