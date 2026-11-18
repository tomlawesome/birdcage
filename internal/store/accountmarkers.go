package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// The restore guard's markers (issue #164, note 63923). They are rows in
// the settings table but not operator settings: they are outside
// settingDefs, so `birdcage settings` neither lists nor sets them. They
// live in settings, not auth_documents, because a bad restore that loses
// auth_documents must not lose them too.
//
// The guard protects against operator error (the wrong database file, a
// wrong path, a restore that missed a table), not against someone who can
// write the database: such a person can add or remove these rows at will.
const (
	// markerAccountsInitialised is one-way: written when the first account
	// registers (and whenever start-up sees an account), cleared by nothing.
	markerAccountsInitialised = "accounts_initialised"
	// markerAccountsReset is `birdcage auth reset`'s acknowledgement,
	// spent once an account exists.
	markerAccountsReset = "accounts_reset_acknowledged"
)

// AccountHistory is what says "an account has existed": the initialised
// marker, or a user.register audit row (gauntlet records user.register
// outside its own account transaction, so the marker is best effort and
// the audit row covers the gap). Agents, findings, failed sign-ins and any
// other rows do not count: a fresh install makes those before its first
// admin.
type AccountHistory struct {
	Initialised   bool
	Registrations int
}

// InUse reports whether either signal is present.
func (h AccountHistory) InUse() bool { return h.Initialised || h.Registrations > 0 }

// ReadAccountHistory reads both signals.
func ReadAccountHistory(ctx context.Context, conn db.Conn) (AccountHistory, error) {
	var h AccountHistory
	var err error
	if h.Initialised, err = markerSet(ctx, conn, markerAccountsInitialised); err != nil {
		return AccountHistory{}, err
	}
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE action = 'user.register'`).Scan(&h.Registrations); err != nil {
		return AccountHistory{}, fmt.Errorf("count user.register audit rows: %w", err)
	}
	return h, nil
}

// MarkAccountsInitialised writes the one-way marker; writing it again
// keeps the first time.
func MarkAccountsInitialised(ctx context.Context, conn db.Conn, at time.Time) error {
	return setMarker(ctx, conn, markerAccountsInitialised, at)
}

// RecordAccountsReset writes `auth reset`'s acknowledgement on conn,
// normally the transaction that also writes the reset's audit row.
func RecordAccountsReset(ctx context.Context, conn db.Conn, at time.Time) error {
	return setMarker(ctx, conn, markerAccountsReset, at)
}

// AccountsResetAcknowledged reports whether an unspent acknowledgement is
// stored.
func AccountsResetAcknowledged(ctx context.Context, conn db.Conn) (bool, error) {
	return markerSet(ctx, conn, markerAccountsReset)
}

// SpendAccountsReset removes the acknowledgement, if any: an account
// exists, so the guard arms again.
func SpendAccountsReset(ctx context.Context, conn db.Conn) error {
	if _, err := conn.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, markerAccountsReset); err != nil {
		return fmt.Errorf("spend accounts reset: %w", err)
	}
	return nil
}

func setMarker(ctx context.Context, conn db.Conn, key string, at time.Time) error {
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO NOTHING`,
		key, "true", at.UTC().Format(receivedAtLayout)); err != nil {
		return fmt.Errorf("write %s: %w", key, err)
	}
	return nil
}

func markerSet(ctx context.Context, conn db.Conn, key string) (bool, error) {
	var one int
	err := conn.QueryRowContext(ctx, `SELECT 1 FROM settings WHERE key = ?`, key).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read %s: %w", key, err)
	}
	return true, nil
}
