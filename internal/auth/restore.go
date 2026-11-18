package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/persist"

	"github.com/tomlawesome/birdcage/internal/authstore"
	"github.com/tomlawesome/birdcage/internal/db"
)

// The restore guard (issue #164, design call note 63632): an empty
// accounts store on a database that is not new is a botched restore until
// the operator says otherwise with `birdcage auth reset`. That command
// leaves an acknowledgement here, in auth_documents beside the accounts
// it vouches for, so a restore that misses the table loses both. The
// acknowledgement is spent once an account exists, so it never becomes a
// standing off switch.

// docResetAck names the acknowledgement's auth_documents row. It holds no
// secret: only when the reset was confirmed.
const docResetAck = "accounts-reset"

// AccountCount opens the sealed accounts store read-only with key and
// says how many accounts it holds. No code is announced and nothing is
// written.
func AccountCount(ctx context.Context, database *db.DB, key []byte) (int, error) {
	if len(key) < persist.MinKeyBytes {
		return 0, fmt.Errorf("auth: the sign-in key is %d bytes; it must be at least %d (BIRDCAGE_AUTH_KEY_FILE)", len(key), persist.MinKeyBytes)
	}
	backend, err := persist.Encrypt(authstore.NewBackend(database, storeAccounts), key, persist.EncryptOptions{Label: storeAccounts})
	if err != nil {
		return 0, fmt.Errorf("auth: seal accounts: %w", err)
	}
	users, err := gauntlet.OpenStore(backend, gauntlet.Options{
		Log:          slog.New(slog.DiscardHandler),
		ProductName:  productName,
		OnSetupCode:  gauntlet.SetupCodeFunc(func(string) {}),
		OnUnlockCode: gauntlet.UnlockCodeFunc(func(string, string) {}),
	})
	if err != nil {
		return 0, fmt.Errorf("auth: open accounts: %w", err)
	}
	return users.Count(), nil
}

// RecordAccountsReset writes the reset acknowledgement on conn, normally
// the transaction that also writes the reset's audit row.
func RecordAccountsReset(ctx context.Context, conn db.Conn, at time.Time) error {
	if _, err := conn.ExecContext(ctx, `DELETE FROM auth_documents WHERE name = ?`, docResetAck); err != nil {
		return fmt.Errorf("auth: record accounts reset: %w", err)
	}
	payload := []byte(fmt.Sprintf(`{"resetAt":%q}`, at.UTC().Format(time.RFC3339Nano)))
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO auth_documents (name, payload, version, updated_at) VALUES (?, ?, ?, ?)`,
		docResetAck, payload, 1, at.UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("auth: record accounts reset: %w", err)
	}
	return nil
}

// AccountsResetAcknowledged reports whether an unspent reset
// acknowledgement is stored.
func AccountsResetAcknowledged(ctx context.Context, conn db.Conn) (bool, error) {
	var one int
	err := conn.QueryRowContext(ctx, `SELECT 1 FROM auth_documents WHERE name = ?`, docResetAck).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("auth: read accounts reset: %w", err)
	}
	return true, nil
}

// SpendAccountsReset removes the acknowledgement, if any: an account
// exists, so the guard arms again.
func SpendAccountsReset(ctx context.Context, conn db.Conn) error {
	if _, err := conn.ExecContext(ctx, `DELETE FROM auth_documents WHERE name = ?`, docResetAck); err != nil {
		return fmt.Errorf("auth: spend accounts reset: %w", err)
	}
	return nil
}
