package auth

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/persist"

	"github.com/tomlawesome/birdcage/internal/authstore"
	"github.com/tomlawesome/birdcage/internal/db"
)

// The restore guard (issue #164, notes 63632 and 63923) asks how many
// accounts exist; the markers it weighs that against live in
// internal/store (accountmarkers.go).

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
