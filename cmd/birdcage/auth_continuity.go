package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/auth"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// checkStartupAuthContinuity refuses to start when no sign-in account
// exists but one has before (issue #164, design calls in notes 63632 and
// 63923): the one-way accounts_initialised marker in settings, or a
// user.register audit row, with zero accounts is what a restore that
// missed auth_documents, the wrong database file or a wrong path looks
// like, and starting would hand a setup code, so the first admin, to
// anyone who can read the log. Agents, findings and other audit rows do
// not count: a fresh install makes those before its first admin. It runs
// beside checkStartupCAContinuity, before ReleaseCodes, so a refused start
// prints no code. `birdcage auth reset` is the operator's deliberate way
// past it; its acknowledgement is spent here once an account exists.
//
// This guards against operator error, not against someone who can write
// the database: they can add or delete the markers at will.
func checkStartupAuthContinuity(ctx context.Context, cfg startupConfig, database *db.DB, authLog *slog.Logger) error {
	accounts, err := auth.AccountCount(ctx, database, cfg.auth.Key)
	if err != nil {
		return &startupError{authLog, err.Error()}
	}
	if accounts > 0 {
		// Also writes the marker for an account gauntlet saved without
		// its user.register row reaching the database, and for installs
		// whose accounts predate the marker.
		if err := store.MarkAccountsInitialised(ctx, database, time.Now().UTC()); err != nil {
			return &startupError{authLog, err.Error()}
		}
		if err := store.SpendAccountsReset(ctx, database); err != nil {
			return &startupError{authLog, err.Error()}
		}
		return nil
	}
	history, err := store.ReadAccountHistory(ctx, database)
	if err != nil {
		return &startupError{authLog, fmt.Sprintf("restore check: %v", err)}
	}
	if !history.InUse() {
		return nil // a new install: the setup code follows
	}
	acked, err := store.AccountsResetAcknowledged(ctx, database)
	if err != nil {
		return &startupError{authLog, err.Error()}
	}
	if acked {
		authLog.Warn("no account exists, but one has before; `birdcage auth reset` was confirmed, so a setup code follows")
		return nil
	}
	return &startupError{authLog, fmt.Sprintf(
		"refusing to start: no sign-in account exists, but this database has had one before (%s). "+
			"That is what a restore that missed the auth_documents table, "+
			"the wrong database file or a wrong %s/%s looks like, so no setup code is issued. "+
			"Put the right database back (docs/configuration.md, Backup and restore) and do not create a new admin. "+
			"If the accounts were lost for good and you mean to create a new admin over this data, run `birdcage auth reset`, then start again",
		describeAccountHistory(history), envDBPath, envDatabaseURL)}
}

// describeAccountHistory names the signals present, for the refusal and
// the `auth reset` prompt.
func describeAccountHistory(h store.AccountHistory) string {
	var parts []string
	if h.Initialised {
		parts = append(parts, "the accounts_initialised marker is set")
	}
	if h.Registrations > 0 {
		parts = append(parts, fmt.Sprintf("%d user.register audit row(s)", h.Registrations))
	}
	return strings.Join(parts, ", ")
}
