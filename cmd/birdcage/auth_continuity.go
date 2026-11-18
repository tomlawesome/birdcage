package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/tomlawesome/birdcage/internal/auth"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// checkStartupAuthContinuity refuses to start when the sign-in accounts
// are empty but the database is not new (issue #164, design call note
// 63632): agents, findings or audit rows with no account is what a
// restore that missed auth_documents, the wrong database file or a wrong
// path looks like, and starting would hand a setup code, so the first
// admin, to anyone who can read the log. It runs beside
// checkStartupCAContinuity, before ReleaseCodes, so a refused start
// prints no code. `birdcage auth reset` is the operator's deliberate way
// past it; its acknowledgement is spent here once an account exists.
func checkStartupAuthContinuity(ctx context.Context, cfg startupConfig, database *db.DB, authLog *slog.Logger) error {
	accounts, err := auth.AccountCount(ctx, database, cfg.auth.Key)
	if err != nil {
		return &startupError{authLog, err.Error()}
	}
	if accounts > 0 {
		if err := auth.SpendAccountsReset(ctx, database); err != nil {
			return &startupError{authLog, err.Error()}
		}
		return nil
	}
	history, err := store.ReadDatabaseHistory(ctx, database)
	if err != nil {
		return &startupError{authLog, fmt.Sprintf("restore check: %v", err)}
	}
	if !history.InUse() {
		return nil // a new install: the setup code follows
	}
	acked, err := auth.AccountsResetAcknowledged(ctx, database)
	if err != nil {
		return &startupError{authLog, err.Error()}
	}
	if acked {
		authLog.Warn("no account exists on a database already in use; `birdcage auth reset` was confirmed, so a setup code follows")
		return nil
	}
	return &startupError{authLog, fmt.Sprintf(
		"refusing to start: no sign-in account exists, but this database is not new "+
			"(%d agent(s), %d finding(s), %d audit row(s)). That is what a restore that missed the auth_documents table, "+
			"the wrong database file or a wrong %s/%s looks like, so no setup code is issued. "+
			"Put the right database back (docs/configuration.md, Backup and restore) and do not create a new admin. "+
			"If the accounts were lost for good and you mean to create a new admin over this data, run `birdcage auth reset`, then start again",
		history.Agents, history.Findings, history.AuditRows, envDBPath, envDatabaseURL)}
}
