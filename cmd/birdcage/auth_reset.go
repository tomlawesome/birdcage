package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tomlawesome/gauntlet/persist"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/auth"
	"github.com/tomlawesome/birdcage/internal/store"
)

const authResetUsage = "usage: birdcage auth reset"

// errAuthResetDeclined is the operator answering anything but `reset`:
// a non-zero exit after the plain line already printed under the prompt.
var errAuthResetDeclined = errors.New("auth reset not confirmed")

// runAuth dispatches `birdcage auth <reset>` (#164).
func runAuth(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) < 1 {
		return errors.New(authResetUsage)
	}
	switch args[0] {
	case "reset":
		return runAuthResetCommand(args[1:], stdin, stdout, stderr)
	default:
		return fmt.Errorf("unknown auth subcommand %q (want reset)", args[0])
	}
}

// runAuthResetCommand implements `birdcage auth reset` (#164, design call
// note 63632), the same shape as `ca reset`: the deliberate way past
// checkStartupAuthContinuity when the accounts are lost for good on a
// database that is in use. It refuses when an account exists or the
// database is new (nothing to reset); asks the operator to type `reset`;
// then, in one transaction, records the acknowledgement the guard looks
// for (a settings row) and one audit row. It deletes nothing: agents, findings and history
// are kept. It prints no setup code; the next server start logs one. The
// acknowledgement is spent once an account exists, so it is not a standing
// off switch.
func runAuthResetCommand(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) != 0 {
		return errors.New(authResetUsage)
	}
	keyFile := os.Getenv(envAuthKeyFile)
	if keyFile == "" {
		return fmt.Errorf("%s is not set: auth reset needs the sign-in key to read the accounts", envAuthKeyFile)
	}
	key, err := readSecretFile(envAuthKeyFile, keyFile, false)
	if err != nil {
		return err
	}
	if len(key) < persist.MinKeyBytes {
		return fmt.Errorf("%s=%q holds %d bytes; it must hold at least %d", envAuthKeyFile, keyFile, len(key), persist.MinKeyBytes)
	}

	database, err := openCanaryDB()
	if err != nil {
		return err
	}
	defer closeCanaryDB(database)

	ctx := context.Background()
	accounts, err := auth.AccountCount(ctx, database, key)
	if err != nil {
		return err
	}
	if accounts > 0 {
		return fmt.Errorf("nothing to reset: %d sign-in account(s) exist; auth reset is only for accounts lost with no backup", accounts)
	}
	history, err := store.ReadAccountHistory(ctx, database)
	if err != nil {
		return err
	}
	if !history.InUse() {
		return errors.New("nothing to reset: no account has existed on this database, so start-up issues a setup code by itself")
	}

	_, _ = fmt.Fprintf(stdout, "No sign-in account exists, but this database has had one before (%s).\n"+
		"If this follows a restore, stop: put the right database back (docs/configuration.md, Backup and restore).\n"+
		"Continuing lets the next start issue a setup code, and whoever uses it becomes a new admin. Agents, findings and history are kept.\n"+
		"Type reset to continue: ", describeAccountHistory(history))
	if !readConfirmation(stdin) {
		_, _ = fmt.Fprintln(stderr, "\nnot confirmed; nothing changed")
		return errAuthResetDeclined
	}

	now := time.Now().UTC()
	tx, err := database.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	committed := false
	defer rollbackCanaryTx(tx, &committed)

	if err := store.RecordAccountsReset(ctx, tx, now); err != nil {
		return err
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Action:      "auth.reset",
		Target:      "accounts",
		Reason:      fmt.Sprintf("accounts lost after one had existed (%s); operator confirmed a new first admin", describeAccountHistory(history)),
		TriggeredBy: "cli",
		CreatedAt:   now,
	}); err != nil {
		return fmt.Errorf("record auth reset audit entry: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	committed = true

	_, _ = fmt.Fprintln(stdout, "reset recorded; the next start writes a setup code to its log for the new first admin")
	return nil
}
