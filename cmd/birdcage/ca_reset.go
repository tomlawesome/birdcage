package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/ca"
	"github.com/tomlawesome/birdcage/internal/store"
)

const caResetUsage = "usage: birdcage ca reset [--backup-taken]"

// errCAResetDeclined is the operator answering anything but `reset`: not
// a failure to log, just a non-zero exit after the plain line already
// printed under the prompt.
var errCAResetDeclined = errors.New("ca reset not confirmed")

// runCA dispatches `birdcage ca <reset>` (#213).
func runCA(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) < 1 {
		return errors.New(caResetUsage)
	}
	switch args[0] {
	case "reset":
		return runCAResetCommand(args[1:], stdin, stdout, stderr)
	default:
		return fmt.Errorf("unknown ca subcommand %q (want reset)", args[0])
	}
}

// runCAResetCommand implements `birdcage ca reset [--backup-taken]` (#213, owner
// decision 38b): the deliberate way back when BIRDCAGE_CA_DIR is lost and
// no backup of it exists, which checkStartupCAContinuity otherwise
// refuses forever. It refuses unless the CA is missing and a client
// certificate was issued; backs the database up first (SQLite: VACUUM
// INTO a timestamped copy beside it; Postgres: only with --backup-taken,
// checked before connecting); asks the operator to type `reset`; then
// removes every client certificate and writes one audit row in a single
// transaction. Agents, findings and event history are kept; every agent
// that held a certificate must enrol again under the new CA start-up
// mints.
func runCAResetCommand(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("ca reset", flag.ContinueOnError)
	fs.SetOutput(stderr)
	backupTaken := fs.Bool("backup-taken", false, "Postgres only: you have taken your own database backup (birdcage cannot copy a Postgres database)")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, caResetUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New(caResetUsage)
	}

	caDir := os.Getenv(envCADir)
	if caDir == "" {
		caDir = defaultCADir
	}
	missing, err := ca.CAMissing(caDir)
	if err != nil {
		return fmt.Errorf("check CA directory (%s=%q): %w", envCADir, caDir, err)
	}
	if missing == "" {
		return fmt.Errorf("the CA at %s is present; ca reset is only for a CA that is lost with no backup", caDir)
	}

	databaseURL := canaryDatabaseURL()
	postgres := strings.HasPrefix(databaseURL, "postgres://") || strings.HasPrefix(databaseURL, "postgresql://")
	if postgres && !*backupTaken {
		return errors.New("birdcage cannot back up a Postgres database itself: take a backup (see docs/configuration.md), then run again with --backup-taken")
	}

	database, err := openCanaryDB()
	if err != nil {
		return err
	}
	defer closeCanaryDB(database)

	ctx := context.Background()
	issued, err := store.AnyClientCertsIssued(ctx, database)
	if err != nil {
		return err
	}
	if !issued {
		return errors.New("nothing to reset: no client certificate was ever issued, so start-up creates a new CA by itself")
	}
	agents, err := store.CountAgentsWithLiveClientCerts(ctx, database)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(stdout, "The CA is lost. This removes every client certificate it signed; %d enrolled agent(s) will need to enrol again.\nAgents, findings and event history are kept.\nType reset to continue: ", agents)
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	if strings.TrimRight(line, "\r\n") != "reset" {
		_, _ = fmt.Fprintln(stderr, "\nnot confirmed; nothing changed")
		return errCAResetDeclined
	}

	now := time.Now().UTC()
	reason := "CA lost with no backup; operator confirmed their own database backup (--backup-taken)"
	if !postgres {
		path := strings.TrimPrefix(databaseURL, "sqlite:")
		backup := filepath.Join(filepath.Dir(path), filepath.Base(path)+".ca-reset-"+now.Format("20060102T150405Z"))
		// VACUUM INTO is SQLite's own consistent copy; it refuses to
		// overwrite an existing file.
		if _, err := database.ExecContext(ctx, `VACUUM INTO ?`, backup); err != nil {
			return fmt.Errorf("back up the database to %s (nothing changed): %w", backup, err)
		}
		_, _ = fmt.Fprintf(stdout, "database backed up to %s\n", backup)
		reason = "CA lost with no backup; database backup at " + backup
	}

	tx, err := database.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	committed := false
	defer rollbackCanaryTx(tx, &committed)

	removed, err := store.DeleteAllClientCerts(ctx, tx)
	if err != nil {
		return err
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Action:      "ca.reset",
		Target:      caDir,
		Reason:      fmt.Sprintf("%s; %d client certificate(s) removed", reason, removed),
		TriggeredBy: "cli",
		CreatedAt:   now,
	}); err != nil {
		return fmt.Errorf("record ca reset audit entry: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	committed = true

	_, _ = fmt.Fprintf(stdout, "removed %d client certificate(s); the next start creates a new CA, then enrol each agent again\n", removed)
	return nil
}
