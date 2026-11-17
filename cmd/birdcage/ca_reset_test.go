package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/ca"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// `birdcage ca reset [--backup-taken]` (#213, owner decision 38b) is driven
// through runSubcommand, the entry point every other CLI test uses. The
// command reads its confirmation line from os.Stdin, so these tests swap
// os.Stdin; like captureStdout, that is process-global and no test here
// runs in parallel.

type caResetEnv struct {
	dbPath string
	caDir  string // never created by the helper; tests create a CA or leave it missing
}

func newCAResetEnv(t *testing.T) caResetEnv {
	t.Helper()
	e := caResetEnv{dbPath: testDBPath(t), caDir: filepath.Join(t.TempDir(), "ca")}
	t.Setenv(envDBPath, e.dbPath)
	t.Setenv(envDatabaseURL, "")
	t.Setenv(envCADir, e.caDir)
	return e
}

// seed opens the database, runs fn, and closes it again before the command
// under test opens it.
func (e caResetEnv) seed(t *testing.T, fn func(*db.DB)) {
	t.Helper()
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)
	fn(database)
}

// enrolTwoAgents leaves two agents with issued certificates, one agent
// with none, and one alert and one finding that must survive a reset.
func (e caResetEnv) enrolTwoAgents(t *testing.T) {
	t.Helper()
	e.seed(t, func(d *db.DB) {
		insertTestCanary(t, d, "agent-one")
		insertTestClientCert(t, d, "agent-one")
		insertTestCanary(t, d, "agent-two")
		insertTestClientCert(t, d, "agent-two")
		insertTestCanary(t, d, "agent-nocert")
		if _, err := store.InsertAlertIfNew(context.Background(), d, store.AlertInsert{
			InstanceID: "agent-one", SourceIP: "192.0.2.7", DestPort: 22, Service: "ssh",
			Raw: "{}", ReceivedAt: time.Now().UTC(), EventID: "ev-keep-1",
		}); err != nil {
			t.Fatalf("InsertAlertIfNew: %v", err)
		}
		now := time.Now().UTC().Format(time.RFC3339)
		if _, err := d.Exec(`INSERT INTO findings (agent_id, target, vulnerability_id, first_seen, last_seen, state)
			VALUES (?, ?, ?, ?, ?, ?)`, "agent-one", "img", "CVE-0000-0001", now, now, "open"); err != nil {
			t.Fatalf("insert finding: %v", err)
		}
	})
}

func (e caResetEnv) count(t *testing.T, query string) int {
	t.Helper()
	var n int
	e.seed(t, func(d *db.DB) {
		if err := d.QueryRow(query).Scan(&n); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	})
	return n
}

// runCAReset runs `birdcage ca reset <args>` with stdin as the operator's
// typed input, returning the exit code and everything printed to stdout and
// stderr.
func runCAReset(t *testing.T, stdin string, args ...string) (int, string) {
	t.Helper()
	oldIn, oldOut, oldErr := os.Stdin, os.Stdout, os.Stderr
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := io.WriteString(inW, stdin); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	_ = inW.Close() // EOF after the input, so an unread prompt never hangs
	outFile, err := os.Create(filepath.Join(t.TempDir(), "out.txt"))
	if err != nil {
		t.Fatalf("create out: %v", err)
	}
	os.Stdin, os.Stdout, os.Stderr = inR, outFile, outFile
	var buf bytes.Buffer
	handled, code := runSubcommand(append([]string{"birdcage", "ca", "reset"}, args...), io.MultiWriter(&buf, outFile))
	os.Stdin, os.Stdout, os.Stderr = oldIn, oldOut, oldErr
	_ = inR.Close()
	_ = outFile.Close()
	if !handled {
		t.Fatalf("runSubcommand(ca reset) handled = false, want true")
	}
	printed, err := os.ReadFile(outFile.Name())
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	return code, string(printed)
}

// dbSiblings lists files next to the database that are not the database
// itself (or its SQLite journal files): the backup copies.
func (e caResetEnv) dbSiblings(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(e.dbPath))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var out []string
	base := filepath.Base(e.dbPath)
	for _, ent := range entries {
		n := ent.Name()
		if n == base || n == base+"-wal" || n == base+"-shm" || n == base+"-journal" {
			continue
		}
		out = append(out, filepath.Join(filepath.Dir(e.dbPath), n))
	}
	return out
}

func (e caResetEnv) lastAudit(t *testing.T) (action, reason string, n int) {
	t.Helper()
	e.seed(t, func(d *db.DB) {
		if err := d.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action LIKE '%reset%'`).Scan(&n); err != nil {
			t.Fatalf("count audit: %v", err)
		}
		if n > 0 {
			if err := d.QueryRow(`SELECT action, reason FROM audit_log WHERE action LIKE '%reset%' ORDER BY id DESC LIMIT 1`).Scan(&action, &reason); err != nil {
				t.Fatalf("scan audit: %v", err)
			}
		}
	})
	return
}

func TestCAResetRefusesWhenCAIsPresent(t *testing.T) {
	e := newCAResetEnv(t)
	e.enrolTwoAgents(t)
	if _, _, err := ca.Load(e.caDir, nil); err != nil {
		t.Fatalf("ca.Load: %v", err)
	}

	code, out := runCAReset(t, "reset\n")
	if code == 0 {
		t.Fatalf("exit = 0, want non-zero for a working CA; output %q", out)
	}
	if n := e.count(t, `SELECT COUNT(*) FROM client_certs`); n != 2 {
		t.Errorf("client_certs = %d after refusal, want 2 untouched", n)
	}
	if missing, err := ca.CAMissing(e.caDir); err != nil || missing != "" {
		t.Errorf("CA changed by a refused reset: missing=%q err=%v", missing, err)
	}
	if _, _, n := e.lastAudit(t); n != 0 {
		t.Errorf("%d reset audit rows after a refusal, want 0", n)
	}
	if got := e.dbSiblings(t); len(got) != 0 {
		t.Errorf("backup files %v made for a refused reset, want none", got)
	}
}

func TestCAResetRefusesOnFreshInstall(t *testing.T) {
	// No certificates and no CA: nothing was lost, so there is nothing to
	// reset (start-up already mints a new CA here). Reset refuses and
	// changes nothing.
	e := newCAResetEnv(t)
	e.seed(t, func(d *db.DB) { insertTestCanary(t, d, "agent-nocert") })

	code, out := runCAReset(t, "reset\n")
	if code == 0 {
		t.Fatalf("exit = 0, want non-zero on a fresh install; output %q", out)
	}
	if !strings.Contains(strings.ToLower(out), "nothing to reset") {
		t.Errorf("output %q, want it to say there is nothing to reset", out)
	}
	if _, _, n := e.lastAudit(t); n != 0 {
		t.Errorf("%d reset audit rows, want 0", n)
	}
	if got := e.dbSiblings(t); len(got) != 0 {
		t.Errorf("backup files %v made, want none", got)
	}
	if _, err := os.Stat(e.caDir); !os.IsNotExist(err) {
		t.Errorf("CA directory exists after a refused reset (stat err %v)", err)
	}
}

func TestCAResetWrongConfirmationChangesNothing(t *testing.T) {
	for name, input := range map[string]string{
		"empty line": "\n",
		"EOF":        "",
		"yes":        "yes\n",
		"upper case": "RESET\n",
		"with extra": "reset now\n",
	} {
		t.Run(name, func(t *testing.T) {
			e := newCAResetEnv(t)
			e.enrolTwoAgents(t)

			code, out := runCAReset(t, input)
			if code == 0 {
				t.Fatalf("exit = 0, want non-zero when not confirmed; output %q", out)
			}
			if n := e.count(t, `SELECT COUNT(*) FROM client_certs`); n != 2 {
				t.Errorf("client_certs = %d, want 2 untouched", n)
			}
			if _, _, n := e.lastAudit(t); n != 0 {
				t.Errorf("%d reset audit rows, want 0", n)
			}
		})
	}
}

func TestCAResetPrintsHowManyAgentsMustEnrolAgain(t *testing.T) {
	e := newCAResetEnv(t)
	e.enrolTwoAgents(t)

	_, out := runCAReset(t, "no\n")
	if !strings.Contains(out, "2") || strings.Contains(out, "3") {
		t.Errorf("output %q, want the count 2 (agents holding certificates), not 3", out)
	}
	if !strings.Contains(out, "reset") {
		t.Errorf("output %q, want it to tell the operator to type reset", out)
	}
}

func TestCAResetSQLiteBacksUpThenResets(t *testing.T) {
	e := newCAResetEnv(t)
	e.enrolTwoAgents(t)

	code, out := runCAReset(t, "reset\n")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; output %q", code, out)
	}
	if n := e.count(t, `SELECT COUNT(*) FROM client_certs`); n != 0 {
		t.Errorf("client_certs = %d, want 0 after reset", n)
	}
	if n := e.count(t, `SELECT COUNT(*) FROM alerts`); n != 1 {
		t.Errorf("alerts = %d, want the event history kept (1)", n)
	}
	if n := e.count(t, `SELECT COUNT(*) FROM findings`); n != 1 {
		t.Errorf("findings = %d, want kept (1)", n)
	}
	if n := e.count(t, `SELECT COUNT(*) FROM canaries`); n != 3 {
		t.Errorf("agents = %d, want all 3 kept", n)
	}

	// The next start-up no longer refuses and may mint a new CA.
	cfg := startupConfig{caNeeded: true, caDir: e.caDir}
	e.seed(t, func(d *db.DB) {
		if err := checkStartupCAContinuity(context.Background(), cfg, d, discardLog()); err != nil {
			t.Errorf("checkStartupCAContinuity after reset = %v, want nil", err)
		}
	})

	// A copy of the database sits in the same folder, with the time in its name.
	backups := e.dbSiblings(t)
	if len(backups) != 1 {
		t.Fatalf("files next to the database = %v, want exactly one backup", backups)
	}
	if !strings.HasPrefix(filepath.Base(backups[0]), filepath.Base(e.dbPath)) {
		t.Errorf("backup name %q should start from the database name", backups[0])
	}
	if !strings.ContainsAny(filepath.Base(backups[0])[len(filepath.Base(e.dbPath)):], "0123456789") {
		t.Errorf("backup name %q carries no time", backups[0])
	}
	backup, err := db.Open(backups[0])
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer func() { _ = backup.Close() }()
	var n int
	if err := backup.QueryRow(`SELECT COUNT(*) FROM client_certs`).Scan(&n); err != nil || n != 2 {
		t.Errorf("backup client_certs = %d (err %v), want the pre-reset 2", n, err)
	}

	// One audit row names the reset and the backup's path.
	action, reason, rows := e.lastAudit(t)
	if rows != 1 {
		t.Fatalf("reset audit rows = %d, want 1", rows)
	}
	if !strings.Contains(action, "reset") || !strings.Contains(reason, backups[0]) {
		t.Errorf("audit = (%q, %q), want a reset naming the backup path %q", action, reason, backups[0])
	}
}

func TestCAResetSQLiteIgnoresBackupTakenAndStillCopies(t *testing.T) {
	e := newCAResetEnv(t)
	e.enrolTwoAgents(t)

	code, out := runCAReset(t, "reset\n", "--backup-taken")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; output %q", code, out)
	}
	if got := e.dbSiblings(t); len(got) != 1 {
		t.Errorf("files next to the database = %v, want the copy still made on SQLite", got)
	}
}

func TestCAResetStopsWhenBackupFails(t *testing.T) {
	e := newCAResetEnv(t)
	e.enrolTwoAgents(t)
	dir := filepath.Dir(e.dbPath)
	if err := os.Chmod(dir, 0o500); err != nil { // readable, not writable: no copy possible
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if f, err := os.CreateTemp(dir, "probe"); err == nil { // running as root: cannot force a failure
		_ = f.Close()
		_ = os.Remove(f.Name())
		t.Skip("directory stays writable for this user; cannot simulate a failed backup")
	}

	code, out := runCAReset(t, "reset\n")
	if code == 0 {
		t.Fatalf("exit = 0, want non-zero when the backup fails; output %q", out)
	}
	_ = os.Chmod(dir, 0o700)
	if n := e.count(t, `SELECT COUNT(*) FROM client_certs`); n != 2 {
		t.Errorf("client_certs = %d after a failed backup, want 2 untouched", n)
	}
	if _, _, n := e.lastAudit(t); n != 0 {
		t.Errorf("%d reset audit rows after a failed backup, want 0", n)
	}
}

func TestCAResetPostgresRefusesWithoutBackupTaken(t *testing.T) {
	// Birdcage cannot copy a Postgres database. Without --backup-taken it
	// refuses before doing anything; the address is an unroutable example
	// one, so nothing here can reach a real server.
	newCAResetEnv(t)
	t.Setenv(envDatabaseURL, "postgres://u:p@192.0.2.1:5432/birdcage?sslmode=verify-full")

	code, out := runCAReset(t, "reset\n")
	if code == 0 {
		t.Fatalf("exit = 0, want non-zero on Postgres without --backup-taken; output %q", out)
	}
	if !strings.Contains(out, "--backup-taken") {
		t.Errorf("output %q, want it to name --backup-taken", out)
	}
}

func TestCheckStartupCAContinuityRefusalNamesCAReset(t *testing.T) {
	database := openTestDB(t)
	insertTestCanary(t, database, "canary-names-reset")
	insertTestClientCert(t, database, "canary-names-reset")

	cfg := startupConfig{caNeeded: true, caDir: filepath.Join(t.TempDir(), "ca")}
	err := checkStartupCAContinuity(context.Background(), cfg, database, discardLog())
	if err == nil {
		t.Fatal("checkStartupCAContinuity = nil, want a refusal")
	}
	if !strings.Contains(err.Error(), "birdcage ca reset") {
		t.Errorf("refusal %q, want it to name `birdcage ca reset`", err.Error())
	}
}
