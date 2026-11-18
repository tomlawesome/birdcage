package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/auth"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// Issue #164, design call (note 63632): start-up refuses when the accounts
// store is empty but the database is not new (a botched restore), with
// `birdcage auth reset` as the operator's deliberate way past it, the same
// shape as checkStartupCAContinuity and `birdcage ca reset`.
//
// The names these tests hold the code to:
//
//	checkStartupAuthContinuity(ctx, cfg startupConfig, database *db.DB, authLog *slog.Logger) error
//	    reads cfg.auth.Key; returns a *startupError to refuse.
//	`birdcage auth reset` through runSubcommand (handled = true), reading
//	    its confirmation line from os.Stdin and the key from
//	    BIRDCAGE_AUTH_KEY_FILE.

const authTestPassword = "mulberry cadence anvil 71 harbour"

var authSetupCodeLine = regexp.MustCompile(`with setup code (\S+)`)

func authTestKey() []byte { return bytes.Repeat([]byte{'k'}, 32) }

// seedAccount registers a first admin through the real sign-in service over
// database, then closes the service: the accounts store is no longer empty.
func seedAccount(t *testing.T, database *db.DB) {
	t.Helper()
	var logged bytes.Buffer
	svc, err := auth.Open(t.Context(), database, auth.Config{Key: authTestKey()}, slog.New(slog.NewTextHandler(&logged, nil)))
	if err != nil {
		t.Fatalf("auth.Open: %v", err)
	}
	defer svc.Close()
	svc.ReleaseCodes()
	m := authSetupCodeLine.FindStringSubmatch(logged.String())
	if m == nil {
		t.Fatalf("no setup code logged by a fresh store; log:\n%s", logged.String())
	}
	server := httptest.NewServer(svc.Wrap(http.NotFoundHandler()))
	defer server.Close()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/api/auth/register",
		strings.NewReader(`{"username":"erebus-admin","password":"`+authTestPassword+`","setupCode":"`+m[1]+`"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "birdcage")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register first admin: status %d, want 201", resp.StatusCode)
	}
}

// history says what makes a database "not new".
type usedHistory struct {
	name string
	seed func(t *testing.T, d *db.DB)
}

// The two signals that "an account has existed" (note 63923): a settings
// row accounts_initialised (written when user.register is recorded) or a
// user.register audit row. Either one with zero accounts is a refusal.
func seedInitialisedMarker(t *testing.T, d *db.DB) {
	t.Helper()
	if _, err := d.Exec(`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)`,
		"accounts_initialised", "true", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("insert accounts_initialised: %v", err)
	}
}

func seedAuditRow(t *testing.T, d *db.DB, action string) {
	t.Helper()
	if _, err := audit.Append(context.Background(), d, audit.Entry{
		Action: action, Target: "erebus-admin", Reason: "r", TriggeredBy: "erebus-admin", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("audit.Append(%s): %v", action, err)
	}
}

// seedUsed is a database with an account's history: the marker, plus a
// canary the operator would lose a hold on.
func seedUsed(t *testing.T, d *db.DB) {
	t.Helper()
	insertTestCanary(t, d, "canary-164")
	seedInitialisedMarker(t, d)
}

var usedDatabaseHistories = []usedHistory{
	{"the accounts_initialised marker", seedInitialisedMarker},
	{"a user.register audit row", func(t *testing.T, d *db.DB) { seedAuditRow(t, d, "user.register") }},
}

// ordinaryFreshInstallHistories are events a fresh install produces before
// its first admin: they must never count as "not new".
var ordinaryFreshInstallHistories = []usedHistory{
	{"a canary", func(t *testing.T, d *db.DB) { insertTestCanary(t, d, "canary-164") }},
	{"a finding", func(t *testing.T, d *db.DB) {
		now := time.Now().UTC().Format(time.RFC3339)
		if _, err := d.Exec(`INSERT INTO findings (agent_id, target, vulnerability_id, first_seen, last_seen, state)
			VALUES (?, ?, ?, ?, ?, ?)`, "agent-164", "img", "CVE-0000-0164", now, now, "open"); err != nil {
			t.Fatalf("insert finding: %v", err)
		}
	}},
	{"a failed sign-in", func(t *testing.T, d *db.DB) { seedAuditRow(t, d, "user.login_failed") }},
	{"rate-limit hits", func(t *testing.T, d *db.DB) {
		seedAuditRow(t, d, "user.login_failed")
		seedAuditRow(t, d, "user.login_throttled")
	}},
}

// startsAndPrintsSetupCode opens the sign-in service the way a start does
// after the guard passes and expects exactly one setup code in its log.
func startsAndPrintsSetupCode(t *testing.T, database *db.DB) {
	t.Helper()
	var logged bytes.Buffer
	svc, err := auth.Open(t.Context(), database, auth.Config{Key: authTestKey()}, slog.New(slog.NewTextHandler(&logged, nil)))
	if err != nil {
		t.Fatalf("auth.Open: %v", err)
	}
	defer svc.Close()
	svc.ReleaseCodes()
	if got := authSetupCodeLine.FindAllString(logged.String(), -1); len(got) != 1 {
		t.Errorf("setup code lines after a normal start = %d, want 1; log:\n%s", len(got), logged.String())
	}
}

func authCfg() startupConfig { return startupConfig{auth: auth.Config{Key: authTestKey()}} }

func TestCheckStartupAuthContinuityRefusesEmptyAccountsOnUsedDatabase(t *testing.T) {
	for _, h := range usedDatabaseHistories {
		t.Run(h.name, func(t *testing.T) {
			database := openTestDB(t)
			h.seed(t, database)

			out, err := captureStdout(t, func() error {
				return checkStartupAuthContinuity(context.Background(), authCfg(), database, discardLog())
			})
			if err == nil {
				t.Fatal("checkStartupAuthContinuity = nil with no accounts and a used database, want a refusal")
			}
			var se *startupError
			if !errors.As(err, &se) {
				t.Errorf("error is %T, want *startupError like the CA continuity check", err)
			}
			low := strings.ToLower(err.Error())
			for _, want := range []string{"birdcage auth reset", "restore", "new admin"} {
				if !strings.Contains(low, want) {
					t.Errorf("error = %q, want it to contain %q", err.Error(), want)
				}
			}
			if authSetupCodeLine.MatchString(out) {
				t.Errorf("the check printed a setup code on a refused start:\n%s", out)
			}
		})
	}
}

func TestCheckStartupAuthContinuityAllowsANewDatabase(t *testing.T) {
	database := openTestDB(t)
	if err := checkStartupAuthContinuity(context.Background(), authCfg(), database, discardLog()); err != nil {
		t.Errorf("fresh database: error = %v, want nil", err)
	}
	// A setting alone (an operator ran `settings set` before the first
	// start) is not "in use".
	if err := store.SetSetting(context.Background(), database, store.SettingAdminApprovalAddress, "admin@example.net", time.Now().UTC()); err != nil {
		t.Fatalf("set setting: %v", err)
	}
	if err := checkStartupAuthContinuity(context.Background(), authCfg(), database, discardLog()); err != nil {
		t.Errorf("database with only a setting: error = %v, want nil", err)
	}
}

// A fresh install restarting after ordinary pre-admin events starts
// normally and prints a setup code.
func TestCheckStartupAuthContinuityAllowsAFreshInstallAfterOrdinaryEvents(t *testing.T) {
	for _, h := range ordinaryFreshInstallHistories {
		t.Run(h.name, func(t *testing.T) {
			database := openTestDB(t)
			h.seed(t, database)
			if err := checkStartupAuthContinuity(context.Background(), authCfg(), database, discardLog()); err != nil {
				t.Fatalf("error = %v, want nil: this is an ordinary fresh install", err)
			}
			startsAndPrintsSetupCode(t, database)
		})
	}
}

// The CLI-only commands an operator runs before the first start (`agent
// add`, `agent enrol`) leave audit rows and agents; the next start is
// still a fresh install.
func TestCheckStartupAuthContinuityAllowsAFreshInstallAfterCLIAddAndEnrol(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	t.Setenv(envDatabaseURL, "")
	t.Setenv(envAdvertiseHost, "203.0.113.10")
	t.Setenv(envCADir, filepath.Join(t.TempDir(), "ca"))
	enrolDBWithCert(t, false)
	if _, err := captureStdout(t, func() error {
		return runCanaryAdd([]string{"canary-add-164", "front desk", "office", "22,80"})
	}); err != nil {
		t.Fatalf("runCanaryAdd: %v", err)
	}
	if _, err := captureStdout(t, func() error {
		return runCanaryEnrol([]string{"--name", "scanner-1", "--lane", "front-door", "--kind", "scanner"})
	}); err != nil {
		t.Fatalf("runCanaryEnrol: %v", err)
	}
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)
	if err := checkStartupAuthContinuity(context.Background(), authCfg(), database, discardLog()); err != nil {
		t.Fatalf("after agent add and enrol: error = %v, want nil", err)
	}
	startsAndPrintsSetupCode(t, database)
}

// The marker is written outside auth_documents, so a restore that loses
// that table (and with it every account) still leaves the guard armed.
func TestCheckStartupAuthContinuityMarkerSurvivesLosingAuthDocuments(t *testing.T) {
	database := openTestDB(t)
	seedAccount(t, database) // registering records the marker and the audit row
	if _, err := database.Exec(`DELETE FROM auth_documents`); err != nil {
		t.Fatalf("lose auth_documents: %v", err)
	}
	if err := checkStartupAuthContinuity(context.Background(), authCfg(), database, discardLog()); err == nil {
		t.Error("guard = nil after auth_documents was lost, want a refusal")
	}
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM settings WHERE key = 'accounts_initialised'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("accounts_initialised rows = %d (err %v), want 1 written by the first registration", n, err)
	}
}

func TestCheckStartupAuthContinuityAllowsAUsedDatabaseWithAccounts(t *testing.T) {
	for _, h := range usedDatabaseHistories {
		t.Run(h.name, func(t *testing.T) {
			database := openTestDB(t)
			h.seed(t, database)
			seedAccount(t, database)
			if err := checkStartupAuthContinuity(context.Background(), authCfg(), database, discardLog()); err != nil {
				t.Errorf("accounts present: error = %v, want nil", err)
			}
		})
	}
}

// ---- `birdcage auth reset`

type authResetEnv struct{ dbPath string }

func newAuthResetEnv(t *testing.T) authResetEnv {
	t.Helper()
	e := authResetEnv{dbPath: testDBPath(t)}
	t.Setenv(envDBPath, e.dbPath)
	t.Setenv(envDatabaseURL, "")
	t.Setenv(testEnvAuthKeyFile, writeKeyFile(t, 32))
	return e
}

func (e authResetEnv) seed(t *testing.T, fn func(*db.DB)) {
	t.Helper()
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)
	fn(database)
}

func (e authResetEnv) resetAudits(t *testing.T) (n int) {
	t.Helper()
	e.seed(t, func(d *db.DB) {
		if err := d.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action LIKE '%auth%reset%' OR action LIKE '%reset%auth%'`).Scan(&n); err != nil {
			t.Fatalf("count audit: %v", err)
		}
	})
	return
}

func (e authResetEnv) guard(t *testing.T) (err error) {
	t.Helper()
	e.seed(t, func(d *db.DB) {
		err = checkStartupAuthContinuity(context.Background(), authCfg(), d, discardLog())
	})
	return
}

// runAuthReset runs `birdcage auth reset <args>` with stdin as the
// operator's typed input and returns the exit code and everything printed.
func runAuthReset(t *testing.T, stdin string, args ...string) (int, string) {
	t.Helper()
	oldIn, oldOut, oldErr := os.Stdin, os.Stdout, os.Stderr
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := io.WriteString(inW, stdin); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	_ = inW.Close()
	outFile, err := os.Create(filepath.Join(t.TempDir(), "out.txt"))
	if err != nil {
		t.Fatalf("create out: %v", err)
	}
	os.Stdin, os.Stdout, os.Stderr = inR, outFile, outFile
	var buf bytes.Buffer
	handled, code := runSubcommand(append([]string{"birdcage", "auth", "reset"}, args...), io.MultiWriter(&buf, outFile))
	os.Stdin, os.Stdout, os.Stderr = oldIn, oldOut, oldErr
	_ = inR.Close()
	_ = outFile.Close()
	if !handled {
		t.Fatalf("runSubcommand(auth reset) handled = false, want true")
	}
	printed, err := os.ReadFile(outFile.Name())
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	return code, string(printed) + buf.String()
}

func TestAuthResetRefusesWhenAccountsExist(t *testing.T) {
	e := newAuthResetEnv(t)
	e.seed(t, func(d *db.DB) { seedUsed(t, d); seedAccount(t, d) })

	code, out := runAuthReset(t, "reset\n")
	if code == 0 {
		t.Fatalf("exit = 0 with an account present, want non-zero; output %q", out)
	}
	if n := e.resetAudits(t); n != 0 {
		t.Errorf("%d reset audit rows after a refusal, want 0", n)
	}
	if err := e.guard(t); err != nil {
		t.Errorf("accounts must be untouched by a refused reset; guard = %v", err)
	}
}

func TestAuthResetRefusesOnANewDatabase(t *testing.T) {
	e := newAuthResetEnv(t)
	e.seed(t, func(d *db.DB) {}) // migrated, empty

	code, out := runAuthReset(t, "reset\n")
	if code == 0 {
		t.Fatalf("exit = 0 on a new database, want non-zero; output %q", out)
	}
	if !strings.Contains(strings.ToLower(out), "nothing to reset") {
		t.Errorf("output %q, want it to say there is nothing to reset", out)
	}
	if n := e.resetAudits(t); n != 0 {
		t.Errorf("%d reset audit rows, want 0", n)
	}
}

// A canary and a failed sign-in are an ordinary fresh install, not "in
// use": there is nothing to reset.
func TestAuthResetRefusesOnAFreshInstallWithOrdinaryHistory(t *testing.T) {
	for _, h := range ordinaryFreshInstallHistories {
		t.Run(h.name, func(t *testing.T) {
			e := newAuthResetEnv(t)
			e.seed(t, func(d *db.DB) { h.seed(t, d) })
			code, out := runAuthReset(t, "reset\n")
			if code == 0 || !strings.Contains(strings.ToLower(out), "nothing to reset") {
				t.Errorf("exit = %d, output %q, want a non-zero exit saying there is nothing to reset", code, out)
			}
			if n := e.resetAudits(t); n != 0 {
				t.Errorf("%d reset audit rows, want 0", n)
			}
		})
	}
}

func TestAuthResetWrongConfirmationChangesNothing(t *testing.T) {
	for name, input := range map[string]string{
		"empty line": "\n", "EOF": "", "yes": "yes\n", "upper case": "RESET\n", "with extra": "reset now\n",
	} {
		t.Run(name, func(t *testing.T) {
			e := newAuthResetEnv(t)
			e.seed(t, func(d *db.DB) { seedUsed(t, d) })

			code, out := runAuthReset(t, input)
			if code == 0 {
				t.Fatalf("exit = 0 when not confirmed; output %q", out)
			}
			if n := e.resetAudits(t); n != 0 {
				t.Errorf("%d reset audit rows, want 0", n)
			}
			if err := e.guard(t); err == nil {
				t.Error("guard passes after an unconfirmed reset, want it still refusing")
			}
		})
	}
}

func TestAuthResetPromptsForResetAndWarnsAboutAdmins(t *testing.T) {
	e := newAuthResetEnv(t)
	e.seed(t, func(d *db.DB) { seedUsed(t, d) })
	_, out := runAuthReset(t, "no\n")
	if !strings.Contains(out, "reset") {
		t.Errorf("output %q, want it to tell the operator to type reset", out)
	}
	if !strings.Contains(strings.ToLower(out), "admin") {
		t.Errorf("output %q, want it to say a new admin will be created", out)
	}
}

func TestAuthResetConfirmedLetsStartUpPastTheGuard(t *testing.T) {
	e := newAuthResetEnv(t)
	e.seed(t, func(d *db.DB) { seedUsed(t, d) })
	if err := e.guard(t); err == nil {
		t.Fatal("precondition: guard should refuse before the reset")
	}

	code, out := runAuthReset(t, "reset\n")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; output %q", code, out)
	}
	if authSetupCodeLine.MatchString(out) {
		t.Errorf("the CLI printed a setup code (only the server's log may):\n%s", out)
	}
	if n := e.resetAudits(t); n != 1 {
		t.Errorf("reset audit rows = %d, want exactly 1", n)
	}
	// Start-up (and a restart while still empty) now proceeds to print a code.
	for i := 0; i < 2; i++ {
		if err := e.guard(t); err != nil {
			t.Errorf("guard after reset, start %d = %v, want nil", i+1, err)
		}
	}
	// The data an operator restores is kept: only the guard is lifted.
	e.seed(t, func(d *db.DB) {
		var n int
		if err := d.QueryRow(`SELECT COUNT(*) FROM agents`).Scan(&n); err != nil || n != 1 {
			t.Errorf("agents = %d (err %v) after auth reset, want the canary kept", n, err)
		}
	})
}

// The reset acknowledgement is not a standing off switch: once the first
// admin exists it is spent, so a later empty accounts store on a used
// database is refused again.
func TestAuthResetAcknowledgementIsSpentOnceAnAccountExists(t *testing.T) {
	e := newAuthResetEnv(t)
	e.seed(t, func(d *db.DB) { seedUsed(t, d) })
	if code, out := runAuthReset(t, "reset\n"); code != 0 {
		t.Fatalf("auth reset exit = %d, want 0; output %q", code, out)
	}
	if err := e.guard(t); err != nil {
		t.Fatalf("guard right after reset = %v, want nil", err)
	}

	e.seed(t, func(d *db.DB) { seedAccount(t, d) }) // the first admin registers
	if err := e.guard(t); err != nil {              // a start with an account present
		t.Fatalf("guard with the first admin present = %v, want nil", err)
	}

	// The accounts are lost again (a botched restore over a used database).
	e.seed(t, func(d *db.DB) {
		if _, err := d.Exec(`DELETE FROM auth_documents WHERE name = 'accounts'`); err != nil {
			t.Fatalf("empty the accounts store: %v", err)
		}
	})
	if err := e.guard(t); err == nil {
		t.Error("guard = nil after the accounts were emptied again, want a refusal: the reset must not stay in force")
	}
}

// endlessInput yields 'a' forever (up to limit bytes) and counts what was read.
type endlessInput struct {
	limit, read int
}

func (r *endlessInput) Read(p []byte) (int, error) {
	if r.read >= r.limit {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.limit-r.read {
		n = r.limit - r.read
	}
	for i := 0; i < n; i++ {
		p[i] = 'a'
	}
	r.read += n
	return n, nil
}

// maxConfirmationRead is the most a reset command may read for its one
// confirmation word; the answer is `reset`, so anything near this is not it.
const maxConfirmationRead = 64 << 10

func TestAuthResetRefusesOverLongInputWithoutReadingItAll(t *testing.T) {
	e := newAuthResetEnv(t)
	e.seed(t, func(d *db.DB) { seedUsed(t, d) })
	in := &endlessInput{limit: 64 << 20}
	err := runAuth([]string{"reset"}, in, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("auth reset accepted 64 MiB of input with no newline, want a refusal")
	}
	if in.read > maxConfirmationRead {
		t.Errorf("auth reset read %d bytes of stdin, want at most %d", in.read, maxConfirmationRead)
	}
	if n := e.resetAudits(t); n != 0 {
		t.Errorf("%d reset audit rows after a refused reset, want 0", n)
	}
	if err := e.guard(t); err == nil {
		t.Error("guard passes after an over-long answer, want it still refusing")
	}
}

func TestCAResetRefusesOverLongInputWithoutReadingItAll(t *testing.T) {
	e := newCAResetEnv(t)
	e.enrolTwoAgents(t)
	in := &endlessInput{limit: 64 << 20}
	err := runCA([]string{"reset"}, in, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("ca reset accepted 64 MiB of input with no newline, want a refusal")
	}
	if in.read > maxConfirmationRead {
		t.Errorf("ca reset read %d bytes of stdin, want at most %d", in.read, maxConfirmationRead)
	}
	if n := e.count(t, `SELECT COUNT(*) FROM client_certs`); n != 2 {
		t.Errorf("client_certs = %d after a refused reset, want 2 untouched", n)
	}
}
