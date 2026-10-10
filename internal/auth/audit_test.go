package auth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/tomlawesome/birdcage/internal/api"
	"github.com/tomlawesome/birdcage/internal/auth"
	"github.com/tomlawesome/birdcage/internal/db"
)

// Tests for item 16 of the test specification for issue #8: the sign-in
// service writes gauntlet's account and token events to the audit_log
// table (internal/audit.Append), mapping actor to triggered_by, action to
// action, target to target and detail to reason.
//
// Item 6 of that list (an event with an empty target or detail is stored
// as "-") has no test here: every route that writes an audit record gets a
// non-empty target and a detail ending in from="...", so no HTTP request can
// produce a blank one, and the auditor type is unexported.

// auditRow is one audit_log row.
type auditRow struct {
	Action, Target, Reason, TriggeredBy string
}

func (r auditRow) String() string {
	return fmt.Sprintf("{action=%q target=%q reason=%q triggered_by=%q}", r.Action, r.Target, r.Reason, r.TriggeredBy)
}

// auditRows returns every audit_log row, oldest first.
func auditRows(t *testing.T, database *db.DB) []auditRow {
	t.Helper()
	rows, err := database.QueryContext(context.Background(),
		`SELECT action, target, reason, triggered_by FROM audit_log ORDER BY id`)
	if err != nil {
		t.Fatalf("read audit_log: %v", err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.Action, &r.Target, &r.Reason, &r.TriggeredBy); err != nil {
			t.Fatalf("scan audit_log row: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read audit_log: %v", err)
	}
	return out
}

// rowsWithAction returns the rows with the given action, oldest first.
func rowsWithAction(rows []auditRow, action string) []auditRow {
	var out []auditRow
	for _, r := range rows {
		if r.Action == action {
			out = append(out, r)
		}
	}
	return out
}

// createToken has the signed-in admin mint a token and returns its id,
// name and secret value.
func (s *system) createToken(t *testing.T, client *http.Client, name string) (id, value string) {
	t.Helper()
	status, body := post(t, client, s.server.URL+"/api/tokens", map[string]string{"name": name, "password": testAdminPassword})
	if status != http.StatusCreated {
		t.Fatalf("create API token: status %d, want 201; body=%s", status, body)
	}
	var tok struct {
		ID    string `json:"id"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.ID == "" || tok.Value == "" {
		t.Fatalf("token response has no id or value: %v; body=%s", err, body)
	}
	return tok.ID, tok.Value
}

// TestSuccessfulSignInIsAudited is item 16, case 1: a completed sign-in
// writes one user.login row whose triggered_by and target are the username
// and whose reason names the client address.
func TestSuccessfulSignInIsAudited(t *testing.T) {
	database := openDatabase(t)
	sys := startSystem(t, database, testKey('a'))
	secret := sys.registerFirstAdmin(t, newClient(t))
	before := len(rowsWithAction(auditRows(t, database), "user.login"))

	sys.signIn(t, secret)

	logins := rowsWithAction(auditRows(t, database), "user.login")
	if len(logins) != before+1 {
		t.Fatalf("user.login rows = %d, want %d (one more than before the sign-in); all rows: %v", len(logins), before+1, auditRows(t, database))
	}
	got := logins[len(logins)-1]
	if got.TriggeredBy != testAdminName || got.Target != testAdminName {
		t.Errorf("user.login row = %v, want triggered_by and target %q", got, testAdminName)
	}
	if !strings.Contains(got.Reason, `from="127.0.0.1"`) {
		t.Errorf("user.login reason = %q, want it to contain from=\"127.0.0.1\"", got.Reason)
	}
}

// TestWrongPasswordIsAudited is item 16, case 2: a wrong password for a
// real account writes a user.login_failed row targeting that account.
func TestWrongPasswordIsAudited(t *testing.T) {
	database := openDatabase(t)
	sys := startSystem(t, database, testKey('a'))
	sys.registerFirstAdmin(t, newClient(t))
	before := len(rowsWithAction(auditRows(t, database), "user.login_failed"))

	status, body := post(t, newClient(t), sys.server.URL+"/api/auth/login",
		map[string]string{"username": testAdminName, "password": "not-the-password-at-all-1"})
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong password: status %d, want 401; body=%s", status, body)
	}

	failed := rowsWithAction(auditRows(t, database), "user.login_failed")
	if len(failed) != before+1 {
		t.Fatalf("user.login_failed rows = %d, want %d; all rows: %v", len(failed), before+1, auditRows(t, database))
	}
	if got := failed[len(failed)-1]; got.Target != testAdminName {
		t.Errorf("user.login_failed row = %v, want target %q", got, testAdminName)
	}
}

// TestUnknownAccountSignInIsAuditedWithoutTheTypedName is item 16, case 3:
// a sign-in attempt for an account that does not exist writes a row, and
// neither its target nor its triggered_by contains the typed name.
func TestUnknownAccountSignInIsAuditedWithoutTheTypedName(t *testing.T) {
	const typed = "Zephyrine-Quill-Ghost"
	database := openDatabase(t)
	sys := startSystem(t, database, testKey('a'))
	sys.registerFirstAdmin(t, newClient(t))
	before := auditRows(t, database)

	status, body := post(t, newClient(t), sys.server.URL+"/api/auth/login",
		map[string]string{"username": typed, "password": "some-other-wrong-password-9"})
	if status != http.StatusUnauthorized {
		t.Fatalf("unknown account: status %d, want 401; body=%s", status, body)
	}

	after := auditRows(t, database)
	if len(after) <= len(before) {
		t.Fatalf("audit_log rows = %d after an attempt for an unknown account, want more than %d", len(after), len(before))
	}
	for _, r := range after[len(before):] {
		if strings.Contains(r.Target, typed) || strings.Contains(r.TriggeredBy, typed) {
			t.Errorf("row %v contains the typed name %q in target or triggered_by", r, typed)
		}
	}
}

// TestTokenCreateAndRevokeAreAudited is item 16, case 4: creating an API
// token writes token.create and revoking it writes token.revoke.
func TestTokenCreateAndRevokeAreAudited(t *testing.T) {
	database := openDatabase(t)
	sys := startSystem(t, database, testKey('a'))
	secret := sys.registerFirstAdmin(t, newClient(t))
	admin := sys.signIn(t, secret)

	id, _ := sys.createToken(t, admin, "audit-journey")
	created := rowsWithAction(auditRows(t, database), "token.create")
	if len(created) != 1 {
		t.Fatalf("token.create rows = %d, want 1; all rows: %v", len(created), auditRows(t, database))
	}
	if created[0].Target != "audit-journey" || created[0].TriggeredBy != testAdminName {
		t.Errorf("token.create row = %v, want target %q and triggered_by %q", created[0], "audit-journey", testAdminName)
	}

	status, body := call(t, admin, http.MethodDelete, sys.server.URL+"/api/tokens/"+id, nil, withCSRF)
	if status != http.StatusOK {
		t.Fatalf("revoke token: status %d, want 200; body=%s", status, body)
	}
	revoked := rowsWithAction(auditRows(t, database), "token.revoke")
	if len(revoked) != 1 {
		t.Fatalf("token.revoke rows = %d, want 1; all rows: %v", len(revoked), auditRows(t, database))
	}
	if revoked[0].Target != id || revoked[0].TriggeredBy != testAdminName {
		t.Errorf("token.revoke row = %v, want target %q and triggered_by %q", revoked[0], id, testAdminName)
	}
}

// TestAuditRowsHoldNoSecrets is item 16, case 5: across a whole journey
// (setup code, registration, authenticator enrolment, sign-in with a code,
// a wrong password, a token minted and revoked) no row's reason, target or
// triggered_by contains the password, an authenticator code or secret, the
// setup code or the token secret.
func TestAuditRowsHoldNoSecrets(t *testing.T) {
	database := openDatabase(t)
	sys := startSystem(t, database, testKey('a'))
	setupCodes := sys.log.setupCodes()
	secret := sys.registerFirstAdmin(t, newClient(t))
	admin := sys.signIn(t, secret)
	wrongPassword := testAdminPassword + " but wrong"
	if status, body := post(t, newClient(t), sys.server.URL+"/api/auth/login",
		map[string]string{"username": testAdminName, "password": wrongPassword}); status != http.StatusUnauthorized {
		t.Fatalf("wrong password: status %d, want 401; body=%s", status, body)
	}
	id, tokenValue := sys.createToken(t, admin, "secret-check")
	if status, body := call(t, admin, http.MethodDelete, sys.server.URL+"/api/tokens/"+id, nil, withCSRF); status != http.StatusOK {
		t.Fatalf("revoke token: status %d, want 200; body=%s", status, body)
	}

	secrets := map[string]string{
		"password":       testAdminPassword,
		"wrong password": wrongPassword,
		"token secret":   tokenValue,
		"TOTP secret":    secret,
	}
	for i, c := range setupCodes {
		secrets[fmt.Sprintf("setup code %d", i)] = c
	}
	now := counterNow()
	for _, c := range []uint64{now - 1, now, now + 1, now + 2} {
		secrets[fmt.Sprintf("TOTP code at step %d", c)] = totpCode(t, secret, c)
	}
	rows := auditRows(t, database)
	if len(rows) == 0 {
		t.Fatal("audit_log is empty after a full journey, want rows to check")
	}
	for _, r := range rows {
		for name, s := range secrets {
			for col, val := range map[string]string{"reason": r.Reason, "target": r.Target, "triggered_by": r.TriggeredBy} {
				if strings.Contains(val, s) {
					t.Errorf("row %v: %s contains the %s", r, col, name)
				}
			}
		}
	}
}

// levelCapture wraps logCapture and also keeps the lines logged at error
// level or above, which logCapture does not record.
type levelCapture struct {
	*logCapture
	mu     *sync.Mutex
	errors *[]string
	attrs  []slog.Attr
}

func newLevelCapture() (*slog.Logger, *levelCapture) {
	inner := &logCapture{mu: &sync.Mutex{}, lines: &[]string{}}
	c := &levelCapture{logCapture: inner, mu: &sync.Mutex{}, errors: &[]string{}}
	return slog.New(c), c
}

func (c *levelCapture) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelError {
		var b strings.Builder
		b.WriteString(r.Message)
		for _, a := range c.attrs {
			fmt.Fprintf(&b, " %s=%v", a.Key, a.Value)
		}
		r.Attrs(func(a slog.Attr) bool {
			fmt.Fprintf(&b, " %s=%v", a.Key, a.Value)
			return true
		})
		c.mu.Lock()
		*c.errors = append(*c.errors, b.String())
		c.mu.Unlock()
	}
	return c.logCapture.Handle(ctx, r)
}

func (c *levelCapture) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &levelCapture{
		logCapture: c.logCapture.WithAttrs(attrs).(*logCapture),
		mu:         c.mu,
		errors:     c.errors,
		attrs:      append(append([]slog.Attr{}, c.attrs...), attrs...),
	}
}

func (c *levelCapture) WithGroup(string) slog.Handler { return c }

func (c *levelCapture) errorLines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), *c.errors...)
}

// TestFailedAuditWriteIsLoggedAndTheRequestCarriesOn is item 16, case 7:
// when the audit write fails, the request still completes and the logger
// receives an error-level line naming the action.
//
// The write is made to fail by dropping the audit_log table under the
// running service rather than closing the database: the account and
// session stores share the database, so closing it would fail the sign-in
// before any audit record was reached and prove nothing about the audit
// path.
func TestFailedAuditWriteIsLoggedAndTheRequestCarriesOn(t *testing.T) {
	database := openDatabase(t)
	logger, capture := newLevelCapture()
	svc, err := auth.Open(context.Background(), database, auth.Config{Key: testKey('a')}, logger)
	if err != nil {
		t.Fatalf("auth.Open: %v", err)
	}
	t.Cleanup(svc.Close)
	mux := http.NewServeMux()
	mux.Handle("/api/", api.NewHandler(database, nil, "test"))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<!doctype html><title>birdcage frontend stand-in</title>")
	})
	server := httptest.NewServer(svc.Wrap(mux))
	t.Cleanup(server.Close)
	sys := &system{svc: svc, log: capture.logCapture, server: server, database: database}

	secret := sys.registerFirstAdmin(t, newClient(t))
	if _, err := database.ExecContext(context.Background(), `DROP TABLE audit_log`); err != nil {
		t.Fatalf("drop audit_log: %v", err)
	}

	// A failed sign-in still answers 401, and a good one still succeeds.
	status, body := post(t, newClient(t), server.URL+"/api/auth/login",
		map[string]string{"username": testAdminName, "password": "not-the-password-at-all-1"})
	if status != http.StatusUnauthorized {
		t.Errorf("wrong password with the audit write failing: status %d, want 401; body=%s", status, body)
	}
	sys.signIn(t, secret)

	lines := capture.errorLines()
	for _, action := range []string{"user.login_failed", "user.login"} {
		// \b so that "user.login" is not satisfied by "user.login_failed".
		named := regexp.MustCompile(regexp.QuoteMeta(action) + `\b`)
		found := false
		for _, l := range lines {
			if named.MatchString(l) {
				found = true
			}
		}
		if !found {
			t.Errorf("no error-level log line names %q; error lines: %q", action, lines)
		}
	}
}
