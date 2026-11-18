package auth_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"

	"github.com/tomlawesome/birdcage/internal/auth"
	"github.com/tomlawesome/birdcage/internal/authstore"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/logging"
)

// Issue #164 (first-run setup), written from the specification in note 63487
// alone. The log-level tests drive birdcage's real logger
// (internal/logging) with stdout redirected, because the defect is in the
// threshold that logger applies: BIRDCAGE_LOG_LEVEL=error hid the code.

var unlockCodeLine = regexp.MustCompile(`with unlock code (\S+)`)

// captureStdoutOf runs fn with os.Stdout pointed at a file and returns what
// was written. internal/logging writes to whatever os.Stdout is at write
// time. Process-global, so no test here runs in parallel.
func captureStdoutOf(t *testing.T, fn func()) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatalf("create stdout file: %v", err)
	}
	old := os.Stdout
	os.Stdout = f
	func() {
		defer func() { os.Stdout = old }()
		fn()
	}()
	if err := f.Close(); err != nil {
		t.Fatalf("close stdout file: %v", err)
	}
	out, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("read stdout file: %v", err)
	}
	return string(out)
}

// atLevel sets the process-wide log threshold for one test.
func atLevel(t *testing.T, level string) {
	t.Helper()
	logging.SetLevel(level)
	t.Cleanup(func() { logging.SetLevel("info") })
}

// TestSetupCodeIsPrintedWhateverTheLogLevel: with BIRDCAGE_LOG_LEVEL=error,
// an empty store's Open plus ReleaseCodes still writes exactly one
// "with setup code" line to stdout, and an ordinary Warn line stays hidden.
func TestSetupCodeIsPrintedWhateverTheLogLevel(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		t.Run(level, func(t *testing.T) {
			atLevel(t, level)
			database := openDatabase(t)
			out := captureStdoutOf(t, func() {
				log := logging.New("auth")
				svc, err := auth.Open(t.Context(), database, auth.Config{Key: testKey('a')}, log)
				if err != nil {
					t.Errorf("auth.Open: %v", err)
					return
				}
				defer svc.Close()
				svc.ReleaseCodes()
				log.Warn("an ordinary warning from elsewhere")
			})
			if got := setupCodeLine.FindAllStringSubmatch(out, -1); len(got) != 1 {
				t.Errorf("setup code lines on stdout at level %s = %d, want exactly 1; stdout:\n%s", level, len(got), out)
			}
			wantWarn := level != "error"
			if has := strings.Contains(out, "an ordinary warning from elsewhere"); has != wantWarn {
				t.Errorf("ordinary Warn line on stdout at level %s = %v, want %v", level, has, wantWarn)
			}
		})
	}
}

// disableEveryAccount marks every stored account as having its local
// sign-in disabled just now, by rewriting the sealed accounts document the
// way a run of failed sign-ins would leave it (gauntlet only issues the
// unlock code when the store opens in that state, and 50 failures in a row
// take hours of lockouts to reach).
func disableEveryAccount(t *testing.T, database *db.DB, key []byte) {
	t.Helper()
	backend, err := persist.Encrypt(authstore.NewBackend(database, "accounts"), key, persist.EncryptOptions{Label: "accounts"})
	if err != nil {
		t.Fatalf("seal accounts backend: %v", err)
	}
	snap, err := backend.Load(t.Context())
	if err != nil || !snap.Exists {
		t.Fatalf("load accounts document: exists=%v err=%v", snap.Exists, err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(snap.Payload, &doc); err != nil {
		t.Fatalf("decode accounts document: %v", err)
	}
	var users []map[string]any
	if err := json.Unmarshal(doc["users"], &users); err != nil || len(users) == 0 {
		t.Fatalf("accounts document has no users: %v", err)
	}
	for _, u := range users {
		u["loginDisabledAt"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	doc["users"], _ = json.Marshal(users)
	payload, _ := json.Marshal(doc)
	if _, err := backend.Save(t.Context(), payload, snap.Version); err != nil {
		t.Fatalf("save accounts document: %v", err)
	}
}

// TestUnlockCodeIsPrintedWhateverTheLogLevel: the only admin is disabled;
// the next start announces an unlock code, and the line reaches stdout at
// every level including error.
func TestUnlockCodeIsPrintedWhateverTheLogLevel(t *testing.T) {
	for _, level := range []string{"info", "error"} {
		t.Run(level, func(t *testing.T) {
			database := openDatabase(t)
			key := testKey('a')
			sys := startSystem(t, database, key)
			sys.registerFirstAdmin(t, newClient(t))
			sys.svc.Close()
			disableEveryAccount(t, database, key)

			atLevel(t, level)
			out := captureStdoutOf(t, func() {
				svc, err := auth.Open(t.Context(), database, auth.Config{Key: key}, logging.New("auth"))
				if err != nil {
					t.Errorf("auth.Open: %v", err)
					return
				}
				defer svc.Close()
				svc.ReleaseCodes()
			})
			if got := unlockCodeLine.FindAllStringSubmatch(out, -1); len(got) != 1 {
				t.Errorf("unlock code lines on stdout at level %s = %d, want exactly 1; stdout:\n%s", level, len(got), out)
			}
		})
	}
}

// TestSetupCodeStaysOutOfEveryOtherChannel: at level error the code goes to
// stdout only; the audit log and the session answer never carry it.
func TestSetupCodeStaysOutOfEveryOtherChannel(t *testing.T) {
	atLevel(t, "error")
	database := openDatabase(t)
	var server *httptest.Server
	out := captureStdoutOf(t, func() {
		svc, err := auth.Open(t.Context(), database, auth.Config{Key: testKey('a')}, logging.New("auth"))
		if err != nil {
			t.Errorf("auth.Open: %v", err)
			return
		}
		t.Cleanup(svc.Close)
		svc.ReleaseCodes()
		server = httptest.NewServer(svc.Wrap(http.NotFoundHandler()))
		t.Cleanup(server.Close)
	})
	m := setupCodeLine.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no setup code on stdout at level error; stdout:\n%s", out)
	}
	code := m[1]
	_, body := call(t, newClient(t), http.MethodGet, server.URL+"/api/auth/session", nil, nil)
	if strings.Contains(string(body), code) {
		t.Errorf("session answer contains the setup code: %s", body)
	}
	for _, row := range auditRows(t, database) {
		if strings.Contains(fmt.Sprint(row), code) {
			t.Errorf("audit row contains the setup code: %v", row)
		}
	}
}

// TestFirstAdminRegistrationIsAuditedOnce is item 2: one user.register row,
// triggered_by and target the new username, reason containing role=admin, and the
// setup code nowhere in the audit log.
func TestFirstAdminRegistrationIsAuditedOnce(t *testing.T) {
	database := openDatabase(t)
	sys := startSystem(t, database, testKey('a'))
	code := sys.log.setupCodes()[0]
	sys.registerFirstAdmin(t, newClient(t))

	rows := rowsWithAction(auditRows(t, database), "user.register")
	if len(rows) != 1 {
		t.Fatalf("user.register rows = %d, want exactly 1; all rows: %v", len(rows), auditRows(t, database))
	}
	got := rows[0]
	if got.TriggeredBy != testAdminName || got.Target != testAdminName || !strings.Contains(got.Reason, "role=admin") {
		t.Errorf("user.register row = %v, want triggered_by=%q target=%q reason containing role=admin (gauntlet appends the client address)", got, testAdminName, testAdminName)
	}
	for _, row := range auditRows(t, database) {
		if strings.Contains(fmt.Sprint(row), code) {
			t.Errorf("audit row contains the setup code: %v", row)
		}
	}
}

// TestRestartWhileEmptyIssuesANewCode is item 3: a code from an earlier
// process is refused with 401 and the new one works.
func TestRestartWhileEmptyIssuesANewCode(t *testing.T) {
	database := openDatabase(t)
	first, firstLog, err := openService(t, database, testKey('a'))
	if err != nil {
		t.Fatalf("first auth.Open: %v", err)
	}
	codeA := firstLog.setupCodes()
	if len(codeA) != 1 {
		t.Fatalf("first start logged setup codes %v, want exactly one", codeA)
	}
	first.Close()

	sys := startSystem(t, database, testKey('a'))
	codeB := sys.log.setupCodes()
	if len(codeB) != 1 {
		t.Fatalf("second start logged setup codes %v, want exactly one", codeB)
	}
	if codeA[0] == codeB[0] {
		t.Fatalf("second start reused the setup code %q, want a new one", codeB[0])
	}
	register := func(code string) int {
		status, _ := post(t, newClient(t), sys.server.URL+"/api/auth/register", map[string]string{
			"username": testAdminName, "password": testAdminPassword, "setupCode": code,
		})
		return status
	}
	if status := register(codeA[0]); status != http.StatusUnauthorized {
		t.Errorf("register with the earlier process's code: status %d, want 401", status)
	}
	if status := register(codeB[0]); status != http.StatusCreated {
		t.Errorf("register with the new code: status %d, want 201", status)
	}
}

// TestRegisterIsThrottledPerClient is item 4: five wrong codes from one
// client, then the right code from that client gives 429 and creates no
// account; the session still says setupRequired.
func TestRegisterIsThrottledPerClient(t *testing.T) {
	database := openDatabase(t)
	sys := startSystem(t, database, testKey('a'))
	code := sys.log.setupCodes()[0]
	register := func(c *http.Client, setupCode string) int {
		status, _ := post(t, c, sys.server.URL+"/api/auth/register", map[string]string{
			"username": testAdminName, "password": testAdminPassword, "setupCode": setupCode,
		})
		return status
	}
	client := newClient(t)
	for i := 0; i < 5; i++ {
		if status := register(client, fmt.Sprintf("wrong-code-%d", i)); status != http.StatusUnauthorized {
			t.Fatalf("wrong code #%d: status %d, want 401", i, status)
		}
	}
	if status := register(client, code); status != http.StatusTooManyRequests {
		t.Errorf("right code after five wrong ones: status %d, want 429", status)
	}
	_, body := call(t, newClient(t), http.MethodGet, sys.server.URL+"/api/auth/session", nil, nil)
	var s struct {
		SetupRequired bool `json:"setupRequired"`
	}
	if err := json.Unmarshal(body, &s); err != nil || !s.SetupRequired {
		t.Errorf("session after the throttled try = %s (err %v), want setupRequired true", body, err)
	}
}

// problemType decodes the problem type of an RFC 9457 body.
func problemType(body []byte) string {
	var p struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(body, &p)
	return p.Type
}

// TestDashboardRoutesWaitForTheFirstAdmin is item 5, dashboard half: before
// any account, a dashboard data route answers 503 setup-required with no
// data.
func TestDashboardRoutesWaitForTheFirstAdmin(t *testing.T) {
	database := openDatabase(t)
	seedCanary(t, database)
	sys := startSystem(t, database, testKey('a'))
	for _, path := range dashboardPaths {
		if strings.HasSuffix(path, "/api/stream") || path == "/api/stream" {
			continue // an event stream has no body to inspect
		}
		status, body := call(t, newClient(t), http.MethodGet, sys.server.URL+path, nil, nil)
		if status != http.StatusServiceUnavailable || !strings.Contains(problemType(body), "setup-required") {
			t.Errorf("GET %s before any account: status %d body=%s, want 503 setup-required", path, status, body)
		}
		if strings.Contains(string(body), "scanner-a") {
			t.Errorf("GET %s before any account returned data: %s", path, body)
		}
	}
}

// fakeIssuer answers OIDC discovery, like the one in sso_degrade_test.go.
func fakeIssuer(t *testing.T) string {
	t.Helper()
	var issuer string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/auth",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/keys",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	t.Cleanup(provider.Close)
	issuer = provider.URL
	return issuer
}

// TestSSOWaitsForTheFirstAdmin is item 5, SSO half: both OIDC routes answer
// 503 setup-required before any account; after the first admin exists the
// login route no longer answers 503.
func TestSSOWaitsForTheFirstAdmin(t *testing.T) {
	database := openDatabase(t)
	sys := startSystemWith(t, database, auth.Config{
		Key:              testKey('c'),
		PublicURL:        ssoTestPublicURL,
		OIDCIssuer:       fakeIssuer(t),
		OIDCClientID:     "birdcage-test-client",
		OIDCClientSecret: "fake-client-secret-for-tests",
	})
	for _, path := range []string{"/api/auth/oidc/login", "/api/auth/oidc/callback"} {
		status, body := call(t, newClient(t), http.MethodGet, sys.server.URL+path, nil, nil)
		if status != http.StatusServiceUnavailable || !strings.Contains(problemType(body), "setup-required") {
			t.Errorf("GET %s before any account: status %d body=%s, want 503 setup-required", path, status, body)
		}
	}
	sys.registerFirstAdmin(t, newClient(t))
	if status, body := call(t, newClient(t), http.MethodGet, sys.server.URL+"/api/auth/oidc/login", nil, nil); status == http.StatusServiceUnavailable {
		t.Errorf("GET /api/auth/oidc/login after the first admin: status %d body=%s, want anything but 503", status, body)
	}
}
