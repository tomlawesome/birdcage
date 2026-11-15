package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/tomlawesome/gauntlet/persist"

	"github.com/tomlawesome/birdcage/internal/auth"
	"github.com/tomlawesome/birdcage/internal/authstore"
)

// TestEveryDashboardRouteNeedsASignIn is test 5 of the specification for
// issue #8: behind Service.Wrap, with an account in place, every dashboard
// route answers 401 with no session; 200 for the admin signed in with
// password and authenticator code; and 200 for a read API token as a bearer.
func TestEveryDashboardRouteNeedsASignIn(t *testing.T) {
	database := openDatabase(t)
	seedCanary(t, database)
	sys := startSystem(t, database, testKey('a'))
	admin := newClient(t)
	secret := sys.registerFirstAdmin(t, admin)
	base := sys.server.URL
	// One sign-in serves both subtests that need a session: a code is single
	// use, and only the previous, current and next 30-second steps are accepted.
	signedIn := sys.signIn(t, secret)

	t.Run("no session answers 401", func(t *testing.T) {
		anonymous := newClient(t)
		for _, path := range dashboardPaths {
			if status, body := call(t, anonymous, http.MethodGet, base+path, nil, nil); status != http.StatusUnauthorized {
				t.Errorf("GET %s with no session: status %d, want 401; body=%s", path, status, body)
			}
		}
	})

	t.Run("a bad bearer token answers 401", func(t *testing.T) {
		anonymous := newClient(t)
		for _, path := range dashboardPaths {
			status, _ := call(t, anonymous, http.MethodGet, base+path, nil, map[string]string{"Authorization": "Bearer not-a-real-token"})
			if status != http.StatusUnauthorized {
				t.Errorf("GET %s with a bad token: status %d, want 401", path, status)
			}
		}
	})

	t.Run("signed in with a second factor answers 200", func(t *testing.T) {
		for _, path := range dashboardPaths {
			if status, body := call(t, signedIn, http.MethodGet, base+path, nil, nil); status != http.StatusOK {
				t.Errorf("GET %s signed in: status %d, want 200; body=%s", path, status, body)
			}
		}
		u, _ := url.Parse(base)
		found := false
		for _, c := range signedIn.Jar.Cookies(u) {
			if c.Name == "birdcage_session" {
				found = true
			}
		}
		if !found {
			t.Errorf("no birdcage_session cookie after signing in; cookies: %v", signedIn.Jar.Cookies(u))
		}
	})

	t.Run("a read API token as a bearer answers 200", func(t *testing.T) {
		token := sys.mintReadToken(t, signedIn)
		anonymous := newClient(t)
		for _, path := range dashboardPaths {
			status, body := call(t, anonymous, http.MethodGet, base+path, nil, map[string]string{"Authorization": "Bearer " + token})
			if status != http.StatusOK {
				t.Errorf("GET %s with a read token: status %d, want 200; body=%s", path, status, body)
			}
		}
	})
}

// TestAuthRoutePostNeedsTheCSRFHeader is test 5, CSRF part: a POST to an
// auth route without X-Requested-With: birdcage is refused (403), even with
// the right password; a different header value is refused too; the right
// value gets as far as checking the password.
func TestAuthRoutePostNeedsTheCSRFHeader(t *testing.T) {
	database := openDatabase(t)
	sys := startSystem(t, database, testKey('a'))
	sys.registerFirstAdmin(t, newClient(t))
	login := sys.server.URL + "/api/auth/login"
	creds := map[string]string{"username": testAdminName, "password": testAdminPassword}

	if status, body := call(t, newClient(t), http.MethodPost, login, creds, nil); status != http.StatusForbidden {
		t.Errorf("POST login with no X-Requested-With: status %d, want 403; body=%s", status, body)
	}
	if status, body := call(t, newClient(t), http.MethodPost, login, creds, map[string]string{csrfHeader: "mikroview"}); status != http.StatusForbidden {
		t.Errorf("POST login with X-Requested-With: mikroview: status %d, want 403; body=%s", status, body)
	}
	wrong := map[string]string{"username": testAdminName, "password": "not-the-password-at-all-1"}
	if status, body := post(t, newClient(t), login, wrong); status != http.StatusUnauthorized {
		t.Errorf("POST login with the CSRF header and a wrong password: status %d, want 401; body=%s", status, body)
	}
}

// TestSessionAndFrontendAreReachableWithoutASession is test 5, open part:
// GET /api/auth/session answers 200 with no session (before any account
// exists, and after), and the frontend at / is served with no session.
func TestSessionAndFrontendAreReachableWithoutASession(t *testing.T) {
	database := openDatabase(t)
	sys := startSystem(t, database, testKey('a'))
	base := sys.server.URL

	check := func(t *testing.T, wantSetupRequired bool) {
		t.Helper()
		status, body := call(t, newClient(t), http.MethodGet, base+"/api/auth/session", nil, nil)
		if status != http.StatusOK {
			t.Fatalf("GET /api/auth/session with no session: status %d, want 200; body=%s", status, body)
		}
		var session struct {
			Authenticated bool `json:"authenticated"`
			SetupRequired bool `json:"setupRequired"`
		}
		if err := json.Unmarshal(body, &session); err != nil {
			t.Fatalf("decode session: %v; body=%s", err, body)
		}
		if session.Authenticated || session.SetupRequired != wantSetupRequired {
			t.Errorf("session = %+v, want authenticated false, setupRequired %v", session, wantSetupRequired)
		}
		status, body = call(t, newClient(t), http.MethodGet, base+"/", nil, nil)
		if status != http.StatusOK || !strings.Contains(string(body), "frontend stand-in") {
			t.Errorf("GET / with no session: status %d body=%s, want 200 with the frontend", status, body)
		}
	}
	check(t, true)
	sys.registerFirstAdmin(t, newClient(t))
	check(t, false)
}

// TestSetupCodeIsLoggedOnceAndRequiredForTheFirstAdmin is test 6: an empty
// accounts store logs the one-time setup code exactly once on the logger
// given to Open; registering needs that code (none or a wrong one is
// refused and creates nothing); the right code creates the admin; a second
// Open over the now-populated store announces no code.
func TestSetupCodeIsLoggedOnceAndRequiredForTheFirstAdmin(t *testing.T) {
	database := openDatabase(t)
	sys := startSystem(t, database, testKey('a'))
	base := sys.server.URL
	codes := sys.log.setupCodes()
	if len(codes) != 1 {
		t.Fatalf("setup codes logged after Open = %v, want exactly one", codes)
	}
	creds := func(code string) map[string]string {
		return map[string]string{"username": testAdminName, "password": testAdminPassword, "setupCode": code}
	}

	for _, code := range []string{"", "AAAA-AAAA-AAAA-AAAA"} {
		if status, body := post(t, newClient(t), base+"/api/auth/register", creds(code)); status != http.StatusUnauthorized {
			t.Errorf("register with setup code %q: status %d, want 401; body=%s", code, status, body)
		}
	}
	status, body := call(t, newClient(t), http.MethodGet, base+"/api/auth/session", nil, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"setupRequired":true`) {
		t.Fatalf("after refused registrations: session status %d body=%s, want setupRequired true (no account made)", status, body)
	}

	if status, body := post(t, newClient(t), base+"/api/auth/register", creds(codes[0])); status != http.StatusCreated {
		t.Fatalf("register with the logged setup code: status %d, want 201; body=%s", status, body)
	}
	if status, body := post(t, newClient(t), base+"/api/auth/register", creds(codes[0])); status != http.StatusConflict {
		t.Errorf("register a second admin with the same code: status %d, want 409; body=%s", status, body)
	}
	if got := sys.log.setupCodes(); len(got) != 1 {
		t.Errorf("setup codes logged after registering = %v, want still exactly one", got)
	}

	// Another process over the same database finds an account and announces no code.
	_, second, err := openService(t, database, testKey('a'))
	if err != nil {
		t.Fatalf("auth.Open over a populated store: %v", err)
	}
	if got := second.setupCodes(); len(got) != 0 {
		t.Errorf("setup codes logged by a second Open over a populated store = %v, want none", got)
	}
}

// TestStoreWrittenUnderOneKeyDoesNotOpenUnderAnother is test 8: accounts
// saved under key A are refused when opened under key B (an error from
// Open, not an empty store with a fresh setup code), and still open under
// key A.
func TestStoreWrittenUnderOneKeyDoesNotOpenUnderAnother(t *testing.T) {
	database := openDatabase(t)
	first := startSystem(t, database, testKey('a'))
	first.registerFirstAdmin(t, newClient(t))
	first.svc.Close()
	first.server.Close()

	if svc, _, err := openService(t, database, testKey('b')); err == nil {
		svc.Close()
		t.Fatal("auth.Open under a different key = nil error, want a refusal")
	}

	reopened := startSystem(t, database, testKey('a'))
	status, body := call(t, newClient(t), http.MethodGet, reopened.server.URL+"/api/auth/session", nil, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"setupRequired":false`) {
		t.Errorf("reopened under the original key: session status %d body=%s, want the existing account (setupRequired false)", status, body)
	}
	if codes := reopened.log.setupCodes(); len(codes) != 0 {
		t.Errorf("reopened under the original key announced setup codes %v, want none", codes)
	}
}

// TestStoresAreSealedUnderTheKeyWithTheStoreNameAsLabel: what reaches
// auth_documents is ciphertext (no username in it) that persist.Encrypt
// under the same key and the store's name as label opens (ADR-0016
// decision 3); the same bytes do not open under another label.
func TestStoresAreSealedUnderTheKeyWithTheStoreNameAsLabel(t *testing.T) {
	database := openDatabase(t)
	key := testKey('a')
	sys := startSystem(t, database, key)
	sys.registerFirstAdmin(t, newClient(t))
	sys.svc.Close()

	var raw []byte
	if err := database.QueryRow(`SELECT payload FROM auth_documents WHERE name = ?`, "accounts").Scan(&raw); err != nil {
		t.Fatalf("read the accounts document: %v", err)
	}
	if bytes.Contains(raw, []byte(testAdminName)) {
		t.Fatalf("the accounts document in auth_documents holds the username in the clear")
	}

	open := func(label string) (persist.Snapshot, error) {
		sealed, err := persist.Encrypt(authstore.NewBackend(database, "accounts"), key, persist.EncryptOptions{Label: label})
		if err != nil {
			t.Fatalf("persist.Encrypt: %v", err)
		}
		return sealed.Load(context.Background())
	}
	snap, err := open("accounts")
	if err != nil {
		t.Fatalf("opening the accounts document under its own label: %v", err)
	}
	if !bytes.Contains(snap.Payload, []byte(testAdminName)) {
		t.Errorf("the accounts document opened under the key and label \"accounts\" does not hold the admin")
	}
	if _, err := open("tokens"); err == nil {
		t.Errorf("the accounts document opened under the label \"tokens\"; the store name must be its label")
	}
}

// TestOpenRefusesAKeyUnderMinimumLength: a key shorter than
// persist.MinKeyBytes (32) is refused by Open itself.
func TestOpenRefusesAKeyUnderMinimumLength(t *testing.T) {
	database := openDatabase(t)
	for _, n := range []int{0, 16, 31} {
		svc, _, err := openService(t, database, bytes.Repeat([]byte{'k'}, n))
		if err == nil {
			svc.Close()
			t.Errorf("auth.Open with a %d-byte key = nil error, want a refusal", n)
		}
	}
}

// TestNoCountryLookupWithoutAProvider is test 7, service part: with no
// country provider configured, Open succeeds and country lookup is off.
func TestNoCountryLookupWithoutAProvider(t *testing.T) {
	database := openDatabase(t)
	svc, _, err := openService(t, database, testKey('a'))
	if err != nil {
		t.Fatalf("auth.Open with no country provider: %v", err)
	}
	if svc.CountryLookupEnabled() {
		t.Error("CountryLookupEnabled() = true with no provider configured, want false")
	}
}

var _ = auth.Config{} // the tests above set only Config.Key; every other field stays at its zero value.
