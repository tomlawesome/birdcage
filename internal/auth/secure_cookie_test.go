package auth_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tomlawesome/birdcage/internal/api"
	"github.com/tomlawesome/birdcage/internal/auth"
	"github.com/tomlawesome/birdcage/internal/db"
)

// startSystemWith is startSystem with the whole Config given, for tests of
// the settings behind a reverse proxy (issue #8 items 13-14).
func startSystemWith(t *testing.T, database *db.DB, cfg auth.Config) *system {
	t.Helper()
	logger, capture := newLogCapture()
	svc, err := auth.Open(t.Context(), database, cfg, logger)
	if err != nil {
		t.Fatalf("auth.Open: %v", err)
	}
	t.Cleanup(svc.Close)
	mux := http.NewServeMux()
	mux.Handle("/api/", api.NewHandler(database, nil, "test"))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><title>birdcage frontend stand-in</title>")
	})
	server := httptest.NewServer(svc.Wrap(mux))
	t.Cleanup(server.Close)
	return &system{svc: svc, log: capture, server: server, database: database}
}

// signInCookies signs the admin in over plain HTTP and returns the cookies
// the responses set. It carries cookies between the two steps by hand: a
// browser's jar (and net/http's) would drop a Secure cookie sent over http,
// and the second step needs the first step's.
func (s *system) signInCookies(t *testing.T, secret string) []*http.Cookie {
	t.Helper()
	client := newClient(t)
	var carried, seen []*http.Cookie
	step := func(path string, body map[string]string) {
		t.Helper()
		h := map[string]string{csrfHeader: csrfValue}
		raw, err := jsonBody(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, s.server.URL+path, raw)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range h {
			req.Header.Set(k, v)
		}
		for _, c := range carried {
			req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer resp.Body.Close()
		payload, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST %s: status %d, want 200; body=%s", path, resp.StatusCode, payload)
		}
		for _, c := range resp.Cookies() {
			seen = append(seen, c)
			carried = append(carried, c)
		}
	}
	step("/api/auth/login", map[string]string{"username": testAdminName, "password": testAdminPassword})
	step("/api/auth/login/factor", map[string]string{"code": totpCode(t, secret, counterNow()+1)})
	return seen
}

// sessionCookie picks the session cookie out of a response's cookies. The
// name may carry a prefix (gauntlet adds __Host- while the cookie is
// Secure), so it is matched on its ending.
func sessionCookie(t *testing.T, cookies []*http.Cookie) *http.Cookie {
	t.Helper()
	var found *http.Cookie
	for _, c := range cookies {
		if strings.HasSuffix(c.Name, "birdcage_session") && c.Value != "" {
			found = c
		}
	}
	if found == nil {
		t.Fatalf("no birdcage_session cookie among the sign-in's Set-Cookie headers: %v", cookies)
	}
	return found
}

// TestSessionCookieSecureAttributeFollowsConfig is test 14, service part:
// the cookie that completes a sign-in carries Secure when
// Config.SecureCookie is set, and does not when it is not. (Seam assumed:
// Config.SecureCookie already exists; this test pins that it is honoured
// for the session cookie in both directions.)
func TestSessionCookieSecureAttributeFollowsConfig(t *testing.T) {
	for _, secure := range []bool{false, true} {
		name := "SecureCookie false"
		if secure {
			name = "SecureCookie true"
		}
		t.Run(name, func(t *testing.T) {
			database := openDatabase(t)
			first := startSystem(t, database, testKey('a'))
			secret := first.registerFirstAdmin(t, newClient(t))
			first.svc.Close()
			first.server.Close()

			sys := startSystemWith(t, database, auth.Config{Key: testKey('a'), SecureCookie: secure})
			cookie := sessionCookie(t, sys.signInCookies(t, secret))
			if cookie.Secure != secure {
				t.Errorf("session cookie %q: Secure = %v, want %v", cookie.Name, cookie.Secure, secure)
			}
			if !cookie.HttpOnly {
				t.Errorf("session cookie %q: HttpOnly = false, want true", cookie.Name)
			}
		})
	}
}

func jsonBody(v any) (io.Reader, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(raw), nil
}
