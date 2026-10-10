package auth_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/api"
	"github.com/tomlawesome/birdcage/internal/auth"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

const (
	testAdminName     = "erebus-admin"
	testAdminPassword = "mulberry cadence anvil 71 harbour"
	csrfHeader        = "X-Requested-With"
	csrfValue         = "birdcage"
)

// dashboardPaths is the dashboard API's route list (internal/api's own list,
// dashboardRouteSpecs, is not exported to other packages), with a canary
// seeded by seedCanary for the two routes that name one.
var dashboardPaths = []string{
	"/api/alerts",
	"/api/instances",
	"/api/stats",
	"/api/canaries",
	"/api/canary?id=scanner-a",
	"/api/canaries/scanner-a/runs",
	"/api/scans",
	"/api/findings",
	"/api/visitors",
	"/api/trace",
	"/api/stream",
	"/api/history",
	"/api/mail",
}

// openDatabase opens and migrates a fresh SQLite database.
func openDatabase(t *testing.T) *db.DB {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "birdcage-auth-test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := db.Migrate(context.Background(), database); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	return database
}

// seedCanary inserts the canary the two per-canary routes read.
func seedCanary(t *testing.T, database *db.DB) {
	t.Helper()
	err := store.InsertCanary(context.Background(), database, store.Canary{
		ID: "scanner-a", Name: "scanner-a", Lane: "lan", Kind: agentkind.Scanner, EnrolledAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("InsertCanary: %v", err)
	}
}

// testKey is 32 bytes of obviously fake key material, distinct per seed.
func testKey(seed byte) []byte { return bytes.Repeat([]byte{seed}, 32) }

// logCapture is a slog handler that keeps every record as one line of text
// (message plus attributes), so a test can look for what was logged.
type logCapture struct {
	mu    *sync.Mutex
	lines *[]string
	attrs []slog.Attr
}

func newLogCapture() (*slog.Logger, *logCapture) {
	c := &logCapture{mu: &sync.Mutex{}, lines: &[]string{}}
	return slog.New(c), c
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *logCapture) Handle(_ context.Context, r slog.Record) error {
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
	*c.lines = append(*c.lines, b.String())
	c.mu.Unlock()
	return nil
}

func (c *logCapture) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &logCapture{mu: c.mu, lines: c.lines, attrs: append(append([]slog.Attr{}, c.attrs...), attrs...)}
}

func (c *logCapture) WithGroup(string) slog.Handler { return c }

func (c *logCapture) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), *c.lines...)
}

var setupCodeLine = regexp.MustCompile(`with setup code (\S+)`)

// setupCodes returns every setup code the captured log announced.
func (c *logCapture) setupCodes() []string {
	var codes []string
	for _, line := range c.all() {
		if m := setupCodeLine.FindStringSubmatch(line); m != nil {
			codes = append(codes, m[1])
		}
	}
	return codes
}

// system is one running sign-in service in front of the real dashboard
// handler, served over HTTP the way a browser reaches it: the dashboard API
// under /api/ and a stand-in frontend at every other path, all behind
// Service.Wrap.
type system struct {
	svc      *auth.Service
	log      *logCapture
	server   *httptest.Server
	database *db.DB
}

// startSystem opens the service over database with key and serves it.
func startSystem(t *testing.T, database *db.DB, key []byte) *system {
	t.Helper()
	svc, log, err := openService(t, database, key)
	if err != nil {
		t.Fatalf("auth.Open: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/", api.NewHandler(database, nil, "test"))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><title>birdcage frontend stand-in</title>")
	})
	server := httptest.NewServer(svc.Wrap(mux))
	t.Cleanup(server.Close)
	return &system{svc: svc, log: log, server: server, database: database}
}

// openService opens a Service and arranges for it to be closed with the test.
func openService(t *testing.T, database *db.DB, key []byte) (*auth.Service, *logCapture, error) {
	t.Helper()
	logger, capture := newLogCapture()
	svc, err := auth.Open(context.Background(), database, auth.Config{Key: key}, logger)
	if err != nil {
		return nil, capture, err
	}
	t.Cleanup(svc.Close)
	return svc, capture, nil
}

func newClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// call sends one request and returns the status and body. header values
// are sent as given; the CSRF header is NOT added for the caller.
func call(t *testing.T, c *http.Client, method, url string, body any, header map[string]string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rd = bytes.NewReader(raw)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	if strings.HasSuffix(url, "/api/stream") {
		// An event stream never ends; the status line is all there is to read.
		return resp.StatusCode, nil
	}
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

var withCSRF = map[string]string{csrfHeader: csrfValue}

// post sends a JSON POST with the CSRF header a browser's API client adds.
func post(t *testing.T, c *http.Client, url string, body any) (int, []byte) {
	t.Helper()
	return call(t, c, http.MethodPost, url, body, withCSRF)
}

// totpCode computes the RFC 6238 code (SHA-1, 30 s step, 6 digits) a
// phone's authenticator app shows for the base32 secret at counter.
func totpCode(t *testing.T, secretBase32 string, counter uint64) string {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.ReplaceAll(secretBase32, " ", "")))
	if err != nil {
		t.Fatalf("decode TOTP secret %q: %v", secretBase32, err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", n%1_000_000)
}

// TestTOTPHelperMatchesRFC6238 checks the helper against the RFC 6238
// Appendix B SHA-1 test vector (secret "12345678901234567890", time 59 s,
// counter 1, eight-digit code 94287082, so six digits 287082).
func TestTOTPHelperMatchesRFC6238(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	if got := totpCode(t, secret, 1); got != "287082" {
		t.Fatalf("totpCode at counter 1 = %s, want 287082", got)
	}
}

func counterNow() uint64 { return uint64(time.Now().Unix()) / 30 }

// registerFirstAdmin creates the first admin with the setup code from the
// log, enrols an authenticator app and confirms it and its recovery codes,
// and returns the app's secret. client is left signed in.
func (s *system) registerFirstAdmin(t *testing.T, client *http.Client) string {
	t.Helper()
	codes := s.log.setupCodes()
	if len(codes) != 1 {
		t.Fatalf("setup codes in the log = %v, want exactly one", codes)
	}
	base := s.server.URL
	status, body := post(t, client, base+"/api/auth/register", map[string]string{
		"username": testAdminName, "password": testAdminPassword, "setupCode": codes[0],
	})
	if status != http.StatusCreated {
		t.Fatalf("register first admin: status %d, want 201; body=%s", status, body)
	}

	status, body = post(t, client, base+"/api/auth/totp/enrol", map[string]string{"password": testAdminPassword})
	if status != http.StatusOK {
		t.Fatalf("enrol authenticator app: status %d, want 200; body=%s", status, body)
	}
	var enrol struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(body, &enrol); err != nil || enrol.Secret == "" {
		t.Fatalf("enrol response has no secret: %v; body=%s", err, body)
	}

	status, body = post(t, client, base+"/api/auth/totp/confirm", map[string]string{"code": totpCode(t, enrol.Secret, counterNow())})
	if status != http.StatusOK {
		t.Fatalf("confirm authenticator app: status %d, want 200; body=%s", status, body)
	}
	status, body = post(t, client, base+"/api/auth/recovery-codes/confirm", struct{}{})
	if status != http.StatusOK {
		t.Fatalf("confirm recovery codes saved: status %d, want 200; body=%s", status, body)
	}
	return enrol.Secret
}

// signIn signs the admin in from a fresh browser: password, then a code
// from the authenticator app. The code is for the NEXT 30-second step, which
// the server accepts within its one-step window and which differs from the
// step already spent confirming the app (a code is single-use).
func (s *system) signIn(t *testing.T, secret string) *http.Client {
	t.Helper()
	client := newClient(t)
	base := s.server.URL
	status, body := post(t, client, base+"/api/auth/login", map[string]string{"username": testAdminName, "password": testAdminPassword})
	if status != http.StatusOK || !strings.Contains(string(body), "totp") {
		t.Fatalf("password step: status %d body=%s, want 200 asking for a totp code", status, body)
	}
	status, body = post(t, client, base+"/api/auth/login/factor", map[string]string{"code": totpCode(t, secret, counterNow()+1)})
	if status != http.StatusOK {
		t.Fatalf("second-factor step: status %d, want 200; body=%s", status, body)
	}
	return client
}

// mintReadToken has the signed-in admin mint a read API token.
func (s *system) mintReadToken(t *testing.T, client *http.Client) string {
	t.Helper()
	status, body := post(t, client, s.server.URL+"/api/tokens", map[string]string{"name": "journey", "password": testAdminPassword})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("mint API token: status %d, want 201; body=%s", status, body)
	}
	var tok struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.Value == "" {
		t.Fatalf("token response has no value: %v; body=%s", err, body)
	}
	return tok.Value
}
