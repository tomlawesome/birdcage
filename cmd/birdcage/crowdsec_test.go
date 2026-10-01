package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/crowdsec"
	"github.com/tomlawesome/birdcage/internal/neverblock"
)

// cliFakeLAPI is the smallest LAPI that lets `birdcage crowdsec add`
// run end to end: login, allowlist no, no existing ban, 201 on post.
// The package's own tests cover every other branch; this file is the
// CLI wiring -- argument handling, configuration from the environment,
// the printed line and the exit error.
func cliFakeLAPI(t *testing.T) (srv *httptest.Server, posted *int) {
	t.Helper()
	count := 0
	srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/watchers/login":
			body, _ := io.ReadAll(r.Body)
			var in struct {
				MachineID string `json:"machine_id"`
				Password  string `json:"password"`
			}
			_ = json.Unmarshal(body, &in)
			if in.MachineID != "birdcage" || in.Password != "cli-test-password" {
				w.WriteHeader(401)
				fmt.Fprint(w, `{"code":401,"message":"incorrect Username or Password"}`)
				return
			}
			fmt.Fprint(w, `{"code":200,"expire":"2099-01-01T00:00:00Z","token":"tok"}`)
		case r.Header.Get("Authorization") != "Bearer tok":
			w.WriteHeader(401)
		case strings.HasPrefix(r.URL.Path, "/v1/allowlists/check/"):
			fmt.Fprint(w, `{"allowlisted":false,"reason":""}`)
		case r.Method == "GET" && r.URL.Path == "/v1/alerts":
			fmt.Fprint(w, `[]`)
		case r.Method == "POST" && r.URL.Path == "/v1/alerts":
			count++
			w.WriteHeader(201)
			fmt.Fprint(w, `["9"]`)
		default:
			w.WriteHeader(404)
		}
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &count
}

// crowdsecEnv is a complete, valid CrowdSec environment pointing at
// srv, with the password and the server's certificate in files.
func crowdsecEnv(t *testing.T, srv *httptest.Server) map[string]string {
	t.Helper()
	dir := t.TempDir()
	pw := filepath.Join(dir, "password")
	if err := os.WriteFile(pw, []byte("cli-test-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		crowdsec.EnvLAPIURL:      srv.URL,
		crowdsec.EnvMachineID:    "birdcage",
		crowdsec.EnvPasswordFile: pw,
		crowdsec.EnvCAFile:       ca,
	}
}

func getenvMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestCrowdsecAddHappyPath(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	srv, posted := cliFakeLAPI(t)
	env := crowdsecEnv(t, srv)

	var stdout, stderr bytes.Buffer
	if err := runCrowdsec([]string{"add", "203.0.113.9", "--reason", "cli test"}, getenvMap(env), &stdout, &stderr); err != nil {
		t.Fatalf("runCrowdsec: %v (stderr %q)", err, stderr.String())
	}
	if *posted != 1 {
		t.Fatalf("posted = %d, want 1", *posted)
	}
	out := stdout.String()
	for _, want := range []string{"added: permanent ban on 203.0.113.9", "LAPI alert 9", crowdsec.PermanentDuration, crowdsec.ActionAdded} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout %q lacks %q", out, want)
		}
	}
	if strings.Contains(out, "cli-test-password") {
		t.Fatalf("stdout carries the password: %q", out)
	}

	database, err := openCanaryDB()
	if err != nil {
		t.Fatal(err)
	}
	defer closeCanaryDB(database)
	var action, triggeredBy string
	if err := database.QueryRow(`SELECT action, triggered_by FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&action, &triggeredBy); err != nil {
		t.Fatalf("audit_log: %v", err)
	}
	if action != crowdsec.ActionAdded || triggeredBy != crowdsecTriggeredBy {
		t.Fatalf("audit row = %s/%s", action, triggeredBy)
	}
}

func TestCrowdsecAddFlagBeforeAddress(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	srv, posted := cliFakeLAPI(t)
	var stdout, stderr bytes.Buffer
	if err := runCrowdsec([]string{"add", "--reason", "order", "203.0.113.10"}, getenvMap(crowdsecEnv(t, srv)), &stdout, &stderr); err != nil {
		t.Fatalf("runCrowdsec: %v", err)
	}
	if *posted != 1 {
		t.Fatalf("posted = %d", *posted)
	}
}

func TestCrowdsecAddUsageErrors(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	srv, posted := cliFakeLAPI(t)
	env := crowdsecEnv(t, srv)
	cases := [][]string{
		{},
		{"remove", "203.0.113.9"},
		{"add"},
		{"add", "203.0.113.9"},
		{"add", "203.0.113.9", "203.0.113.10", "--reason", "x"},
		{"add", "203.0.113.0/24", "--reason", "x"},
		{"add", "not-an-ip", "--reason", "x"},
		{"add", "203.0.113.9", "--reason", ""},
	}
	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		if err := runCrowdsec(args, getenvMap(env), &stdout, &stderr); err == nil {
			t.Errorf("runCrowdsec(%v) returned no error", args)
		}
	}
	if *posted != 0 {
		t.Fatalf("posted = %d, want nothing posted for a usage error", *posted)
	}
}

func TestCrowdsecAddNotConfigured(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	var stdout, stderr bytes.Buffer
	err := runCrowdsec([]string{"add", "203.0.113.9", "--reason", "x"}, getenvMap(nil), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), crowdsec.EnvLAPIURL) {
		t.Fatalf("err = %v, want it to name %s", err, crowdsec.EnvLAPIURL)
	}
}

func TestCrowdsecAddHalfConfiguredRefuses(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	srv, posted := cliFakeLAPI(t)
	env := crowdsecEnv(t, srv)
	delete(env, crowdsec.EnvPasswordFile)
	var stdout, stderr bytes.Buffer
	err := runCrowdsec([]string{"add", "203.0.113.9", "--reason", "x"}, getenvMap(env), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), crowdsec.EnvPasswordFile) {
		t.Fatalf("err = %v, want it to name %s", err, crowdsec.EnvPasswordFile)
	}
	if *posted != 0 {
		t.Fatal("something was posted on a half-set configuration")
	}
}

func TestCrowdsecAddRefusesHTTPURL(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	srv, posted := cliFakeLAPI(t)
	env := crowdsecEnv(t, srv)
	env[crowdsec.EnvLAPIURL] = "http://" + strings.TrimPrefix(srv.URL, "https://")
	var stdout, stderr bytes.Buffer
	err := runCrowdsec([]string{"add", "203.0.113.9", "--reason", "x"}, getenvMap(env), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("err = %v, want the https refusal", err)
	}
	if *posted != 0 {
		t.Fatal("something was posted over http")
	}
}

func TestCrowdsecAddWrongPasswordIsRecordedNotLeaked(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	srv, posted := cliFakeLAPI(t)
	env := crowdsecEnv(t, srv)
	if err := os.WriteFile(env[crowdsec.EnvPasswordFile], []byte("wrong-password"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := runCrowdsec([]string{"add", "203.0.113.9", "--reason", "x"}, getenvMap(env), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v, want the 401", err)
	}
	if strings.Contains(err.Error(), "wrong-password") {
		t.Fatalf("error leaks the password: %v", err)
	}
	if *posted != 0 {
		t.Fatal("something was posted after a failed login")
	}
	database, err := openCanaryDB()
	if err != nil {
		t.Fatal(err)
	}
	defer closeCanaryDB(database)
	var action, reason string
	if err := database.QueryRow(`SELECT action, reason FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&action, &reason); err != nil {
		t.Fatalf("audit_log: %v", err)
	}
	if action != crowdsec.ActionFailed || strings.Contains(reason, "wrong-password") {
		t.Fatalf("audit row = %s %q", action, reason)
	}
}

func TestCrowdsecAddFloorRefusalNeverContactsTheLAPI(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	srv, posted := cliFakeLAPI(t)
	env := crowdsecEnv(t, srv)
	env[neverblock.EnvAllow] = "203.0.113.200"
	var stdout, stderr bytes.Buffer
	for _, ip := range []string{"192.168.1.1", "127.0.0.1", "203.0.113.200"} {
		err := runCrowdsec([]string{"add", ip, "--reason", "x"}, getenvMap(env), &stdout, &stderr)
		if err == nil || !strings.Contains(err.Error(), "never-block floor") {
			t.Fatalf("add %s: err = %v, want the floor refusal", ip, err)
		}
	}
	if *posted != 0 {
		t.Fatal("a floor address was posted")
	}
	database, err := openCanaryDB()
	if err != nil {
		t.Fatal(err)
	}
	defer closeCanaryDB(database)
	var n int
	if err := database.QueryRow(`SELECT count(*) FROM audit_log WHERE action = ?`, neverblock.AuditAction).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("floor refusal rows = %d, want 3", n)
	}
}

// TestCrowdsecCAPoolIsReallyUsed proves the CA file is what makes the
// connection trusted: with it pointed at some other certificate the
// command fails before login and nothing is posted.
func TestCrowdsecCAPoolIsReallyUsed(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	srv, posted := cliFakeLAPI(t)
	env := crowdsecEnv(t, srv)
	// Not a second httptest server: every httptest server presents Go's
	// one built-in test certificate, so "another server's CA" would be
	// the same bytes. A freshly generated, unrelated CA is what an
	// operator's typo would actually point at.
	otherCA := filepath.Join(t.TempDir(), "other.pem")
	if err := os.WriteFile(otherCA, []byte(unrelatedCAPEM(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	env[crowdsec.EnvCAFile] = otherCA
	var stdout, stderr bytes.Buffer
	err := runCrowdsec([]string{"add", "203.0.113.9", "--reason", "x"}, getenvMap(env), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "login") {
		t.Fatalf("err = %v, want a login-stage TLS failure", err)
	}
	if *posted != 0 {
		t.Fatal("something was posted with the wrong CA")
	}
}

// unrelatedCAPEM is a throwaway self-signed CA that signed nothing.
func unrelatedCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "unrelated"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
