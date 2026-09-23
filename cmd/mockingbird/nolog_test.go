package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/logging"
)

// This file is #71's regression test for cmd/mockingbird's own package
// doc comment (main.go): the token, any certificate's path or content,
// the receiver's listen address, the log path and the state directory
// must never appear in this agent's log output, at any level. Every
// sub-test here builds a fake Config with distinctive, known-secret
// values (see config_test.go's writeStateDir/setValidEnv for the same
// pattern this package's other tests already use) and proves none of
// them survive into what actually gets logged or returned as an error
// string -- the two places a value could leak into an operator's
// terminal or a log collector.
//
// #47 extends the same never-log list with two values boot's own Config
// never carries at all -- the deploy token and the enrolment secret only
// ever exist transiently, inside loadConfig's own ensureEnrolled/
// enrolAtBoot (enrol.go) -- so TestEnrolAtBootLifecycle below drives
// loadConfig itself, the only path that ever sees either.

// genSelfSignedKeyPair returns a freshly generated ECDSA private key's
// PEM bytes alongside a self-signed certificate PEM for it -- enough
// for client.New to accept as both CACert (any parseable certificate)
// and a matched ClientCert/ClientKey pair (tls.X509KeyPair only checks
// the public/private key match, not that the cert is CA-signed).
func genSelfSignedKeyPair(t *testing.T, commonName string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// fakeConfig builds a Config whose every value is distinctive enough
// that its accidental appearance in log output could not be mistaken
// for anything else -- StateDir and LogPath come from t.TempDir(),
// already unique per test, and the token/cert material is freshly
// generated per call.
func fakeConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()

	caCert, _ := genSelfSignedKeyPair(t, "nolog-test-ca")
	clientCert, clientKey := genSelfSignedKeyPair(t, "nolog-test-client")

	token := "sentinel-token-do-not-log-9f8e7d6c5b4a3210"
	tokenPath := filepath.Join(dir, tokenFileName)
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	return Config{
		BirdcageURL:  "https://birdcage.invalid:8443",
		StateDir:     dir,
		LogPath:      filepath.Join(dir, "opencanary.json"),
		Listen:       "127.0.0.1:0",
		CACert:       caCert,
		ClientCert:   clientCert,
		ClientKey:    clientKey,
		TokenPath:    tokenPath,
		PositionPath: filepath.Join(dir, positionFileName),
	}
}

// TestBootNeverLogsSensitiveValues runs boot -- the startup path main
// runs before entering its blocking service loops (client, token store,
// intake, then the "started" log line) -- against a fake config, and
// proves none of #71's never-log values reach stdout: not the token
// content, not either certificate's PEM bytes, not the log path or
// state directory, and not the receiver's own bound listen address
// (read back from the real *Intake boot returns, since cfg.Listen's
// "127.0.0.1:0" itself is too generic a string to prove anything).
func TestBootNeverLogsSensitiveValues(t *testing.T) {
	cfg := fakeConfig(t)

	var in *Intake
	var bootErr error
	out := captureStdout(t, func() {
		_, _, in, bootErr = boot(cfg, "9.9.9", logging.New("test"))
	})
	t.Cleanup(func() {
		if in != nil {
			_ = in.Receiver.Close()
		}
	})
	if bootErr != nil {
		t.Fatalf("boot: %v", bootErr)
	}

	if !strings.Contains(out, "started") {
		t.Fatalf("captured output = %q, want it to contain the startup line", out)
	}

	boundAddr := in.Receiver.Addr().String()
	never := map[string]string{
		"token":               "sentinel-token-do-not-log-9f8e7d6c5b4a3210",
		"CA cert PEM":         string(cfg.CACert),
		"client cert PEM":     string(cfg.ClientCert),
		"client key PEM":      string(cfg.ClientKey),
		"log path":            cfg.LogPath,
		"state directory":     cfg.StateDir,
		"receiver bound addr": boundAddr,
		"token path":          cfg.TokenPath,
		"position path":       cfg.PositionPath,
	}
	for name, secret := range never {
		if strings.Contains(out, secret) {
			t.Errorf("captured output contains the %s (%q) -- must never be logged:\n%s", name, secret, out)
		}
	}
}

// TestBootRefusesOnEachDependencyFailure drives all three of boot's
// error returns -- client.New, loadTokenStore and NewIntake, in that
// order -- each by breaking exactly one otherwise-valid fakeConfig
// field, proving boot stops and names which step failed rather than
// continuing past a broken dependency. Every failure here is a pure
// validation check (no real network dial), so this needs no fake server.
func TestBootRefusesOnEachDependencyFailure(t *testing.T) {
	t.Run("client.New", func(t *testing.T) {
		cfg := fakeConfig(t)
		cfg.BirdcageURL = "" // client.New's own first check
		_, _, in, err := boot(cfg, "9.9.9", logging.New("test"))
		if in != nil {
			t.Cleanup(func() { _ = in.Receiver.Close() })
		}
		if err == nil {
			t.Fatal("boot succeeded with an empty BirdcageURL, want an error")
		}
		if !strings.Contains(err.Error(), "build birdcage client") {
			t.Errorf("boot error = %q, want it to name the birdcage-client step", err.Error())
		}
	})

	t.Run("loadTokenStore", func(t *testing.T) {
		cfg := fakeConfig(t)
		cfg.TokenPath = filepath.Join(t.TempDir(), "no-such-token")
		_, _, in, err := boot(cfg, "9.9.9", logging.New("test"))
		if in != nil {
			t.Cleanup(func() { _ = in.Receiver.Close() })
		}
		if err == nil {
			t.Fatal("boot succeeded with a missing token file, want an error")
		}
		if !strings.Contains(err.Error(), "load token") {
			t.Errorf("boot error = %q, want it to name the load-token step", err.Error())
		}
	})

	t.Run("NewIntake", func(t *testing.T) {
		cfg := fakeConfig(t)
		cfg.Listen = "8.8.8.8:0" // requireLoopback refuses any non-loopback host
		_, _, in, err := boot(cfg, "9.9.9", logging.New("test"))
		if in != nil {
			t.Cleanup(func() { _ = in.Receiver.Close() })
		}
		if err == nil {
			t.Fatal("boot succeeded with a non-loopback Listen address, want an error")
		}
		if !strings.Contains(err.Error(), "build intake") {
			t.Errorf("boot error = %q, want it to name the build-intake step", err.Error())
		}
	})
}

// TestLoadConfigErrorNeverLeaksStateDirPath is config.go's own half of
// the same guarantee: an unreadable state-dir file is a startup failure
// (see config_test.go's TestLoadConfigMissingCACert), and the error
// that produces must name the file by its bare name only, never by the
// real path underneath it -- safeErr (safelog.go) is what strips that.
func TestLoadConfigErrorNeverLeaksStateDirPath(t *testing.T) {
	dir := writeStateDir(t)
	if err := os.Remove(filepath.Join(dir, caFileName)); err != nil {
		t.Fatalf("remove %s: %v", caFileName, err)
	}
	setValidEnv(t, dir)

	_, err := loadConfig()
	if err == nil {
		t.Fatal("loadConfig succeeded with ca.pem missing")
	}
	if strings.Contains(err.Error(), dir) {
		t.Fatalf("loadConfig error = %q, leaks the state directory path %q", err, dir)
	}
	if !strings.Contains(err.Error(), caFileName) {
		t.Fatalf("loadConfig error = %q, want it to still name %s", err, caFileName)
	}
}

// TestLoadTokenStoreErrorNeverLeaksStateDirPath is loadTokenStore's own
// version of the same guarantee, for the token file specifically.
func TestLoadTokenStoreErrorNeverLeaksStateDirPath(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, tokenFileName)

	_, err := loadTokenStore(tokenPath)
	if err == nil {
		t.Fatal("loadTokenStore succeeded with no token file present")
	}
	if strings.Contains(err.Error(), dir) {
		t.Fatalf("loadTokenStore error = %q, leaks the state directory path %q", err, dir)
	}
}

// Sentinel values for TestEnrolAtBootLifecycle -- distinctive enough that
// their accidental appearance in captured output could not be mistaken
// for anything else, the same shape fakeConfig's own token above uses.
const (
	testDeployToken     = "sentinel-deploy-token-do-not-log-1a2b3c4d5e6f"
	testEnrolmentSecret = "sentinel-enrolment-secret-do-not-log-7g8h9i0j"
	testCanaryToken     = "sentinel-canary-token-do-not-log-9j0k1l2m3n4o"
)

// genEnrolTestCA and genEnrolTestLeaf build a minimal CA/leaf pair via
// crypto/x509 directly -- this package must never import internal/ca
// (scripts/agent-deps-check.sh's fence), and internal/agent/enrol's own
// equivalent test helpers are unexported, so this is its own small copy of
// the same shape, not a shared one.
func genEnrolTestCA(t *testing.T) (der []byte, cert *x509.Certificate, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mockingbird-lifecycle-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return der, cert, key
}

func genEnrolTestLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (der []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "mockingbird-lifecycle-test-leaf"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	return der, key
}

// newFakeEnrolServer is a minimal stand-in for birdcage's enrolment
// listener (internal/enrol's own POST /enrol/hello and POST
// /enrol/provision), just enough to drive loadConfig's ensureEnrolled/
// enrolAtBoot end to end against the ratified wire contract, without
// depending on internal/enrol itself. helloHits and provisionHits count
// how many times each route was actually reached, so a second boot can be
// proven not to have contacted either again.
func newFakeEnrolServer(t *testing.T) (ts *httptest.Server, pin string, helloHits, provisionHits *int32) {
	t.Helper()
	caDER, caCert, caKey := genEnrolTestCA(t)
	leafDER, leafKey := genEnrolTestLeaf(t, caCert, caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	var hello, provision int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /enrol/hello", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hello, 1)
		var req struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Token != testDeployToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"refused"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"enrolment_secret":       testEnrolmentSecret,
			"ca_pem":                 string(caPEM),
			"ingest_url":             "https://ingest.invalid:8443",
			"window_deadline":        time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339),
			"admin_approval_address": "admin@example.com",
			"release_address":        "release@example.com",
		})
	})
	mux.HandleFunc("POST /enrol/provision", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&provision, 1)
		var req struct {
			EnrolmentSecret string `json:"enrolment_secret"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.EnrolmentSecret != testEnrolmentSecret {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"refused"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"canary_id":            "canary-lifecycle-1",
			"canary_token":         testCanaryToken,
			"client_cert_pem":      "PLACEHOLDER-CLIENT-CERT-PEM-CONTENT",
			"client_key_pem":       "PLACEHOLDER-CLIENT-KEY-PEM-CONTENT",
			"heartbeat_interval_s": 30,
		})
	})

	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafDER, caDER},
			PrivateKey:  leafKey,
		}},
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	sum := sha256.Sum256(caDER)
	return server, hex.EncodeToString(sum[:]), &hello, &provision
}

// TestEnrolAtBootLifecycle is #47's own version of
// TestBootNeverLogsSensitiveValues, run one layer up: against loadConfig
// itself, the only path that ever sees the deploy token or the enrolment
// secret at all. It also proves the lifecycle rule #47 exists for:
// enrolment happens once, and a second boot against the same, now-enrolled
// state directory does not contact birdcage's enrolment endpoints again.
func TestEnrolAtBootLifecycle(t *testing.T) {
	ts, pin, helloHits, provisionHits := newFakeEnrolServer(t)

	dir := t.TempDir()
	t.Setenv(envBirdcageURL, ts.URL)
	t.Setenv(envStateDir, dir)
	t.Setenv(envLogPath, filepath.Join(dir, "opencanary.json"))
	t.Setenv(envListen, "127.0.0.1:0")
	t.Setenv(envCAPin, pin)
	t.Setenv(envDeployToken, testDeployToken)

	var cfg Config
	var err error
	out := captureStdout(t, func() {
		cfg, err = loadConfig()
	})
	if err != nil {
		t.Fatalf("loadConfig (first boot): %v", err)
	}

	never := map[string]string{
		"deploy token":     testDeployToken,
		"enrolment secret": testEnrolmentSecret,
		"canary token":     testCanaryToken,
		"client key PEM":   "PLACEHOLDER-CLIENT-KEY-PEM-CONTENT",
		"state directory":  dir,
	}
	for name, secret := range never {
		if strings.Contains(out, secret) {
			t.Errorf("first boot's captured output contains the %s (%q) -- must never be logged:\n%s", name, secret, out)
		}
	}

	if got, want := atomic.LoadInt32(helloHits), int32(1); got != want {
		t.Errorf("hello hits = %d, want %d", got, want)
	}
	if got, want := atomic.LoadInt32(provisionHits), int32(1); got != want {
		t.Errorf("provision hits = %d, want %d", got, want)
	}
	if cfg.BirdcageURL != "https://ingest.invalid:8443" {
		t.Errorf("Config.BirdcageURL = %q, want the ingest_url hello returned", cfg.BirdcageURL)
	}

	allFiles := append(append([]string{}, enrolStateFiles...),
		ingestURLFileName, adminApprovalAddressFileName, releaseAddressFileName)
	for _, name := range allFiles {
		info, statErr := os.Stat(filepath.Join(dir, name))
		if statErr != nil {
			t.Fatalf("stat %s: %v", name, statErr)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, want 0600", name, perm)
		}
	}

	// Second boot: same env, same now-enrolled state directory. Must not
	// contact either enrolment endpoint again, and must log the
	// "already enrolled" line without ever naming the ignored token.
	out2 := captureStdout(t, func() {
		_, err = loadConfig()
	})
	if err != nil {
		t.Fatalf("loadConfig (second boot): %v", err)
	}
	if got, want := atomic.LoadInt32(helloHits), int32(1); got != want {
		t.Errorf("hello hits after second boot = %d, want still %d (enrolment must not repeat)", got, want)
	}
	if got, want := atomic.LoadInt32(provisionHits), int32(1); got != want {
		t.Errorf("provision hits after second boot = %d, want still %d (enrolment must not repeat)", got, want)
	}
	if !strings.Contains(out2, "already enrolled") {
		t.Errorf("second boot's output = %q, want it to mention already being enrolled", out2)
	}
	for name, secret := range never {
		if strings.Contains(out2, secret) {
			t.Errorf("second boot's captured output contains the %s (%q) -- must never be logged:\n%s", name, secret, out2)
		}
	}
}
