package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/ca"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/history"
	"github.com/tomlawesome/birdcage/internal/mailbox"
	"github.com/tomlawesome/birdcage/internal/store"
	"github.com/tomlawesome/birdcage/internal/tlsconfig"
)

// discardLog is a logger tests can pass to any startup* function
// without polluting test output -- the shape settings_test.go and
// canary_test.go use for the CLI's own component loggers, applied here
// to the server-start path's.
func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// envMap turns a map into loadStartupConfig's getenv func(string)
// string, the same seam internal/mail.Load and internal/mailbox.Load
// already take -- unset keys read back as "".
func envMap(m map[string]string) func(string) string {
	return func(key string) string { return m[key] }
}

// mintTestCert generates a fresh self-signed ECDSA P-256 certificate
// for 127.0.0.1, the same recipe internal/tlsconfig's own reload_test.go
// uses -- reimplemented here rather than imported, since that helper is
// unexported and this package's tests stand on their own.
func mintTestCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "birdcage-test"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// testCA loads a fresh CA into a subdirectory of t.TempDir() that does
// not exist yet, so ca.Load creates it at the mode (0700) it requires
// rather than inheriting t.TempDir()'s own.
func testCA(t *testing.T) *ca.CA {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ca")
	c, _, err := ca.Load(dir, nil)
	if err != nil {
		t.Fatalf("ca.Load: %v", err)
	}
	return c
}

// openTestDB opens and migrates a fresh SQLite database, the same way
// openStartupDatabase does, for tests exercising code downstream of it
// that needs a real *db.DB rather than testing openStartupDatabase
// itself.
func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "birdcage-startup-test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := db.Migrate(context.Background(), database); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	return database
}

// freeLoopbackAddr reserves an ephemeral loopback TCP port and releases
// it immediately, for a test that needs to know a specific address is
// very likely free before handing it to code that binds it itself
// (serveAll's dashboard path does its own net.Listen internally, so
// there's no listener to hand it directly).
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a loopback port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved port: %v", err)
	}
	return addr
}

// --- runSubcommand ---------------------------------------------------

func TestRunSubcommand(t *testing.T) {
	t.Run("version writes one line to stdout and is handled", func(t *testing.T) {
		var buf bytes.Buffer
		handled, exitCode := runSubcommand([]string{"birdcage", "version"}, &buf)
		if !handled || exitCode != 0 {
			t.Fatalf("runSubcommand(version) = handled=%v exitCode=%d, want true, 0", handled, exitCode)
		}
		if strings.TrimSpace(buf.String()) != version {
			t.Errorf("stdout = %q, want %q", buf.String(), version)
		}
	})

	t.Run("canary with no subcommand is handled with exit 1", func(t *testing.T) {
		handled, exitCode := runSubcommand([]string{"birdcage", "canary"}, io.Discard)
		if !handled || exitCode != 1 {
			t.Fatalf("runSubcommand(canary) = handled=%v exitCode=%d, want true, 1", handled, exitCode)
		}
	})

	t.Run("unknown settings subcommand is handled with exit 1", func(t *testing.T) {
		t.Setenv(envDBPath, testDBPath(t))
		handled, exitCode := runSubcommand([]string{"birdcage", "settings", "x"}, io.Discard)
		if !handled || exitCode != 1 {
			t.Fatalf("runSubcommand(settings x) = handled=%v exitCode=%d, want true, 1", handled, exitCode)
		}
	})

	t.Run("no args is not handled", func(t *testing.T) {
		handled, _ := runSubcommand([]string{"birdcage"}, io.Discard)
		if handled {
			t.Fatalf("runSubcommand(no args) handled = true, want false")
		}
	})
}

// --- loadStartupConfig ------------------------------------------------

func TestLoadStartupConfigDefaults(t *testing.T) {
	cfg, err := loadStartupConfig(envMap(nil), discardLog(), discardLog(), discardLog(), discardLog())
	if err != nil {
		t.Fatalf("loadStartupConfig: %v", err)
	}
	if cfg.dbPath != defaultDBPath {
		t.Errorf("dbPath = %q, want %q", cfg.dbPath, defaultDBPath)
	}
	if cfg.httpAddr != defaultHTTPAddr {
		t.Errorf("httpAddr = %q, want %q", cfg.httpAddr, defaultHTTPAddr)
	}
	if cfg.caDir != defaultCADir {
		t.Errorf("caDir = %q, want %q", cfg.caDir, defaultCADir)
	}
	if cfg.enrolAddr != defaultEnrolAddr {
		t.Errorf("enrolAddr = %q, want %q", cfg.enrolAddr, defaultEnrolAddr)
	}
	// The default address has no certificate and a non-loopback (empty)
	// host, so it mints its own certificate (issue #63) -- and needs a
	// CA to do it.
	if cfg.httpSelection.Mode != tlsconfig.ModeMintedCert {
		t.Errorf("httpSelection.Mode = %v, want ModeMintedCert", cfg.httpSelection.Mode)
	}
	if !cfg.caNeeded {
		t.Errorf("caNeeded = false, want true (dashboard mints its own certificate)")
	}
}

func TestLoadStartupConfigHTTPAddrUnparseable(t *testing.T) {
	_, err := loadStartupConfig(envMap(map[string]string{envHTTPAddr: "127.0.0.1"}), discardLog(), discardLog(), discardLog(), discardLog())
	if err == nil {
		t.Fatal("loadStartupConfig with an unparseable BIRDCAGE_HTTP_ADDR = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), "tlsconfig:") {
		t.Errorf("error = %q, want tlsconfig's own refusal text", err.Error())
	}
}

func TestLoadStartupConfigCertWithoutKey(t *testing.T) {
	_, err := loadStartupConfig(envMap(map[string]string{envHTTPTLSCert: "/etc/birdcage/cert.pem"}), discardLog(), discardLog(), discardLog(), discardLog())
	if err == nil {
		t.Fatal("loadStartupConfig with cert but no key = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), "must both be set or both unset") {
		t.Errorf("error = %q, want tlsconfig's cert/key refusal", err.Error())
	}
}

func TestLoadStartupConfigBadInternalRanges(t *testing.T) {
	_, err := loadStartupConfig(envMap(map[string]string{envInternalRanges: "not-a-cidr"}), discardLog(), discardLog(), discardLog(), discardLog())
	if err == nil {
		t.Fatal("loadStartupConfig with a bad BIRDCAGE_INTERNAL_RANGES = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), envInternalRanges) {
		t.Errorf("error = %q, want it to name %s", err.Error(), envInternalRanges)
	}
}

func TestLoadStartupConfigBadIngestAddrWithAdvertiseHost(t *testing.T) {
	_, err := loadStartupConfig(envMap(map[string]string{
		envIngestAddr:    "bad",
		envAdvertiseHost: "canary.example.net",
	}), discardLog(), discardLog(), discardLog(), discardLog())
	if err == nil {
		t.Fatal("loadStartupConfig with a bad BIRDCAGE_INGEST_ADDR = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), "is not a valid address") {
		t.Errorf("error = %q, want the ingest address refusal", err.Error())
	}
}

func TestLoadStartupConfigIngestURL(t *testing.T) {
	cfg, err := loadStartupConfig(envMap(map[string]string{
		envIngestAddr:    ":8443",
		envAdvertiseHost: "canary.example.net",
	}), discardLog(), discardLog(), discardLog(), discardLog())
	if err != nil {
		t.Fatalf("loadStartupConfig: %v", err)
	}
	if want := "https://canary.example.net:8443"; cfg.ingestURL != want {
		t.Errorf("ingestURL = %q, want %q", cfg.ingestURL, want)
	}
}

// --- checkStartupFiles / checkStartupDatabase --------------------------

func TestCheckStartupFilesMissingDataDir(t *testing.T) {
	cfg := startupConfig{dbPath: filepath.Join(t.TempDir(), "missing", "birdcage.db")}
	err := checkStartupFiles(cfg, discardLog(), discardLog())
	if err == nil {
		t.Fatal("checkStartupFiles with a missing data directory = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), "is not usable by this process") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "is not usable by this process")
	}
}

func TestCheckStartupFilesModeCertMissingCert(t *testing.T) {
	cfg := startupConfig{
		dbPath:      testDBPath(t),
		httpTLSCert: filepath.Join(t.TempDir(), "does-not-exist.pem"),
		httpTLSKey:  filepath.Join(t.TempDir(), "does-not-exist-key.pem"),
	}
	cfg.httpSelection = tlsconfig.Selection{Mode: tlsconfig.ModeCert}
	err := checkStartupFiles(cfg, discardLog(), discardLog())
	if err == nil {
		t.Fatal("checkStartupFiles with a missing cert file = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), "is not usable by this process") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "is not usable by this process")
	}
}

func TestCheckStartupDatabasePostgresWithoutVerifyFull(t *testing.T) {
	cfg := startupConfig{databaseURL: "postgres://u:p@host:5432/db?sslmode=disable"}
	err := checkStartupDatabase(cfg)
	if err == nil {
		t.Fatal("checkStartupDatabase with sslmode=disable = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), "sslmode=verify-full") {
		t.Errorf("error = %q, want it to name the fix (sslmode=verify-full)", err.Error())
	}
}

// --- loadStartupCA ------------------------------------------------------

func TestLoadStartupCANotNeeded(t *testing.T) {
	cfg := startupConfig{caNeeded: false}
	got, err := loadStartupCA(cfg, discardLog())
	if err != nil {
		t.Fatalf("loadStartupCA: %v", err)
	}
	if got != nil {
		t.Errorf("loadStartupCA(caNeeded=false) = %v, want nil", got)
	}
}

func TestLoadStartupCACreated(t *testing.T) {
	cfg := startupConfig{caNeeded: true, caDir: filepath.Join(t.TempDir(), "ca")}
	got, err := loadStartupCA(cfg, discardLog())
	if err != nil {
		t.Fatalf("loadStartupCA: %v", err)
	}
	if got == nil {
		t.Fatal("loadStartupCA(caNeeded=true) = nil, want a *ca.CA")
	}
	if got.Pin() == "" {
		t.Errorf("loadStartupCA's CA has an empty pin")
	}
}

func TestLoadStartupCAUnwritableDir(t *testing.T) {
	dir := t.TempDir()
	// ca.Load requires an existing directory to already be mode 0700;
	// t.TempDir() is not guaranteed to be, and this leaves it at a mode
	// ca.Load refuses either way.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	cfg := startupConfig{caNeeded: true, caDir: dir}
	_, err := loadStartupCA(cfg, discardLog())
	if err == nil {
		t.Fatal("loadStartupCA with a wrongly-permissioned dir = nil error, want a refusal")
	}
}

// --- openStartupDatabase -------------------------------------------------

func TestOpenStartupDatabaseOpensAndMigrates(t *testing.T) {
	cfg := startupConfig{databaseURL: filepath.Join(t.TempDir(), "birdcage.db")}
	database, err := openStartupDatabase(context.Background(), cfg, discardLog())
	if err != nil {
		t.Fatalf("openStartupDatabase: %v", err)
	}
	defer database.Close()
	if database.Engine != db.SQLite {
		t.Errorf("Engine = %v, want SQLite", database.Engine)
	}
}

func TestOpenStartupDatabaseUnopenablePathErrors(t *testing.T) {
	cfg := startupConfig{databaseURL: filepath.Join(t.TempDir(), "no-such-directory", "birdcage.db")}
	_, err := openStartupDatabase(context.Background(), cfg, discardLog())
	if err == nil {
		t.Fatal("openStartupDatabase with an unopenable path = nil error, want a refusal")
	}
}

// --- runHistoryLoop / runApprovalLoop ------------------------------------

func TestRunHistoryLoopReturnsOnCancel(t *testing.T) {
	database := openTestDB(t)
	recorder := history.NewWithTokenConflictHook(database, nil)
	if err := recorder.Start(context.Background(), time.Now().UTC()); err != nil {
		t.Fatalf("recorder.Start: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runHistoryLoop(ctx, recorder, nil, 5*time.Millisecond, discardLog(), discardLog())
		close(done)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runHistoryLoop did not return within 2s of ctx cancellation")
	}
}

func TestRunApprovalLoopReturnsOnCancel(t *testing.T) {
	// No real IMAP server is reachable here, so every poll's dial fails
	// (fast: port 1 on loopback refuses immediately) and handle is
	// never actually exercised -- this only proves the loop itself
	// returns promptly once ctx is canceled.
	reader := mailbox.New(mailbox.Config{Host: "127.0.0.1:1", Username: "x", Mailbox: "INBOX"}, discardLog())
	handle := func(context.Context, []byte) error { return nil }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runApprovalLoop(ctx, reader, handle, 5*time.Millisecond, discardLog())
		close(done)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runApprovalLoop did not return within 2s of ctx cancellation")
	}
}

// --- buildDashboardServer -------------------------------------------------

func TestBuildDashboardServerModeCert(t *testing.T) {
	certPath, keyPath := mintTestCert(t)
	cfg := startupConfig{
		httpTLSCert:   certPath,
		httpTLSKey:    keyPath,
		httpSelection: tlsconfig.Selection{Mode: tlsconfig.ModeCert, Addr: "127.0.0.1:0"},
	}
	srv, unixPath, err := buildDashboardServer(cfg, nil, http.NotFoundHandler(), discardLog(), discardLog())
	if err != nil {
		t.Fatalf("buildDashboardServer: %v", err)
	}
	if srv.Addr != cfg.httpSelection.Addr {
		t.Errorf("Addr = %q, want %q", srv.Addr, cfg.httpSelection.Addr)
	}
	if srv.TLSConfig == nil {
		t.Error("TLSConfig = nil, want a configured TLS config")
	}
	if unixPath != "" {
		t.Errorf("unixPath = %q, want empty", unixPath)
	}
}

func TestBuildDashboardServerModeMintedCert(t *testing.T) {
	birdcageCA := testCA(t)
	cfg := startupConfig{
		httpSelection: tlsconfig.Selection{Mode: tlsconfig.ModeMintedCert, Addr: "0.0.0.0:8080"},
	}
	srv, unixPath, err := buildDashboardServer(cfg, birdcageCA, http.NotFoundHandler(), discardLog(), discardLog())
	if err != nil {
		t.Fatalf("buildDashboardServer: %v", err)
	}
	if srv.Addr != cfg.httpSelection.Addr {
		t.Errorf("Addr = %q, want %q", srv.Addr, cfg.httpSelection.Addr)
	}
	if srv.TLSConfig == nil {
		t.Error("TLSConfig = nil, want a configured TLS config")
	}
	if unixPath != "" {
		t.Errorf("unixPath = %q, want empty", unixPath)
	}
}

func TestBuildDashboardServerModePlainLoopbackTCP(t *testing.T) {
	cfg := startupConfig{
		httpSelection: tlsconfig.Selection{Mode: tlsconfig.ModePlainLoopbackTCP, Addr: "127.0.0.1:8080"},
	}
	srv, unixPath, err := buildDashboardServer(cfg, nil, http.NotFoundHandler(), discardLog(), discardLog())
	if err != nil {
		t.Fatalf("buildDashboardServer: %v", err)
	}
	if srv.Addr != cfg.httpSelection.Addr {
		t.Errorf("Addr = %q, want %q", srv.Addr, cfg.httpSelection.Addr)
	}
	if srv.TLSConfig != nil {
		t.Error("TLSConfig != nil, want nil for plain HTTP")
	}
	if unixPath != "" {
		t.Errorf("unixPath = %q, want empty", unixPath)
	}
}

func TestBuildDashboardServerModePlainUnixSocket(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "http.sock")
	cfg := startupConfig{
		httpSelection: tlsconfig.Selection{Mode: tlsconfig.ModePlainUnixSocket, UnixPath: sockPath},
	}
	srv, unixPath, err := buildDashboardServer(cfg, nil, http.NotFoundHandler(), discardLog(), discardLog())
	if err != nil {
		t.Fatalf("buildDashboardServer: %v", err)
	}
	if srv.Addr != "" {
		t.Errorf("Addr = %q, want empty for a unix socket", srv.Addr)
	}
	if unixPath != sockPath {
		t.Errorf("unixPath = %q, want %q", unixPath, sockPath)
	}
}

func TestBuildDashboardServerDashboardHostExplicitlyEmpty(t *testing.T) {
	birdcageCA := testCA(t)
	cfg := startupConfig{
		httpSelection:    tlsconfig.Selection{Mode: tlsconfig.ModeMintedCert, Addr: "0.0.0.0:8080"},
		dashboardHostEnv: ",,", // trims to no names at all
	}
	_, _, err := buildDashboardServer(cfg, birdcageCA, http.NotFoundHandler(), discardLog(), discardLog())
	if err == nil {
		t.Fatal("buildDashboardServer with an explicit-and-empty BIRDCAGE_DASHBOARD_HOST = nil error, want a refusal")
	}
}

// --- buildIngestServers -------------------------------------------------

func TestBuildIngestServersOff(t *testing.T) {
	cfg := startupConfig{}
	ingestSrv, enrolSrv, err := buildIngestServers(cfg, nil, nil, nil, nil, nil, discardLog(), discardLog(), discardLog())
	if err != nil {
		t.Fatalf("buildIngestServers: %v", err)
	}
	if ingestSrv != nil || enrolSrv != nil {
		t.Errorf("buildIngestServers(ingest off) = %v, %v, want nil, nil", ingestSrv, enrolSrv)
	}
}

func TestBuildIngestServersOn(t *testing.T) {
	birdcageCA := testCA(t)
	database := openTestDB(t)
	cfg := startupConfig{
		ingestAddr: "127.0.0.1:18443",
		enrolAddr:  "127.0.0.1:18444",
	}
	idx := store.NewSelfTestIndex()
	ingestSrv, enrolSrv, err := buildIngestServers(cfg, database, birdcageCA, nil, idx, nil, discardLog(), discardLog(), discardLog())
	if err != nil {
		t.Fatalf("buildIngestServers: %v", err)
	}
	if ingestSrv == nil || enrolSrv == nil {
		t.Fatalf("buildIngestServers(ingest on) = %v, %v, want both non-nil", ingestSrv, enrolSrv)
	}
	if ingestSrv.Addr != cfg.ingestAddr {
		t.Errorf("ingestSrv.Addr = %q, want %q", ingestSrv.Addr, cfg.ingestAddr)
	}
	if enrolSrv.Addr != cfg.enrolAddr {
		t.Errorf("enrolSrv.Addr = %q, want %q", enrolSrv.Addr, cfg.enrolAddr)
	}
}

// --- serveAll -------------------------------------------------------------

func TestServeAllReturnsNilOnCleanShutdown(t *testing.T) {
	addr := freeLoopbackAddr(t)
	dashboard := &http.Server{Addr: addr, Handler: http.NotFoundHandler()}
	ctx, stop := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- serveAll(ctx, stop, dashboard, tlsconfig.ModePlainLoopbackTCP, "", nil, nil, discardLog(), discardLog(), discardLog(), discardLog())
	}()

	// Poll until the listener is actually accepting connections, then
	// cancel -- no fixed sleep guessing how long ListenAndServe takes
	// to bind.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	stop()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serveAll after a clean shutdown = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveAll did not return within 2s of ctx cancellation")
	}
}

func TestServeAllReturnsErrorOnBindFailure(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a loopback port: %v", err)
	}
	defer blocker.Close()

	dashboard := &http.Server{Addr: blocker.Addr().String(), Handler: http.NotFoundHandler()}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	done := make(chan error, 1)
	go func() {
		done <- serveAll(ctx, stop, dashboard, tlsconfig.ModePlainLoopbackTCP, "", nil, nil, discardLog(), discardLog(), discardLog(), discardLog())
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Error("serveAll on an already-bound address = nil error, want a refusal")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveAll did not return within 2s of a bind failure")
	}
}

// --- logStartupError / startupError ---------------------------------------

// TestLogStartupErrorUsesNamedLogger proves the *startupError plumbing
// itself: the refusal is logged on the logger it names, not a fixed
// one, which is what lets checkStartupFiles and loadStartupConfig share
// one error type across refusals that belong on different component
// loggers.
func TestLogStartupErrorUsesNamedLogger(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex
	log := slog.New(slog.NewTextHandler(&syncWriter{&buf, &mu}, nil))

	err := &startupError{log: log, msg: "sentinel refusal text"}
	logStartupError(err)

	mu.Lock()
	got := buf.String()
	mu.Unlock()
	if !strings.Contains(got, "sentinel refusal text") {
		t.Errorf("log output = %q, want it to contain the refusal text", got)
	}
}

// TestLogStartupErrorIgnoresPlainErrors proves logStartupError is a
// no-op for an error that isn't a *startupError (e.g. errServeFailed),
// rather than panicking on a failed type assertion.
func TestLogStartupErrorIgnoresPlainErrors(t *testing.T) {
	logStartupError(errors.New("not a startupError"))
	logStartupError(nil)
}

type syncWriter struct {
	buf *bytes.Buffer
	mu  *sync.Mutex
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}
