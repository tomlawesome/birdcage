package enrolment

import (
	"bytes"
	"context"
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
	"errors"
	"log/slog"
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

	"github.com/tomlawesome/birdcage/internal/agent/certkey"
	"github.com/tomlawesome/birdcage/internal/agent/enrol"
)

// This file builds its own certificate chains by hand, via crypto/x509
// directly, the same shape cmd/mockingbird/nolog_test.go and
// internal/agent/enrol's own tests use -- internal/agent/enrol's helpers
// are unexported, so each caller keeps a small copy rather than sharing
// one.

func genCA(t *testing.T, cn string) (der []byte, cert *x509.Certificate, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
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

func genLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (der []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "enrolment-test-leaf"},
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

func pinFor(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// newFakeEnrolServer stands in for birdcage's enrolment listener (POST
// /enrol/hello, POST /enrol/provision), just enough to drive
// EnsureEnrolled end to end against the ratified wire contract.
func newFakeEnrolServer(t *testing.T, deployToken, enrolmentSecret string) (ts *httptest.Server, pin string, helloHits, provisionHits *int32) {
	t.Helper()
	caDER, caCert, caKey := genCA(t, "enrolment-test-ca")
	leafDER, leafKey := genLeaf(t, caCert, caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	var hello, provision int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /enrol/hello", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hello, 1)
		var req struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Token != deployToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"refused"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"enrolment_secret":       enrolmentSecret,
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
			CSRPEM          string `json:"csr_pem"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.EnrolmentSecret != enrolmentSecret {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"refused"}`))
			return
		}
		// ADR-0012 B1: birdcage never sees a private key, only a CSR --
		// prove this fake server (and therefore EnsureEnrolled's own
		// request) really carries one, and never a client_key_pem in the
		// response.
		block, _ := pem.Decode([]byte(req.CSRPEM))
		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"missing or invalid csr_pem"}`))
			return
		}
		if _, err := x509.ParseCertificateRequest(block.Bytes); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"unparseable csr_pem"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"canary_id":            "node-lifecycle-1",
			"canary_token":         "test-canary-token",
			"client_cert_pem":      "PLACEHOLDER-CLIENT-CERT-PEM",
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

	return server, pinFor(caDER), &hello, &provision
}

// testParams builds a Params against dir, capturing every state file
// EnsureEnrolled writes as a []StateFile the way a real caller's
// WriteState would.
func testParams(t *testing.T, dir string) Params {
	t.Helper()
	var buf bytes.Buffer
	return Params{
		StateDir:           dir,
		DeployTokenEnvName: "TEST_DEPLOY_TOKEN",
		RequiredFiles:      []string{"ca.pem", "client.pem", "client-key.pem", "token"},
		NodeNoun:           "canary",
		WriteState: func(hello enrol.Hello, creds enrol.Credentials, keyPEM []byte) []StateFile {
			return []StateFile{
				{Name: "ca.pem", Data: hello.CAPEM},
				{Name: "client.pem", Data: creds.ClientCertPEM},
				{Name: "client-key.pem", Data: keyPEM},
				{Name: "token", Data: []byte(creds.CanaryToken)},
				{Name: "ingest-url", Data: []byte(hello.IngestURL)},
			}
		},
		Log: slog.New(slog.NewTextHandler(&buf, nil)),
	}
}

// TestEnsureEnrolledFullLifecycle proves the happy path end to end: a
// fresh state directory enrols against a real fake server, writes every
// file WriteState names at 0600, and a second call against the
// now-enrolled directory does not contact either endpoint again.
func TestEnsureEnrolledFullLifecycle(t *testing.T) {
	ts, pin, helloHits, provisionHits := newFakeEnrolServer(t, "deploy-tok", "enrol-secret")
	dir := t.TempDir()

	p := testParams(t, dir)
	p.BirdcageURL = ts.URL
	p.CAPin = pin
	p.DeployToken = "deploy-tok"

	if err := EnsureEnrolled(context.Background(), p); err != nil {
		t.Fatalf("EnsureEnrolled (first boot): %v", err)
	}
	if got, want := atomic.LoadInt32(helloHits), int32(1); got != want {
		t.Errorf("hello hits = %d, want %d", got, want)
	}
	if got, want := atomic.LoadInt32(provisionHits), int32(1); got != want {
		t.Errorf("provision hits = %d, want %d", got, want)
	}

	for _, name := range []string{"ca.pem", "client.pem", "client-key.pem", "token", "ingest-url"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, want 0600", name, perm)
		}
	}
	// ADR-0012 B1: the client key on disk is the agent's own, never
	// something birdcage sent -- it must parse as a real ECDSA key, and
	// the staging file must be gone once enrolment has folded it into
	// client-key.pem.
	keyPEM, err := os.ReadFile(filepath.Join(dir, "client-key.pem"))
	if err != nil {
		t.Fatalf("read client-key.pem: %v", err)
	}
	if _, err := certkey.ParseKeyPEM(keyPEM); err != nil {
		t.Errorf("client-key.pem does not parse as an ECDSA key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, pendingKeyFileName)); !os.IsNotExist(err) {
		t.Errorf("pending key staging file still present after successful enrolment (err=%v)", err)
	}

	tok, err := os.ReadFile(filepath.Join(dir, "token"))
	if err != nil {
		t.Fatalf("read token: %v", err)
	}
	if string(tok) != "test-canary-token" {
		t.Errorf("token content = %q, want %q", tok, "test-canary-token")
	}

	// Second boot: same env, same now-enrolled state directory. Must not
	// contact either enrolment endpoint again.
	p2 := testParams(t, dir)
	p2.BirdcageURL = ts.URL
	p2.CAPin = pin
	p2.DeployToken = "deploy-tok"
	if err := EnsureEnrolled(context.Background(), p2); err != nil {
		t.Fatalf("EnsureEnrolled (second boot): %v", err)
	}
	if got, want := atomic.LoadInt32(helloHits), int32(1); got != want {
		t.Errorf("hello hits after second boot = %d, want still %d (enrolment must not repeat)", got, want)
	}
	if got, want := atomic.LoadInt32(provisionHits), int32(1); got != want {
		t.Errorf("provision hits after second boot = %d, want still %d (enrolment must not repeat)", got, want)
	}
}

// TestEnsureEnrolledNothingToDo proves an empty state directory with no
// CAPin/DeployToken set is left alone -- not an error, and no HTTP call
// made -- so a caller's own subsequent file reads report the original
// "missing file" failure unchanged.
func TestEnsureEnrolledNothingToDo(t *testing.T) {
	dir := t.TempDir()
	p := testParams(t, dir)
	p.BirdcageURL = "https://birdcage.invalid"

	if err := EnsureEnrolled(context.Background(), p); err != nil {
		t.Fatalf("EnsureEnrolled: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("state dir has %d entries, want 0 (untouched)", len(entries))
	}
}

// TestEnsureEnrolledIncompleteState proves a state directory holding
// some but not all of RequiredFiles fails closed, naming every missing
// file, rather than silently reusing a half-written credential set.
func TestEnsureEnrolledIncompleteState(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seed ca.pem: %v", err)
	}
	p := testParams(t, dir)

	err := EnsureEnrolled(context.Background(), p)
	if err == nil {
		t.Fatal("EnsureEnrolled succeeded against an incomplete state directory")
	}
	for _, missing := range []string{"client.pem", "client-key.pem", "token"} {
		if !strings.Contains(err.Error(), missing) {
			t.Errorf("error %q does not name missing file %q", err, missing)
		}
	}
}

// TestEnsureEnrolledRefusedDeployToken proves a 401 from /enrol/hello is
// reported plainly and never retried.
func TestEnsureEnrolledRefusedDeployToken(t *testing.T) {
	ts, pin, helloHits, _ := newFakeEnrolServer(t, "the-real-token", "enrol-secret")
	dir := t.TempDir()
	p := testParams(t, dir)
	p.BirdcageURL = ts.URL
	p.CAPin = pin
	p.DeployToken = "wrong-token"

	err := EnsureEnrolled(context.Background(), p)
	if err == nil {
		t.Fatal("EnsureEnrolled succeeded with a wrong deploy token")
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Errorf("error = %q, want it to say the token was refused", err)
	}
	if got, want := atomic.LoadInt32(helloHits), int32(1); got != want {
		t.Errorf("hello hits = %d, want exactly %d (a refusal must not retry)", got, want)
	}
}

// TestEnsureEnrolledLogsNeverContainSecrets proves EnsureEnrolled's own
// log lines never contain the deploy token, the enrolment secret or the
// minted bearer token -- the same guarantee
// cmd/mockingbird/nolog_test.go's TestEnrolAtBootLifecycle asserts for
// its own caller, proven here at the package that actually owns the
// values.
func TestEnsureEnrolledLogsNeverContainSecrets(t *testing.T) {
	ts, pin, _, _ := newFakeEnrolServer(t, "sentinel-deploy-token", "sentinel-enrolment-secret")
	dir := t.TempDir()
	var buf bytes.Buffer
	p := testParams(t, dir)
	p.BirdcageURL = ts.URL
	p.CAPin = pin
	p.DeployToken = "sentinel-deploy-token"
	p.Log = slog.New(slog.NewTextHandler(&buf, nil))

	if err := EnsureEnrolled(context.Background(), p); err != nil {
		t.Fatalf("EnsureEnrolled: %v", err)
	}
	out := buf.String()
	for _, secret := range []string{"sentinel-deploy-token", "sentinel-enrolment-secret", "test-canary-token"} {
		if strings.Contains(out, secret) {
			t.Errorf("log output contains a secret (%q): %s", secret, out)
		}
	}
}

// TestEnsureEnrolledAlreadyEnrolledIgnoresPin proves the "already
// enrolled" branch logs once and never contacts birdcage, even when
// CAPin/DeployToken are (incorrectly) still set.
func TestEnsureEnrolledAlreadyEnrolledIgnoresPin(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"ca.pem", "client.pem", "client-key.pem", "token"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	var buf bytes.Buffer
	p := testParams(t, dir)
	p.BirdcageURL = "https://birdcage.invalid"
	p.CAPin = "leftover-pin"
	p.DeployToken = "leftover-token"
	p.Log = slog.New(slog.NewTextHandler(&buf, nil))

	if err := EnsureEnrolled(context.Background(), p); err != nil {
		t.Fatalf("EnsureEnrolled: %v", err)
	}
	if !strings.Contains(buf.String(), "already enrolled") {
		t.Errorf("log output = %q, want it to mention already being enrolled", buf.String())
	}
	if strings.Contains(buf.String(), "leftover-token") {
		t.Errorf("log output leaks the ignored deploy token: %s", buf.String())
	}
}

// TestRetryEnrolStepStopsOnContextCancel proves the loop's other exit:
// a step that keeps failing with a genuine network error (dial refused,
// which enrol.FirstContact's own postJSON classifies as retryable by
// default) is retried until the context is canceled, not forever and not
// only once. Uses a real dial failure rather than a hand-built
// *enrol.RetryableError, since that type has no exported constructor --
// internal/agent/enrol's own tests prove the classification itself; this
// proves retryEnrolStep's loop control against it.
func TestRetryEnrolStepStopsOnContextCancel(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))

	// Port 0 on a resolved loopback listener that's immediately closed:
	// dialing it afterward fails fast and deterministically with
	// "connection refused", which postJSON wraps as retryable.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err = retryEnrolStep(ctx, log, func(ctx context.Context) (enrol.Hello, error) {
		return enrol.FirstContact(ctx, "https://"+deadAddr, strings.Repeat("00", sha256.Size), "tok")
	})
	if err == nil {
		t.Fatal("retryEnrolStep succeeded against an unreachable server")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("retryEnrolStep error = %v, want context.Canceled", err)
	}
}

// TestHostPort proves the log-line address extraction: a real URL yields
// its host:port, and an unparseable one falls back to a fixed
// placeholder rather than printing something unexpected.
func TestHostPort(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://birdcage.example:8443/enrol", "birdcage.example:8443"},
		{"not a url", "birdcage"},
		{"", "birdcage"},
	}
	for _, tc := range cases {
		if got := hostPort(tc.in); got != tc.want {
			t.Errorf("hostPort(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRedactErrStripsPathAndAddress proves redactErr removes a wrapped
// *fs.PathError's path and a wrapped *net.OpError's address, and leaves
// an unrelated error's message untouched.
func TestRedactErrStripsPathAndAddress(t *testing.T) {
	pathErr := &os.PathError{Op: "open", Path: "/secret/state/token", Err: os.ErrNotExist}
	if got := redactErr(pathErr); strings.Contains(got, "/secret/state/token") {
		t.Errorf("redactErr(%v) = %q, still contains the path", pathErr, got)
	}

	opErr := &net.OpError{Op: "dial", Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 443}, Err: errors.New("refused")}
	if got := redactErr(opErr); strings.Contains(got, "10.0.0.5:443") {
		t.Errorf("redactErr(%v) = %q, still contains the address", opErr, got)
	}

	plain := errors.New("plain failure")
	if got := redactErr(plain); got != "plain failure" {
		t.Errorf("redactErr(%v) = %q, want unchanged message", plain, got)
	}

	if got := redactErr(nil); got != "" {
		t.Errorf("redactErr(nil) = %q, want empty", got)
	}
}

// TestWriteStateLeavesPartialWritesOnFailure proves writeState's own
// documented behaviour: an error partway through leaves earlier files
// durably written and stops before the failing one, rather than
// retrying or rolling anything back.
func TestWriteStateLeavesPartialWritesOnFailure(t *testing.T) {
	dir := t.TempDir()
	files := []StateFile{
		{Name: "first", Data: []byte("ok")},
		{Name: filepath.Join("no-such-subdir", "second"), Data: []byte("never written")},
	}
	err := writeState(dir, files)
	if err == nil {
		t.Fatal("writeState succeeded despite an unwritable second file")
	}
	got, readErr := os.ReadFile(filepath.Join(dir, "first"))
	if readErr != nil {
		t.Fatalf("read first: %v", readErr)
	}
	if string(got) != "ok" {
		t.Fatalf("first = %q, want %q", got, "ok")
	}
}

// TestEnrolAtBootReusesPendingKeyAcrossProvisionRetries proves ADR-0012
// B1's own requirement: a provisioning attempt that fails and is retried
// signs its CSR with the same key every time, not a fresh one per
// attempt. The fake server here refuses the first provision call (a
// retryable network-shaped failure would also work, but a 401-then-200
// sequence is not possible through this package's own retryEnrolStep,
// which never retries a deterministic refusal -- so this drives the
// retry via two genuinely separate EnsureEnrolled calls against the same
// state directory instead, the same "crash and restart before
// provisioning completed" case loadOrGeneratePendingKey's own doc
// comment names).
func TestEnrolAtBootReusesPendingKeyAcrossProvisionRetries(t *testing.T) {
	caDER, caCert, caKey := genCA(t, "retry-test-ca")
	leafDER, leafKey := genLeaf(t, caCert, caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	var provisionAttempts int32
	var firstCSRPubKey atomic.Value

	mux := http.NewServeMux()
	mux.HandleFunc("POST /enrol/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"enrolment_secret":       "enrol-secret",
			"ca_pem":                 string(caPEM),
			"ingest_url":             "https://ingest.invalid:8443",
			"window_deadline":        time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339),
			"admin_approval_address": "admin@example.com",
			"release_address":        "release@example.com",
		})
	})
	mux.HandleFunc("POST /enrol/provision", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&provisionAttempts, 1)
		var req struct {
			CSRPEM string `json:"csr_pem"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		block, _ := pem.Decode([]byte(req.CSRPEM))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatalf("server: parse CSR: %v", err)
		}
		pubDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
		if err != nil {
			t.Fatalf("server: marshal CSR public key: %v", err)
		}

		if n == 1 {
			firstCSRPubKey.Store(pubDER)
			// Refuse the first attempt outright -- an ordinary "boot
			// crashed / provisioning window raced" style failure. This
			// is deterministic (ErrRefused), so this package's own
			// retryEnrolStep does not retry it internally; the test
			// itself drives the second attempt via a second
			// EnsureEnrolled call below, exactly like a restarted
			// process would.
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"refused"}`))
			return
		}

		if !bytes.Equal(pubDER, firstCSRPubKey.Load().([]byte)) {
			t.Errorf("second provision attempt's CSR public key differs from the first's -- pending key was not reused")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"canary_id":            "node-retry-1",
			"canary_token":         "test-canary-token",
			"client_cert_pem":      "PLACEHOLDER-CLIENT-CERT-PEM",
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

	dir := t.TempDir()
	p := testParams(t, dir)
	p.BirdcageURL = server.URL
	p.CAPin = pinFor(caDER)
	p.DeployToken = "deploy-tok"

	// First boot: hello succeeds, provision is refused. EnsureEnrolled
	// itself fails, but the pending key it generated is left staged on
	// disk -- exactly what a crashed or restarted process would find.
	if err := EnsureEnrolled(context.Background(), p); err == nil {
		t.Fatal("EnsureEnrolled succeeded despite provision refusing the first attempt")
	}
	if _, err := os.Stat(filepath.Join(dir, pendingKeyFileName)); err != nil {
		t.Fatalf("pending key staging file missing after a failed provision attempt: %v", err)
	}

	// Second boot, same state directory: provision succeeds this time.
	// The server itself asserts the CSR's public key matches the first
	// attempt's.
	p2 := testParams(t, dir)
	p2.BirdcageURL = server.URL
	p2.CAPin = pinFor(caDER)
	p2.DeployToken = "deploy-tok"
	if err := EnsureEnrolled(context.Background(), p2); err != nil {
		t.Fatalf("EnsureEnrolled (second attempt): %v", err)
	}
	if got := atomic.LoadInt32(&provisionAttempts); got != 2 {
		t.Fatalf("provision attempts = %d, want 2", got)
	}
}

// TestLoadOrGeneratePendingKeyReusesExistingKey proves the first branch
// of ADR-0012 B1's reuse requirement directly: a pending key already
// staged on disk by an earlier attempt is parsed and returned as-is,
// never silently replaced by a fresh one.
func TestLoadOrGeneratePendingKeyReusesExistingKey(t *testing.T) {
	dir := t.TempDir()

	first, err := loadOrGeneratePendingKey(dir)
	if err != nil {
		t.Fatalf("loadOrGeneratePendingKey (stage): %v", err)
	}
	stagedPEM, err := os.ReadFile(filepath.Join(dir, pendingKeyFileName))
	if err != nil {
		t.Fatalf("read staged key: %v", err)
	}

	second, err := loadOrGeneratePendingKey(dir)
	if err != nil {
		t.Fatalf("loadOrGeneratePendingKey (reuse): %v", err)
	}
	if !first.Equal(second) {
		t.Error("loadOrGeneratePendingKey returned a different key on the second call, want the staged one reused")
	}
	gotPEM, err := os.ReadFile(filepath.Join(dir, pendingKeyFileName))
	if err != nil {
		t.Fatalf("read staged key after reuse: %v", err)
	}
	if !bytes.Equal(stagedPEM, gotPEM) {
		t.Error("staged key file changed on a pure reuse call")
	}
}

// TestLoadOrGeneratePendingKeyRegeneratesOnCorruptFile proves the
// fall-through branch: a staged file that exists but does not parse as
// an ECDSA key is not a fatal error -- it is replaced by a freshly
// generated, parseable key, durably staged in its place.
func TestLoadOrGeneratePendingKeyRegeneratesOnCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, pendingKeyFileName)
	if err := os.WriteFile(path, []byte("not a valid pending key"), 0o600); err != nil {
		t.Fatalf("seed corrupt pending key: %v", err)
	}

	key, err := loadOrGeneratePendingKey(dir)
	if err != nil {
		t.Fatalf("loadOrGeneratePendingKey against a corrupt staged file: %v", err)
	}
	if key == nil {
		t.Fatal("loadOrGeneratePendingKey returned a nil key")
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read regenerated staged key: %v", err)
	}
	if string(onDisk) == "not a valid pending key" {
		t.Fatal("corrupt staged key file was never replaced")
	}
	parsed, err := certkey.ParseKeyPEM(onDisk)
	if err != nil {
		t.Fatalf("regenerated staged key does not parse: %v", err)
	}
	if !key.Equal(parsed) {
		t.Error("returned key does not match the key now staged on disk")
	}
}

// TestEnrolAtBootWrapsPendingKeyFailure proves enrolAtBoot's "prepare
// client key" error-wrapping branch: when loadOrGeneratePendingKey
// cannot durably stage a key (here, the staging path is occupied by a
// directory, so atomicfile.Write's rename can never land), EnsureEnrolled
// fails with that step named, and never contacts /enrol/provision.
func TestEnrolAtBootWrapsPendingKeyFailure(t *testing.T) {
	ts, pin, helloHits, provisionHits := newFakeEnrolServer(t, "deploy-tok", "enrol-secret")
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, pendingKeyFileName), 0o700); err != nil {
		t.Fatalf("seed pending-key directory collision: %v", err)
	}

	p := testParams(t, dir)
	p.BirdcageURL = ts.URL
	p.CAPin = pin
	p.DeployToken = "deploy-tok"

	err := EnsureEnrolled(context.Background(), p)
	if err == nil {
		t.Fatal("EnsureEnrolled succeeded despite an unstageable pending key")
	}
	if !strings.Contains(err.Error(), "prepare client key") {
		t.Errorf("error = %q, want it to name the prepare-client-key step", err)
	}
	if got, want := atomic.LoadInt32(helloHits), int32(1); got != want {
		t.Errorf("hello hits = %d, want %d", got, want)
	}
	if got := atomic.LoadInt32(provisionHits); got != 0 {
		t.Errorf("provision hits = %d, want 0 (must not be reached after key preparation fails)", got)
	}
}

// TestEnrolAtBootWrapsFirstContactGenericError proves the non-refused,
// non-retryable branch of FirstContact's own error handling: a
// deterministic failure that is neither a network error nor an
// ErrRefused (here, a CAPin that does not match the server's actual
// certificate) is reported as a plain wrapped "first contact" error, not
// the deploy-token-refused message and not retried.
func TestEnrolAtBootWrapsFirstContactGenericError(t *testing.T) {
	ts, _, helloHits, _ := newFakeEnrolServer(t, "deploy-tok", "enrol-secret")
	dir := t.TempDir()
	p := testParams(t, dir)
	p.BirdcageURL = ts.URL
	p.CAPin = strings.Repeat("ab", sha256.Size) // well-formed, but matches nothing
	p.DeployToken = "deploy-tok"

	err := EnsureEnrolled(context.Background(), p)
	if err == nil {
		t.Fatal("EnsureEnrolled succeeded with a CAPin matching no presented certificate")
	}
	if !strings.Contains(err.Error(), "first contact") {
		t.Errorf("error = %q, want it to name the first-contact step", err)
	}
	if strings.Contains(err.Error(), "deploy token refused") {
		t.Errorf("error = %q, a pin mismatch must not be reported as a refused deploy token", err)
	}
	if got, want := atomic.LoadInt32(helloHits), int32(0); got != want {
		t.Errorf("hello hits = %d, want %d (the TLS handshake itself must fail before the handler runs)", got, want)
	}
}

// TestEnrolAtBootWrapsProvisionGenericError proves the non-refused,
// non-retryable branch of Provision's own error handling: a deterministic
// non-200/401 response is reported as a plain wrapped "provision" error,
// never the enrolment-secret-refused message.
func TestEnrolAtBootWrapsProvisionGenericError(t *testing.T) {
	caDER, caCert, caKey := genCA(t, "provision-error-test-ca")
	leafDER, leafKey := genLeaf(t, caCert, caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /enrol/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"enrolment_secret":       "enrol-secret",
			"ca_pem":                 string(caPEM),
			"ingest_url":             "https://ingest.invalid:8443",
			"window_deadline":        time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339),
			"admin_approval_address": "admin@example.com",
			"release_address":        "release@example.com",
		})
	})
	mux.HandleFunc("POST /enrol/provision", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
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

	dir := t.TempDir()
	p := testParams(t, dir)
	p.BirdcageURL = server.URL
	p.CAPin = pinFor(caDER)
	p.DeployToken = "deploy-tok"

	err := EnsureEnrolled(context.Background(), p)
	if err == nil {
		t.Fatal("EnsureEnrolled succeeded despite a 500 from /enrol/provision")
	}
	if !strings.Contains(err.Error(), "provision") {
		t.Errorf("error = %q, want it to name the provision step", err)
	}
	if strings.Contains(err.Error(), "enrolment secret refused") {
		t.Errorf("error = %q, a 500 must not be reported as a refused enrolment secret", err)
	}
	// The pending key stays staged -- a later retry (or crashed-process
	// restart) can reuse it, same as TestEnrolAtBootReusesPendingKeyAcrossProvisionRetries.
	if _, err := os.Stat(filepath.Join(dir, pendingKeyFileName)); err != nil {
		t.Errorf("pending key staging file missing after a generic provision failure: %v", err)
	}
}

// TestEnrolAtBootWrapsWriteStateFailure proves enrolAtBoot's "write
// state" error-wrapping branch: when WriteState names a file under a
// directory that does not exist, EnsureEnrolled reports that step by
// name, having already completed FirstContact and Provision against a
// real fake server.
func TestEnrolAtBootWrapsWriteStateFailure(t *testing.T) {
	ts, pin, _, provisionHits := newFakeEnrolServer(t, "deploy-tok", "enrol-secret")
	dir := t.TempDir()
	var buf bytes.Buffer
	p := Params{
		StateDir:           dir,
		DeployTokenEnvName: "TEST_DEPLOY_TOKEN",
		RequiredFiles:      []string{"ca.pem"},
		NodeNoun:           "canary",
		WriteState: func(hello enrol.Hello, creds enrol.Credentials, keyPEM []byte) []StateFile {
			return []StateFile{
				{Name: filepath.Join("no-such-subdir", "ca.pem"), Data: hello.CAPEM},
			}
		},
		Log: slog.New(slog.NewTextHandler(&buf, nil)),
	}
	p.BirdcageURL = ts.URL
	p.CAPin = pin
	p.DeployToken = "deploy-tok"

	err := EnsureEnrolled(context.Background(), p)
	if err == nil {
		t.Fatal("EnsureEnrolled succeeded despite an unwritable state file path")
	}
	if !strings.Contains(err.Error(), "write state") {
		t.Errorf("error = %q, want it to name the write-state step", err)
	}
	if got, want := atomic.LoadInt32(provisionHits), int32(1); got != want {
		t.Errorf("provision hits = %d, want %d (provisioning must have completed before the write failed)", got, want)
	}
	// The pending key must still be staged: WriteState failing must not
	// lose the only copy of the now-provisioned key.
	if _, err := os.Stat(filepath.Join(dir, pendingKeyFileName)); err != nil {
		t.Errorf("pending key staging file missing after a failed write-state: %v", err)
	}
}

// TestRetryEnrolStepSucceedsAfterOneRetry proves the loop's other two
// branches TestRetryEnrolStepStopsOnContextCancel does not reach: a
// retryable failure followed by the backoff timer actually firing
// (rather than the context being canceled first), the loop continuing to
// a second attempt, and that attempt's success being returned as-is.
func TestRetryEnrolStepSucceedsAfterOneRetry(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	ts, pin, _, _ := newFakeEnrolServer(t, "deploy-tok", "enrol-secret")

	var attempt int32
	got, err := retryEnrolStep(context.Background(), log, func(ctx context.Context) (enrol.Hello, error) {
		if atomic.AddInt32(&attempt, 1) == 1 {
			// A real dial failure against a closed listener: the same
			// retryable-network-error shape TestRetryEnrolStepStopsOnContextCancel
			// uses, but this time nothing cancels the context, so the
			// loop must wait out the backoff timer itself and retry.
			return enrol.FirstContact(ctx, "https://"+deadAddr, strings.Repeat("00", sha256.Size), "tok")
		}
		return enrol.FirstContact(ctx, ts.URL, pin, "deploy-tok")
	})
	if err != nil {
		t.Fatalf("retryEnrolStep: %v", err)
	}
	if got.EnrolmentSecret != "enrol-secret" {
		t.Errorf("EnrolmentSecret = %q, want %q", got.EnrolmentSecret, "enrol-secret")
	}
	if attempt != 2 {
		t.Errorf("attempts = %d, want 2", attempt)
	}
	if !strings.Contains(buf.String(), "network error, retrying") {
		t.Errorf("log output = %q, want it to mention the retry", buf.String())
	}
}
