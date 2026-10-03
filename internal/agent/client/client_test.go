package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/db/dbtest"
	"github.com/tomlawesome/birdcage/internal/ingest"
	"github.com/tomlawesome/birdcage/internal/store"
)

// forEachEngine mirrors internal/ingest's own test helper
// (http_test.go): every test in this package that needs a real
// database runs once per engine dbtest.Targets returns, so a
// Postgres-only failure is reported distinctly from SQLite's.
func forEachEngine(t *testing.T, fn func(t *testing.T, database *db.DB)) {
	t.Helper()
	for _, tgt := range dbtest.Targets(t) {
		tgt := tgt
		t.Run(tgt.Name, func(t *testing.T) {
			fn(t, tgt.DB)
		})
	}
}

// certPEM PEM-encodes ts's own leaf certificate, so a Client can be
// built to trust exactly it -- the same self-signed-as-its-own-root
// shape any httptest.NewTLSServer caller uses to test real certificate
// verification without a real CA.
func certPEM(t *testing.T, ts *httptest.Server) []byte {
	t.Helper()
	cert := ts.Certificate()
	if cert == nil {
		t.Fatal("test server has no certificate")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// newTestClient builds a Client trusting ts's own certificate.
func newTestClient(t *testing.T, ts *httptest.Server) *Client {
	t.Helper()
	c, err := New(Config{BaseURL: ts.URL, CACert: certPEM(t, ts)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// newIngestServer wraps internal/ingest's real handler (not a
// hand-written fake) in a TLS httptest.Server, and returns a Client
// configured to trust it -- so drift between this package's wire types
// and internal/ingest's own fails a test here rather than only showing
// up against a real deployment.
//
// The server requires a client certificate (issue #47 slice 3: the
// ingest listener runs ClientAuth: RequireAndVerifyClientCert, and
// requireBearerToken binds the certificate's CommonName to the token's
// canary), so the Client presents one for testCanaryID -- the canary
// every test in this package mints its tokens for. Its subject OU is
// kind (issue #106): the registry check now needs a canaries row
// registered with the same kind (ensureCanary below, a no-op if the
// caller already registered testCanaryID itself), and the certificate
// check needs the presented OU to agree with it, or every route in this
// package's tests would be refused as a kind mismatch.
func newIngestServer(t *testing.T, database *db.DB, kind agentkind.Kind) (*Client, *httptest.Server) {
	t.Helper()
	ensureCanary(t, database, testCanaryID, kind)
	clientCert, clientKey := selfSignedKeyPair(t, testCanaryID, string(kind))
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCert) {
		t.Fatal("failed to add generated client cert to pool")
	}
	// ADR-0012 Part B: the ingest listener now refuses any client
	// certificate that has no client_certs row, so the generated
	// certificate above has to be recorded exactly as provisioning
	// would record it, or every request here fails auth before this
	// package's own logic is ever exercised.
	recordClientCert(t, database, testCanaryID, clientCert)
	handler := ingest.NewHandler(database, nil, store.NewSelfTestIndex(), nil)
	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	c, err := New(Config{BaseURL: ts.URL, CACert: certPEM(t, ts), ClientCert: clientCert, ClientKey: clientKey})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, ts
}

// testCanaryID is the one canary this package's real-ingest tests
// enrol, mint tokens for, and present a client certificate as.
const testCanaryID = "canary-a"

func ctx() context.Context {
	return context.Background()
}

// TestNewRejectsUnusableCACert proves New fails closed on a CACert that
// contains no certificate at all, rather than silently building a
// Client that would fall back to the system root pool.
func TestNewRejectsUnusableCACert(t *testing.T) {
	if _, err := New(Config{BaseURL: "https://example.invalid", CACert: []byte("not a certificate")}); err == nil {
		t.Fatal("New succeeded with an unusable CACert")
	}
}

// TestNewRequiresBaseURL proves New fails closed on a missing BaseURL.
func TestNewRequiresBaseURL(t *testing.T) {
	if _, err := New(Config{CACert: []byte("irrelevant")}); err == nil {
		t.Fatal("New succeeded with no BaseURL")
	}
}

// TestClientRefusesRedirect is the gate's required case: #48 research
// #1, "the HTTP client refuses every redirect ... unconditionally".
// The server answers every POST with a 302 to itself; a client that
// followed it would loop forever, so a passing test here also proves
// CheckRedirect actually runs rather than merely being configured.
func TestClientRefusesRedirect(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/somewhere-else", http.StatusFound)
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	_, err := c.PushBatch(ctx(), "tok", []Event{{ID: validID1, DestPort: -1, Raw: "{}"}})
	if err == nil {
		t.Fatal("PushBatch followed a redirect instead of refusing it")
	}
	if !IsRetryable(err) {
		t.Fatalf("err = %v, want a *RetryableError (a refused redirect is a call that never completed)", err)
	}
}

// TestClientTimeout is the gate's required case: a server that never
// answers must not hang PushBatch forever. ctx's own short deadline
// forces the failure quickly regardless of the client's own timeout
// constants, keeping this test fast.
func TestClientTimeout(t *testing.T) {
	block := make(chan struct{})
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	// close(block) must run before ts.Close() -- Close blocks until every
	// outstanding request's handler returns, and the handler above only
	// returns once block is closed. Deferred in this order so LIFO
	// unwinding closes block first, letting the still-blocked handler
	// return before Close waits on it.
	defer func() {
		close(block)
		ts.Close()
	}()
	c := newTestClient(t, ts)

	deadline, cancel := context.WithTimeout(ctx(), 200*time.Millisecond)
	defer cancel()

	_, err := c.PushBatch(deadline, "tok", []Event{{ID: validID1, DestPort: -1, Raw: "{}"}})
	if err == nil {
		t.Fatal("PushBatch returned no error against a server that never answers")
	}
	if !IsRetryable(err) {
		t.Fatalf("err = %v, want a *RetryableError (a timeout is a call that never completed)", err)
	}
}

// TestClientMalformedResponseBody is the gate's required case: birdcage
// answering 200 with a body that isn't valid JSON must not be mistaken
// for a successful, empty ack -- #48's fail-closed shape, "uncertainty
// always resolves toward ... retrying ... never toward skipping,
// trusting".
func TestClientMalformedResponseBody(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{not valid json")
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	_, err := c.PushBatch(ctx(), "tok", []Event{{ID: validID1, DestPort: -1, Raw: "{}"}})
	if err == nil {
		t.Fatal("PushBatch accepted a malformed response body")
	}
	if !IsRetryable(err) {
		t.Fatalf("err = %v, want a *RetryableError (uncertain outcome, never trusted)", err)
	}
}

// TestClientOversizedResponseBody is the gate's required case: a
// response body larger than this package's own read bound must be
// refused rather than fully buffered (#48: "no unbounded reads").
func TestClientOversizedResponseBody(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Valid JSON shape, just enormously padded -- proves the size
		// cap trips before or regardless of successful decoding.
		_, _ = io.WriteString(w, `{"stored":[`)
		for i := 0; i < 20000; i++ {
			if i > 0 {
				_, _ = io.WriteString(w, ",")
			}
			_, _ = fmt.Fprintf(w, `"%064d"`, i)
		}
		_, _ = io.WriteString(w, `],"rejected":{}}`)
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	_, err := c.PushBatch(ctx(), "tok", []Event{{ID: validID1, DestPort: -1, Raw: "{}"}})
	if err == nil {
		t.Fatal("PushBatch accepted an oversized response body")
	}
	if !IsRetryable(err) {
		t.Fatalf("err = %v, want a *RetryableError", err)
	}
}

// unrelatedCertPEM returns a freshly self-signed certificate's PEM
// bytes -- a CA guaranteed to be unrelated to any httptest.Server's own
// certificate, since every httptest.NewTLSServer call shares one fixed
// built-in certificate (a distinct httptest.NewTLSServer would not
// actually prove this test's point).
func unrelatedCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "unrelated test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestClientCertificateVerificationFails proves TLS verification is
// real, not merely configured: a Client trusting a CA unrelated to the
// server's own certificate must refuse to talk to it at all, and never
// fall back to an unverified connection.
func TestClientCertificateVerificationFails(t *testing.T) {
	real := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler reached; the client should have refused the connection before sending a request")
	}))
	defer real.Close()

	c, err := New(Config{BaseURL: real.URL, CACert: unrelatedCertPEM(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, pushErr := c.PushBatch(ctx(), "tok", []Event{{ID: validID1, DestPort: -1, Raw: "{}"}})
	if pushErr == nil {
		t.Fatal("PushBatch succeeded against a server whose certificate does not chain to the trusted CA")
	}
	if !IsRetryable(pushErr) {
		t.Fatalf("err = %v, want a *RetryableError (the call never completed)", pushErr)
	}
}

// selfSignedKeyPair returns a fresh self-signed certificate -- also its
// own CA, the same shape unrelatedCertPEM above uses for a server -- and
// its PEM-encoded EC private key. Being its own CA lets a test use the
// same PEM both as the leaf a Client presents and as the trust anchor a
// test server's ClientCAs pool checks it against, without a separate CA
// key to manage.
// ou is variadic and normally omitted -- every existing caller wants a
// plain self-signed certificate with no OU at all. newIngestServer is
// the one caller that passes kind's string (issue #106): its server
// enforces the same certificate-kind check internal/ingest's real
// listener does, so a self-signed certificate carrying no OU would be
// refused as a legacy (pre-#106) shape.
func selfSignedKeyPair(t *testing.T, cn string, ou ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn, OrganizationalUnit: ou},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// recordClientCert parses certPEM's single leaf certificate and records
// it against canaryID via store.RecordClientCert, the same call
// provisioning and renewal make -- so a test's self-signed certificate
// authenticates against the real ingest handler's client_certs check
// exactly as a real agent's CA-issued one would.
func recordClientCert(t *testing.T, database *db.DB, canaryID string, certPEM []byte) store.ClientCert {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("recordClientCert: no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("recordClientCert: parse certificate: %v", err)
	}
	row, err := store.RecordClientCert(ctx(), database, canaryID, cert)
	if err != nil {
		t.Fatalf("RecordClientCert: %v", err)
	}
	return row
}

// TestClientPresentsCertificate is gap 1's required positive case: a
// Client built with Config.ClientCert/ClientKey set must actually
// present that certificate on the handshake, not merely accept the
// fields. The server requires and verifies a client certificate
// (tls.RequireAndVerifyClientCert); a Client that failed to present one
// would never complete the handshake at all, so a successful PushBatch
// here is only possible if the certificate really rode the connection.
func TestClientPresentsCertificate(t *testing.T) {
	clientCert, clientKey := selfSignedKeyPair(t, "test-agent")
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCert) {
		t.Fatal("failed to add generated client cert to pool")
	}

	var sawPeerCert bool
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPeerCert = r.TLS != nil && len(r.TLS.PeerCertificates) > 0
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"stored":[],"rejected":{}}`)
	}))
	ts.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAs,
	}
	ts.StartTLS()
	defer ts.Close()

	c, err := New(Config{
		BaseURL:    ts.URL,
		CACert:     certPEM(t, ts),
		ClientCert: clientCert,
		ClientKey:  clientKey,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := c.PushBatch(ctx(), "tok", []Event{{ID: validID1, DestPort: -1, Raw: "{}"}}); err != nil {
		t.Fatalf("PushBatch: %v (mTLS handshake likely failed to present the certificate)", err)
	}
	if !sawPeerCert {
		t.Fatal("server saw no peer certificate; the client did not present one")
	}
}

// TestNewRejectsIncompleteOrMismatchedClientCert is gap 1's required
// negative case: New must fail closed, at construction, on every
// half-configured or internally inconsistent ClientCert/ClientKey pair
// -- never leave it to surface later as a confusing handshake failure.
func TestNewRejectsIncompleteOrMismatchedClientCert(t *testing.T) {
	certA, keyA := selfSignedKeyPair(t, "a")
	_, keyB := selfSignedKeyPair(t, "b")

	cases := map[string]Config{
		"cert without key": {BaseURL: "https://example.invalid", CACert: certA, ClientCert: certA},
		"key without cert": {BaseURL: "https://example.invalid", CACert: certA, ClientKey: keyA},
		"mismatched pair":  {BaseURL: "https://example.invalid", CACert: certA, ClientCert: certA, ClientKey: keyB},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg); err == nil {
				t.Fatalf("New succeeded with %s, want a construction-time error", name)
			}
		})
	}
}
