package client

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestRenewCertHappyPath proves the request carries a valid CSR and the
// response is decoded field-for-field -- ADR-0012 B2's wire contract:
// POST /ingest/renew, request {"csr_pem"}, response {"client_cert_pem",
// "not_after"}.
func TestRenewCertHappyPath(t *testing.T) {
	wantNotAfter := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/ingest/renew" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok-abc" {
			t.Errorf("Authorization = %q", got)
		}
		var req wireRenewRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		block, _ := pem.Decode([]byte(req.CSRPEM))
		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			t.Fatalf("request csr_pem is not a CSR PEM block: %q", req.CSRPEM)
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatalf("parse CSR: %v", err)
		}
		if err := csr.CheckSignature(); err != nil {
			t.Fatalf("CSR signature does not verify: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wireRenewResponse{
			ClientCertPEM: "PLACEHOLDER-NEW-CLIENT-CERT-PEM",
			NotAfter:      wantNotAfter.Format(time.RFC3339),
		})
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	result, err := c.RenewCert(ctx(), "tok-abc", testCSRPEM(t))
	if err != nil {
		t.Fatalf("RenewCert: %v", err)
	}
	if string(result.ClientCertPEM) != "PLACEHOLDER-NEW-CLIENT-CERT-PEM" {
		t.Errorf("ClientCertPEM = %q", result.ClientCertPEM)
	}
	if !result.NotAfter.Equal(wantNotAfter) {
		t.Errorf("NotAfter = %v, want %v", result.NotAfter, wantNotAfter)
	}
}

// TestRenewCertUnauthorized proves a 401 is reported as ErrUnauthorized,
// never retried by this package itself.
func TestRenewCertUnauthorized(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	_, err := c.RenewCert(ctx(), "tok-abc", testCSRPEM(t))
	if !IsUnauthorized(err) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

// TestRenewCertMissingFieldIsRetryable proves an incomplete 200 response
// is treated as uncertain, not a successful empty renewal.
func TestRenewCertMissingFieldIsRetryable(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wireRenewResponse{ClientCertPEM: "cert-only"})
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	_, err := c.RenewCert(ctx(), "tok-abc", testCSRPEM(t))
	if !IsRetryable(err) {
		t.Fatalf("err = %v, want a *RetryableError", err)
	}
}

// TestRenewCertServerErrorIsRetryable proves a 5xx is retryable, matching
// every other route in this package.
func TestRenewCertServerErrorIsRetryable(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	_, err := c.RenewCert(ctx(), "tok-abc", testCSRPEM(t))
	if !IsRetryable(err) {
		t.Fatalf("err = %v, want a *RetryableError", err)
	}
}

// TestSwapClientCertPresentsNewPairOnNextRequest proves SwapClientCert
// takes effect for the caller's very next request -- ADR-0012 B2:
// "switch the mTLS client to the new pair for the next request". The
// server records each request's peer certificate's CommonName; a Client
// built with certA's pair must present certA, and after SwapClientCert
// to certB's pair, the next request must present certB -- proving the
// swap reached a live connection, not just an unused config field.
func TestSwapClientCertPresentsNewPairOnNextRequest(t *testing.T) {
	certA, keyA := selfSignedKeyPair(t, "agent-cert-a")
	certB, keyB := selfSignedKeyPair(t, "agent-cert-b")

	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(certA) {
		t.Fatal("add certA to pool")
	}
	if !clientCAs.AppendCertsFromPEM(certB) {
		t.Fatal("add certB to pool")
	}

	var lastCN string
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			lastCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(wireRotateResponse{Token: "irrelevant"})
	}))
	ts.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs}
	ts.StartTLS()
	defer ts.Close()

	c, err := New(Config{BaseURL: ts.URL, CACert: certPEM(t, ts), ClientCert: certA, ClientKey: keyA})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := c.RotateToken(ctx(), "tok"); err != nil {
		t.Fatalf("RotateToken (certA): %v", err)
	}
	if lastCN != "agent-cert-a" {
		t.Fatalf("peer CN = %q, want agent-cert-a", lastCN)
	}

	if err := c.SwapClientCert(certB, keyB); err != nil {
		t.Fatalf("SwapClientCert: %v", err)
	}

	if _, err := c.RotateToken(ctx(), "tok"); err != nil {
		t.Fatalf("RotateToken (certB): %v", err)
	}
	if lastCN != "agent-cert-b" {
		t.Fatalf("peer CN after swap = %q, want agent-cert-b (swap must take effect on the next request)", lastCN)
	}
}

// TestSwapClientCertRejectsMismatchedPair proves SwapClientCert validates
// the pair before swapping anything, exactly like New's own
// construction-time check.
func TestSwapClientCertRejectsMismatchedPair(t *testing.T) {
	certA, _ := selfSignedKeyPair(t, "a")
	_, keyB := selfSignedKeyPair(t, "b")

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	c := newTestClient(t, ts)

	if err := c.SwapClientCert(certA, keyB); err == nil {
		t.Fatal("SwapClientCert succeeded with a mismatched cert/key pair")
	}
}

// testCSRPEM returns a syntactically valid P-256 CSR PEM, standing in for
// whatever internal/agent/certkey.BuildCSR would produce -- this package
// must never import internal/agent/certkey (it is a lower layer than
// internal/agent/renewal, which is the only caller that actually builds
// one for real), so tests build their own minimal CSR by hand instead.
func testCSRPEM(t *testing.T) []byte {
	t.Helper()
	_, keyPEM := selfSignedKeyPair(t, "renew-test")
	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse test key: %v", err)
	}
	return buildCSRPEM(t, key)
}

func buildCSRPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.CertificateRequest{SignatureAlgorithm: x509.ECDSAWithSHA256}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
