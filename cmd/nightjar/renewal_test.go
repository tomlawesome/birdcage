package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/agent/renewal"
)

// renewalSelfSignedCert mints a self-signed ECDSA P-256 certificate/key
// pair with the given validity window, also usable as its own CA --
// internal/agent/renewal's own manager_test.go builds the identical
// fixture; duplicated here (rather than exported from that package for
// tests to import) because runRenewalTick's own behaviour -- which of
// its three log branches fires -- is what this file proves, not
// Manager.Tick's crash-safety, which that package's tests already cover.
func renewalSelfSignedCert(t *testing.T, notBefore, notAfter time.Time) (certPEM, keyPEM []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nightjar-renewal-test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
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
	return certPEM, keyPEM, key
}

// renewalFakeServer stands in for birdcage's own POST /ingest/renew,
// requiring a client certificate and either signing a fresh one (over
// whatever CSR arrived) or answering with failStatus.
func renewalFakeServer(t *testing.T, caCertDER []byte, caKey *ecdsa.PrivateKey, clientCAs *x509.CertPool, failStatus int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ingest/renew", func(w http.ResponseWriter, r *http.Request) {
		if failStatus != 0 {
			w.WriteHeader(failStatus)
			return
		}
		var req struct {
			CSRPEM string `json:"csr_pem"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("server: decode request: %v", err)
		}
		block, _ := pem.Decode([]byte(req.CSRPEM))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatalf("server: parse CSR: %v", err)
		}
		caCert, err := x509.ParseCertificate(caCertDER)
		if err != nil {
			t.Fatalf("server: parse CA: %v", err)
		}
		newTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "renewed-scanner"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(7 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		newDER, err := x509.CreateCertificate(rand.Reader, newTmpl, caCert, csr.PublicKey, caKey)
		if err != nil {
			t.Fatalf("server: sign new certificate: %v", err)
		}
		newCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newDER})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"client_cert_pem": string(newCertPEM),
			"not_after":       newTmpl.NotAfter.UTC().Format(time.RFC3339),
		})
	})

	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{caCertDER}, PrivateKey: caKey}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func serverCACertPEM(t *testing.T, ts *httptest.Server) []byte {
	t.Helper()
	cert := ts.Certificate()
	if cert == nil {
		t.Fatal("test server has no certificate")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// TestRunRenewalTickSucceedsAndSwapsPair proves the success branch: past
// half-life, a real mTLS request to a real (fake) /ingest/renew server
// that signs a fresh certificate, and the Manager's live pair is
// updated -- runRenewalTick's "certificate renewed" log line's own
// precondition.
func TestRunRenewalTickSucceedsAndSwapsPair(t *testing.T) {
	// NotBefore far in the past, NotAfter soon: half-life is behind "now".
	certPEM, keyPEM, caKey := renewalSelfSignedCert(t, time.Now().Add(-4*time.Hour), time.Now().Add(3*time.Hour))
	block, _ := pem.Decode(certPEM)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	ts := renewalFakeServer(t, block.Bytes, caKey, pool, 0)

	c, err := client.New(client.Config{BaseURL: ts.URL, CACert: serverCACertPEM(t, ts), ClientCert: certPEM, ClientKey: keyPEM})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	dir := t.TempDir()
	rm := renewal.NewManager(dir, clientKeyFileName, clientCertFileName, certPEM, keyPEM)

	before := rm.CertPEM()
	runRenewalTick(context.Background(), rm, c, "tok")
	after := rm.CertPEM()

	if string(before) == string(after) {
		t.Fatal("runRenewalTick did not swap the certificate on a successful renewal")
	}
	// The new pair must also have landed durably on disk -- StageAndSwap's
	// own job, driven here through the real success path.
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, clientCertFileName), filepath.Join(dir, clientKeyFileName)); err != nil {
		t.Fatalf("persisted pair does not load as a valid key pair: %v", err)
	}
}

// TestRunRenewalTickUnauthorizedDoesNotPanic proves a canary whose
// certificate birdcage does not recognise (pre-ADR-0012-B or revoked)
// logs a warning and returns, rather than panicking or crash-looping.
func TestRunRenewalTickUnauthorizedDoesNotPanic(t *testing.T) {
	certPEM, keyPEM, caKey := renewalSelfSignedCert(t, time.Now().Add(-4*time.Hour), time.Now().Add(3*time.Hour))
	block, _ := pem.Decode(certPEM)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	ts := renewalFakeServer(t, block.Bytes, caKey, pool, http.StatusUnauthorized)

	c, err := client.New(client.Config{BaseURL: ts.URL, CACert: serverCACertPEM(t, ts), ClientCert: certPEM, ClientKey: keyPEM})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	rm := renewal.NewManager(t.TempDir(), clientKeyFileName, clientCertFileName, certPEM, keyPEM)

	runRenewalTick(context.Background(), rm, c, "tok")

	if string(rm.CertPEM()) != string(certPEM) {
		t.Fatal("runRenewalTick changed the live certificate on an unauthorized response")
	}
}

// TestRunRenewalTickServerErrorDoesNotPanic proves a birdcage-side
// failure (503) is logged and left for the next tick, leaving the
// current certificate untouched -- the same "log and continue" stance
// as an unauthorized response, reached through the other branch of
// runRenewalTick's error handling.
func TestRunRenewalTickServerErrorDoesNotPanic(t *testing.T) {
	certPEM, keyPEM, caKey := renewalSelfSignedCert(t, time.Now().Add(-4*time.Hour), time.Now().Add(3*time.Hour))
	block, _ := pem.Decode(certPEM)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	ts := renewalFakeServer(t, block.Bytes, caKey, pool, http.StatusServiceUnavailable)

	c, err := client.New(client.Config{BaseURL: ts.URL, CACert: serverCACertPEM(t, ts), ClientCert: certPEM, ClientKey: keyPEM})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	rm := renewal.NewManager(t.TempDir(), clientKeyFileName, clientCertFileName, certPEM, keyPEM)

	runRenewalTick(context.Background(), rm, c, "tok")

	if string(rm.CertPEM()) != string(certPEM) {
		t.Fatal("runRenewalTick changed the live certificate on a server error")
	}
}
