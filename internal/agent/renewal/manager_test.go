package renewal

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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
)

// This file drives Manager.Tick against a hand-written fake
// /ingest/renew server, the shape ADR-0012 #130's own test brief asks
// for ("unit tests with an httptest TLS server faking provision and
// renew"), rather than the real internal/ingest handler -- that handler
// does not implement POST /ingest/renew yet (the server half of #130 is
// a separate, parallel change), so a real-handler test here would only
// prove a route that does not exist yet is missing.

// selfSignedCert mints a self-signed ECDSA P-256 certificate/key pair
// with the given validity window and CommonName -- also its own CA, so
// it can serve as both the leaf a Client presents and the trust anchor a
// server's ClientCAs pool checks it against.
func selfSignedCert(t *testing.T, cn string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		// IPAddresses lets this same cert double as the fake server's own
		// TLS leaf below (fakeRenewServer) -- a real ADR-0012 agent
		// certificate never carries a SAN at all (its subject is
		// overwritten and it authenticates as a client only), but this
		// test reuses one pair for both directions to keep the fixture
		// small.
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

// fakeRenewServer stands in for birdcage's ingest listener, just enough
// to drive Manager.Tick: it requires and records the presented client
// certificate's CommonName, and answers POST /ingest/renew either with a
// fresh certificate signed for whatever CSR arrived, or with the given
// failure status. currentCertPEM/currentKeyPEM are the pair the Client
// under test starts with -- also the CA the fake server signs its
// renewal responses from, so a Client trusting the same CA it enrolled
// with keeps trusting birdcage across a renewal, exactly as production
// does.
func fakeRenewServer(t *testing.T, caCertDER []byte, caKey *ecdsa.PrivateKey, clientCAs *x509.CertPool, failStatus int) (ts *httptest.Server, lastPeerCN func() string, hits func() int32) {
	t.Helper()
	var peerCN string
	var n int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ingest/renew", func(w http.ResponseWriter, r *http.Request) {
		n++
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			peerCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		if failStatus != 0 {
			w.WriteHeader(failStatus)
			return
		}
		var req struct {
			CSRPEM string `json:"csr_pem"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
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
			Subject:      pkix.Name{CommonName: "renewed-agent"},
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

	return server, func() string { return peerCN }, func() int32 { return n }
}

func serverCACertPEM(t *testing.T, ts *httptest.Server) []byte {
	t.Helper()
	cert := ts.Certificate()
	if cert == nil {
		t.Fatal("test server has no certificate")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// TestManagerKeyPEMReturnsCurrentKey proves KeyPEM (the counterpart to
// CertPEM, already exercised throughout this file) returns the exact
// key a Manager was constructed with -- callers must never log it, but
// they do need to read it back, e.g. to rebuild a client.Config after a
// restart.
func TestManagerKeyPEMReturnsCurrentKey(t *testing.T) {
	certPEM, keyPEM, _ := selfSignedCert(t, "agent-a", time.Now(), time.Now().Add(time.Hour))
	m := NewManager(t.TempDir(), "client-key.pem", "client.pem", certPEM, keyPEM)

	if string(m.KeyPEM()) != string(keyPEM) {
		t.Fatal("KeyPEM did not return the key the Manager was constructed with")
	}
}

// TestManagerTickNoopBeforeHalfLife proves Tick makes no request at all
// while the current certificate has not reached its half-life yet.
func TestManagerTickNoopBeforeHalfLife(t *testing.T) {
	certPEM, keyPEM, caKey := selfSignedCert(t, "agent-a", time.Now(), time.Now().Add(time.Hour)) // half-life 30m out
	caDER, _, _ := certDER(t, certPEM)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	ts, _, hits := fakeRenewServer(t, caDER, caKey, pool, 0)

	c, err := client.New(client.Config{BaseURL: ts.URL, CACert: serverCACertPEM(t, ts), ClientCert: certPEM, ClientKey: keyPEM})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	m := NewManager(t.TempDir(), "client-key.pem", "client.pem", certPEM, keyPEM)

	renewed, err := m.Tick(context.Background(), c, "tok")
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if renewed {
		t.Fatal("Tick renewed before half-life")
	}
	if got := hits(); got != 0 {
		t.Fatalf("server hits = %d, want 0 (no request before half-life)", got)
	}
}

// TestManagerTickRenewsAfterHalfLifeAndSwapsPair proves the success
// path: past half-life, Tick renews, persists the new pair to disk at
// keyFileName/certFileName (0600), updates the Manager's own in-memory
// pair, and switches c so its very next request presents the new
// certificate -- ADR-0012 B2's whole point.
func TestManagerTickRenewsAfterHalfLifeAndSwapsPair(t *testing.T) {
	// NotBefore in the past, NotAfter soon: half-life is already behind
	// "now".
	certPEM, keyPEM, caKey := selfSignedCert(t, "agent-a", time.Now().Add(-4*time.Hour), time.Now().Add(3*time.Hour))
	caDER, _, _ := certDER(t, certPEM)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	ts, lastPeerCN, hits := fakeRenewServer(t, caDER, caKey, pool, 0)

	c, err := client.New(client.Config{BaseURL: ts.URL, CACert: serverCACertPEM(t, ts), ClientCert: certPEM, ClientKey: keyPEM})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "client-key.pem"), string(keyPEM))
	writeFile(t, filepath.Join(dir, "client.pem"), string(certPEM))
	m := NewManager(dir, "client-key.pem", "client.pem", certPEM, keyPEM)

	renewed, err := m.Tick(context.Background(), c, "tok")
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if !renewed {
		t.Fatal("Tick did not renew past half-life")
	}
	if got := hits(); got != 1 {
		t.Fatalf("server hits = %d, want 1", got)
	}
	if lastPeerCN() != "agent-a" {
		t.Fatalf("renewal request presented CN = %q, want agent-a (the OLD certificate authenticates the renewal call)", lastPeerCN())
	}

	// In-memory pair updated.
	if string(m.CertPEM()) == string(certPEM) {
		t.Fatal("Manager's in-memory certificate unchanged after a successful renewal")
	}

	// On-disk pair updated, key file still 0600.
	onDiskCert, err := os.ReadFile(filepath.Join(dir, "client.pem"))
	if err != nil {
		t.Fatalf("read live cert: %v", err)
	}
	if string(onDiskCert) != string(m.CertPEM()) {
		t.Fatal("live cert file does not match Manager's in-memory certificate")
	}
	info, err := os.Stat(filepath.Join(dir, "client-key.pem"))
	if err != nil {
		t.Fatalf("stat live key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("live key mode = %v, want 0600", info.Mode().Perm())
	}

	// The client itself now presents the new certificate on its very
	// next request.
	if _, err := c.RenewCert(context.Background(), "tok", testCSR(t)); err != nil {
		// A second renewal is refused by this fake server's own logic
		// only if it cares about CN; it doesn't, so this just proves the
		// connection succeeds presenting *some* valid, still-trusted
		// certificate. What matters is the CN recorded below.
		t.Logf("second renewal call: %v", err)
	}
	if lastPeerCN() != "renewed-agent" {
		t.Fatalf("peer CN after swap = %q, want renewed-agent (SwapClientCert must take effect on the next request)", lastPeerCN())
	}
}

// TestManagerTickFailedRenewalKeepsOldPair proves a failed renewal
// (birdcage refuses the request) leaves the old pair completely alone,
// in memory and on disk, for the caller to retry on the next tick.
func TestManagerTickFailedRenewalKeepsOldPair(t *testing.T) {
	certPEM, keyPEM, caKey := selfSignedCert(t, "agent-a", time.Now().Add(-4*time.Hour), time.Now().Add(3*time.Hour))
	caDER, _, _ := certDER(t, certPEM)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	ts, _, hits := fakeRenewServer(t, caDER, caKey, pool, http.StatusInternalServerError)

	c, err := client.New(client.Config{BaseURL: ts.URL, CACert: serverCACertPEM(t, ts), ClientCert: certPEM, ClientKey: keyPEM})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "client-key.pem"), string(keyPEM))
	writeFile(t, filepath.Join(dir, "client.pem"), string(certPEM))
	m := NewManager(dir, "client-key.pem", "client.pem", certPEM, keyPEM)

	renewed, err := m.Tick(context.Background(), c, "tok")
	if err == nil {
		t.Fatal("Tick succeeded against a server that refused every renewal")
	}
	if renewed {
		t.Fatal("Tick reported renewed=true on failure")
	}
	if got := hits(); got != 1 {
		t.Fatalf("server hits = %d, want 1", got)
	}
	if string(m.CertPEM()) != string(certPEM) {
		t.Fatal("Manager's in-memory certificate changed after a failed renewal")
	}
	onDiskCert, rErr := os.ReadFile(filepath.Join(dir, "client.pem"))
	if rErr != nil {
		t.Fatalf("read live cert: %v", rErr)
	}
	if string(onDiskCert) != string(certPEM) {
		t.Fatal("live cert file changed after a failed renewal")
	}
	if _, err := os.Stat(filepath.Join(dir, "client.pem"+stagingSuffix)); !os.IsNotExist(err) {
		t.Fatal("a staging file was left behind after a failed renewal (the request itself failed before any write)")
	}
}

// certDER extracts the raw DER bytes of certPEM's single certificate.
func certDER(t *testing.T, certPEM []byte) (der []byte, cert *x509.Certificate, _ error) {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("certDER: no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("certDER: parse: %v", err)
	}
	return block.Bytes, cert, nil
}

// testCSR returns a syntactically valid CSR PEM for the fake server's
// own second-request smoke check above.
func testCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{SignatureAlgorithm: x509.ECDSAWithSHA256}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
