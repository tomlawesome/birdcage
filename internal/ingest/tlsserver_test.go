package ingest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateSelfSignedCert writes a throwaway self-signed certificate and
// key (PEM) into dir, for tests that need something on disk for
// NewTLSServer to load. Not a stand-in for #47's enrolment CA -- purely
// a fixture, never used against a real network.
func generateSelfSignedCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ingest-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode certificate: %v", err)
	}
	if err := certOut.Close(); err != nil {
		t.Fatalf("close cert file: %v", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyOut, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("encode key: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		t.Fatalf("close key file: %v", err)
	}
	return certFile, keyFile
}

// TestNewTLSServerPinsHTTP1AndTLS13AndTimeouts checks the server
// construction issue #32's "what the research changed" section pins:
// HTTP/1.1 only, TLS 1.3 floor, and every pre-auth timeout/cap set
// (research #1 and #2). No network handshake is needed to verify these
// -- they're all fields on the returned *http.Server.
func TestNewTLSServerPinsHTTP1AndTLS13AndTimeouts(t *testing.T) {
	certFile, keyFile := generateSelfSignedCert(t, t.TempDir())

	srv, err := NewTLSServer("127.0.0.1:0", http.NotFoundHandler(), certFile, keyFile)
	if err != nil {
		t.Fatalf("NewTLSServer: %v", err)
	}

	if srv.TLSConfig == nil || srv.TLSConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("TLSConfig.MinVersion = %v, want tls.VersionTLS13", srv.TLSConfig)
	}
	if len(srv.TLSConfig.Certificates) != 1 {
		t.Errorf("TLSConfig.Certificates has %d entries, want 1", len(srv.TLSConfig.Certificates))
	}
	if srv.Protocols == nil || !srv.Protocols.HTTP1() {
		t.Error("Protocols does not enable HTTP/1.1")
	}
	if srv.Protocols != nil && (srv.Protocols.HTTP2() || srv.Protocols.UnencryptedHTTP2()) {
		t.Error("Protocols enables HTTP/2 or unencrypted HTTP/2; issue #32 pins HTTP/1.1 only")
	}
	if srv.ReadHeaderTimeout == 0 || srv.ReadTimeout == 0 || srv.WriteTimeout == 0 || srv.IdleTimeout == 0 {
		t.Errorf("one or more timeouts unset: ReadHeaderTimeout=%v ReadTimeout=%v WriteTimeout=%v IdleTimeout=%v",
			srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
	if srv.MaxHeaderBytes == 0 {
		t.Error("MaxHeaderBytes unset")
	}
}

// TestNewTLSServerRejectsUnloadableCertificate is issue #32's fail-closed
// rule for listener startup: "TLS certificate or key unloadable -> the
// ingest listener refuses to start, loudly. No plaintext fallback."
// NewTLSServer is the point that load happens; returning an error here,
// rather than a *http.Server a caller might start anyway, is what makes
// that refusal happen before any socket binds.
func TestNewTLSServerRejectsUnloadableCertificate(t *testing.T) {
	dir := t.TempDir()
	_, err := NewTLSServer("127.0.0.1:0", http.NotFoundHandler(), filepath.Join(dir, "missing-cert.pem"), filepath.Join(dir, "missing-key.pem"))
	if err == nil {
		t.Fatal("NewTLSServer with unloadable cert/key returned nil error, want an error")
	}
}
