package tlsconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mintTestCert generates a fresh self-signed ECDSA P-256 certificate
// for "127.0.0.1", using crypto/x509 directly rather than
// internal/ca -- this package's tests stand on their own, independent
// of the CA package's own generation logic. commonName is embedded so a
// test can tell two minted certificates apart after a handshake.
func mintTestCert(t *testing.T, commonName string) (certPEM, keyPEM []byte) {
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
		Subject:      pkix.Name{CommonName: commonName},
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

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// writeTestCert writes certPEM/keyPEM to dir/cert.pem and dir/key.pem
// (creating them the first time, overwriting on a later call), and sets
// their mtimes explicitly to mtime -- rather than relying on the
// filesystem's own clock, whose resolution can be coarser than a fast
// test's two writes are apart, which would make CertReloader's "did the
// mtime change" check flaky.
func writeTestCert(t *testing.T, dir string, certPEM, keyPEM []byte, mtime time.Time) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.Chtimes(certPath, mtime, mtime); err != nil {
		t.Fatalf("chtimes cert: %v", err)
	}
	if err := os.Chtimes(keyPath, mtime, mtime); err != nil {
		t.Fatalf("chtimes key: %v", err)
	}
	return certPath, keyPath
}

// handshakeCommonName dials addr over TLS (trusting whatever
// certificate is presented -- this test cares which key pair the
// server chose, not chain validation, which internal/ca's own tests
// already cover) and returns the presented leaf's CommonName.
func handshakeCommonName(t *testing.T, addr string) string {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer func() { _ = conn.Close() }() // test teardown; nothing left to act on a close error
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatalf("dial %s: no certificate presented", addr)
	}
	return state.PeerCertificates[0].Subject.CommonName
}

func TestCertReloaderReloadsOnMTimeChange(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	certPEM1, keyPEM1 := mintTestCert(t, "first-cert")
	certPath, keyPath := writeTestCert(t, dir, certPEM1, keyPEM1, time.Now())

	reloader, err := NewCertReloader(certPath, keyPath, logger)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }() // test teardown; nothing left to act on a close error

	tlsConfig := HardenedTLSConfig(reloader.GetCertificate)
	server := &tls.Config{MinVersion: tlsConfig.MinVersion, GetCertificate: tlsConfig.GetCertificate}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()      // test teardown; nothing left to act on a close error
				_ = tls.Server(conn, server).Handshake() // server side of the test handshake; failures surface as a client-side timeout/error below
			}()
		}
	}()

	if got := handshakeCommonName(t, ln.Addr().String()); got != "first-cert" {
		t.Fatalf("first handshake CommonName = %q, want %q", got, "first-cert")
	}

	// Rewrite with a second pair, mtime strictly after the first --
	// this is the "operator renews a certificate in place" case #63
	// asks for: the next handshake must present the new pair without a
	// restart.
	certPEM2, keyPEM2 := mintTestCert(t, "second-cert")
	writeTestCert(t, dir, certPEM2, keyPEM2, time.Now().Add(time.Hour))

	if got := handshakeCommonName(t, ln.Addr().String()); got != "second-cert" {
		t.Fatalf("second handshake CommonName = %q, want %q (reload after mtime change)", got, "second-cert")
	}
}

func TestCertReloaderKeepsLastGoodPairOnReloadFailure(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	certPEM1, keyPEM1 := mintTestCert(t, "good-cert")
	certPath, keyPath := writeTestCert(t, dir, certPEM1, keyPEM1, time.Now())

	reloader, err := NewCertReloader(certPath, keyPath, logger)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}

	// Corrupt the key file (as if caught mid-write by a renewal script)
	// and move the mtime forward so GetCertificate attempts a reload.
	if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("corrupt key: %v", err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(keyPath, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	cert, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate after corrupt reload: %v", err)
	}
	if cert.Leaf == nil {
		// tls.LoadX509KeyPair doesn't set Leaf; parse to check identity.
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("parse returned certificate: %v", err)
		}
		cert.Leaf = parsed
	}
	if cert.Leaf.Subject.CommonName != "good-cert" {
		t.Fatalf("GetCertificate after corrupt reload returned CommonName %q, want the last good pair %q", cert.Leaf.Subject.CommonName, "good-cert")
	}
}

func TestNewCertReloaderFailsOnBadInitialPair(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, []byte("not a cert"), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	if _, err := NewCertReloader(certPath, keyPath, slog.New(slog.NewTextHandler(os.Stderr, nil))); err == nil {
		t.Fatal("NewCertReloader with an invalid initial pair returned no error")
	}
}
