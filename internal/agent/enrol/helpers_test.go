package enrol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// This file builds the certificate chains FirstContact's tests need by
// hand, via crypto/x509 directly -- not internal/ca, which this package
// must never import (scripts/agent-deps-check.sh's fence; this package
// ships on the canary).

// genCA returns a freshly generated, self-signed CA certificate (DER and
// parsed) and its private key.
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

// genLeaf returns a server leaf certificate (DER) signed by caCert/caKey,
// valid for 127.0.0.1 -- the address every httptest.Server in this file
// listens on.
func genLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (der []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "enrol-test-leaf"},
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

// pinFor returns der's SHA-256 fingerprint, lower-case hex -- the same
// value MOCKINGBIRD_CA_PIN carries in production.
func pinFor(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// pemCert PEM-encodes a raw DER certificate.
func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// newChainServer starts an httptest TLS server presenting exactly the
// leaf/intermediate DER chain given (leaf first), backed by leafKey, and
// serving handler -- handler is nil-safe to plug per test.
func newChainServer(t *testing.T, chain [][]byte, leafKey *ecdsa.PrivateKey, handler http.Handler) *httptest.Server {
	t.Helper()
	if handler == nil {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
	}
	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: chain,
			PrivateKey:  leafKey,
		}},
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}
