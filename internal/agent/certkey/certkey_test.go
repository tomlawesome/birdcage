package certkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// TestGenerateKeyIsP256 proves GenerateKey returns an ECDSA key on the
// P-256 curve, as ADR-0012 B1 requires.
func TestGenerateKeyIsP256(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if key.Curve != elliptic.P256() {
		t.Fatalf("curve = %v, want P256", key.Curve)
	}
}

// TestMarshalParseKeyRoundTrips proves MarshalKeyPEM/ParseKeyPEM are
// inverses -- the pair loadOrGeneratePendingKey (enrolment) and the
// renewal package both depend on to reuse a key written by an earlier
// attempt.
func TestMarshalParseKeyRoundTrips(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyPEM, err := MarshalKeyPEM(key)
	if err != nil {
		t.Fatalf("MarshalKeyPEM: %v", err)
	}
	got, err := ParseKeyPEM(keyPEM)
	if err != nil {
		t.Fatalf("ParseKeyPEM: %v", err)
	}
	if got.X.Cmp(key.X) != 0 || got.Y.Cmp(key.Y) != 0 || got.D.Cmp(key.D) != 0 {
		t.Fatal("ParseKeyPEM did not round-trip the same key")
	}
}

// TestParseKeyPEMRejectsGarbage proves a corrupt or empty pending-key
// file is reported as an error, never a zero-value key -- the caller
// (loadOrGeneratePendingKey) relies on this to fall back to generating a
// fresh key rather than silently using something unusable.
func TestParseKeyPEMRejectsGarbage(t *testing.T) {
	if _, err := ParseKeyPEM([]byte("not a key")); err == nil {
		t.Fatal("ParseKeyPEM accepted garbage input")
	}
}

// TestBuildCSRIsValidP256AndSelfProves proves BuildCSR returns a PEM CSR
// whose signature verifies (proving possession of the private key) and
// whose public key is the same P-256 key it was built from -- the
// property #130's B1 depends on: birdcage only ever learns the public
// key from a CSR it can verify was signed by the matching private key.
func TestBuildCSRIsValidP256AndSelfProves(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csrPEM, err := BuildCSR(key)
	if err != nil {
		t.Fatalf("BuildCSR: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("BuildCSR did not return a CERTIFICATE REQUEST PEM block: %q", csrPEM)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CheckSignature: %v (CSR was not actually signed by its own key)", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("CSR public key type = %T, want *ecdsa.PublicKey", csr.PublicKey)
	}
	if pub.X.Cmp(key.PublicKey.X) != 0 || pub.Y.Cmp(key.PublicKey.Y) != 0 {
		t.Fatal("CSR public key does not match the key it was built from")
	}
	if csr.Subject.CommonName != SubjectPlaceholder {
		t.Fatalf("CSR CommonName = %q, want placeholder %q", csr.Subject.CommonName, SubjectPlaceholder)
	}
}

// selfSignedCert builds a minimal self-signed certificate with the given
// NotBefore/NotAfter, for HalfLife to parse.
func selfSignedCert(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "half-life-test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestHalfLifeIsMidpoint proves HalfLife computes exactly NotBefore +
// (NotAfter-NotBefore)/2, ADR-0012 B2's renewal trigger.
func TestHalfLifeIsMidpoint(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(7 * 24 * time.Hour)
	certPEM := selfSignedCert(t, notBefore, notAfter)

	got, err := HalfLife(certPEM)
	if err != nil {
		t.Fatalf("HalfLife: %v", err)
	}
	want := notBefore.Add(3*24*time.Hour + 12*time.Hour)
	if !got.Equal(want) {
		t.Fatalf("HalfLife = %v, want %v", got, want)
	}
}

// TestHalfLifeRejectsGarbage proves a missing or unparseable certificate
// is an error, never a zero-value time.Time (which would compare as
// already past and trigger renewal on every tick).
func TestHalfLifeRejectsGarbage(t *testing.T) {
	if _, err := HalfLife([]byte("not a certificate")); err == nil {
		t.Fatal("HalfLife accepted garbage input")
	}
}
