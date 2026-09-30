package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
)

// newTestDir returns a fresh directory at the exact mode Load requires
// (0700), owned by the test process -- t.TempDir() itself is already
// process-owned, but its mode depends on the platform/umask, so it's
// set explicitly here rather than assumed.
func newTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, dirPerm); err != nil {
		t.Fatalf("chmod test dir: %v", err)
	}
	return dir
}

func TestLoadGeneratesCAWithCorrectFileModes(t *testing.T) {
	dir := newTestDir(t)

	c, _, err := Load(dir, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Pin() == "" {
		t.Fatal("Pin() is empty")
	}

	keyInfo, err := os.Stat(filepath.Join(dir, caKeyFileName))
	if err != nil {
		t.Fatalf("stat CA key: %v", err)
	}
	if perm := keyInfo.Mode().Perm(); perm != keyPerm {
		t.Errorf("CA key mode = %04o, want %04o", perm, keyPerm)
	}
	if keyInfo.Mode().Perm()&0o077 != 0 {
		t.Errorf("CA key mode %04o is group- or world-accessible", keyInfo.Mode().Perm())
	}

	certInfo, err := os.Stat(filepath.Join(dir, caCertFileName))
	if err != nil {
		t.Fatalf("stat CA cert: %v", err)
	}
	if perm := certInfo.Mode().Perm(); perm != certPerm {
		t.Errorf("CA cert mode = %04o, want %04o", perm, certPerm)
	}
}

func TestLoadReusesExistingCA(t *testing.T) {
	dir := newTestDir(t)

	first, created, err := Load(dir, nil)
	if err != nil {
		t.Fatalf("first Load: %v", err)
	}
	if !created {
		t.Error("first Load reported created=false, want true")
	}
	second, created, err := Load(dir, nil)
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if created {
		t.Error("second Load reported created=true, want false")
	}

	if first.Pin() != second.Pin() {
		t.Errorf("Pin changed across Loads: first=%s second=%s", first.Pin(), second.Pin())
	}
}

func TestLoadRefusesWrongDirMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if _, _, err := Load(dir, nil); err == nil {
		t.Fatal("Load with 0755 dir returned nil error, want an error")
	}
}

func TestLoadCreatesMissingDirMode0700(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")

	if _, _, err := Load(dir, nil); err != nil {
		t.Fatalf("Load with missing dir: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat created dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("created dir mode = %04o, want 0700", perm)
	}
}

func TestLoadRefusesMissingParent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-parent", "ca")

	if _, _, err := Load(dir, nil); err == nil {
		t.Fatal("Load with missing parent returned nil error, want an error")
	}
}

func TestIssueServerLeafVerifiesAgainstPool(t *testing.T) {
	dir := newTestDir(t)
	c, _, err := Load(dir, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	cert, err := c.IssueServer([]string{"127.0.0.1", "localhost"}, time.Hour)
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	if len(cert.Certificate) != 2 {
		t.Fatalf("chain has %d entries, want 2 (leaf, CA)", len(cert.Certificate))
	}
	if string(cert.Certificate[1]) != string(c.der) {
		t.Error("chain[1] is not the CA certificate's DER")
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	opts := x509.VerifyOptions{
		DNSName: "localhost",
		Roots:   c.Pool(),
	}
	if _, err := leaf.Verify(opts); err != nil {
		t.Errorf("leaf.Verify against Pool(): %v", err)
	}
}

func TestIssueServerLeafFailsWithoutCAPool(t *testing.T) {
	dir := newTestDir(t)
	c, _, err := Load(dir, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	cert, err := c.IssueServer([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	emptyPool := x509.NewCertPool()
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: emptyPool}); err == nil {
		t.Fatal("leaf.Verify against an empty pool succeeded, want an error")
	}
}

func TestServerCertificateSourceRenewsAfterRenewalWindow(t *testing.T) {
	dir := newTestDir(t)
	c, _, err := Load(dir, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	current := time.Now()
	now := func() time.Time { return current }

	source := c.ServerCertificateSource([]string{"127.0.0.1"}, time.Hour, 10*time.Minute, now)

	first, err := source(nil)
	if err != nil {
		t.Fatalf("source (first call): %v", err)
	}

	second, err := source(nil)
	if err != nil {
		t.Fatalf("source (second call, no time passed): %v", err)
	}
	if first != second {
		t.Error("source re-minted without the clock moving into the renewal window")
	}

	// Advance to inside the 10-minute renewal window (ttl=1h): 51
	// minutes in means 9 minutes to expiry, inside the window.
	current = current.Add(51 * time.Minute)

	third, err := source(nil)
	if err != nil {
		t.Fatalf("source (after renewal window): %v", err)
	}
	if third == first {
		t.Error("source did not re-mint after entering the renewal window")
	}
}

// newCSR builds a CSR over key with the requested template -- the
// agent's side of ADR-0012 B1, done here with nothing but crypto/x509.
func newCSR(t *testing.T, key crypto.Signer, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	if tmpl == nil {
		tmpl = &x509.CertificateRequest{}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	return key
}

func loadTestCA(t *testing.T) *CA {
	t.Helper()
	c, _, err := Load(newTestDir(t), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

// TestSignClientSignsTheRequestersKey is ADR-0012 B1's positive case:
// the certificate carries the CSR's public key, is client-auth, chains
// to the CA, and pairs with the private key only the requester holds.
func TestSignClientSignsTheRequestersKey(t *testing.T) {
	c := loadTestCA(t)
	key := newP256(t)

	csr, err := ParseClientCSR(newCSR(t, key, nil))
	if err != nil {
		t.Fatalf("ParseClientCSR: %v", err)
	}
	certPEM, leaf, err := c.SignClient(csr, "canary-1", agentkind.Honeypot, time.Hour)
	if err != nil {
		t.Fatalf("SignClient: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("certificate does not pair with the requester's key: %v", err)
	}

	if leaf.Subject.CommonName != "canary-1" {
		t.Errorf("CommonName = %q, want %q", leaf.Subject.CommonName, "canary-1")
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want exactly client auth", leaf.ExtKeyUsage)
	}
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got < time.Hour || got > time.Hour+10*time.Minute {
		t.Errorf("validity = %s, want about ttl (1h) plus the 5-minute backdate", got)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: c.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("leaf does not verify against the CA: %v", err)
	}
}

// TestSignClientSetsOrganizationalUnitToKind is issue #106's required
// unit test carried over from IssueClient: exactly one OU, naming the
// kind SignClient was given.
func TestSignClientSetsOrganizationalUnitToKind(t *testing.T) {
	c := loadTestCA(t)
	csr, err := ParseClientCSR(newCSR(t, newP256(t), nil))
	if err != nil {
		t.Fatalf("ParseClientCSR: %v", err)
	}
	_, leaf, err := c.SignClient(csr, "canary-1", agentkind.Scanner, time.Hour)
	if err != nil {
		t.Fatalf("SignClient: %v", err)
	}
	ou := leaf.Subject.OrganizationalUnit
	if len(ou) != 1 {
		t.Fatalf("OrganizationalUnit = %v, want exactly one value", ou)
	}
	if ou[0] != string(agentkind.Scanner) {
		t.Errorf("OrganizationalUnit[0] = %q, want %q", ou[0], agentkind.Scanner)
	}
}

// TestSignClientKeepsNothingButThePublicKey is B1's "nothing from the
// CSR but the public key survives": a CSR asking for another canary's
// CN, a different kind, extra OUs, SANs, and a CA basic-constraints
// extension gets none of it.
func TestSignClientKeepsNothingButThePublicKey(t *testing.T) {
	c := loadTestCA(t)
	bc, err := asn1.Marshal(struct {
		IsCA bool `asn1:"optional"`
	}{IsCA: true})
	if err != nil {
		t.Fatalf("marshal basic constraints: %v", err)
	}
	csrPEM := newCSR(t, newP256(t), &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         "someone-elses-canary",
			OrganizationalUnit: []string{string(agentkind.Scanner), "admin"},
			Organization:       []string{"evil"},
		},
		DNSNames:       []string{"birdcage.example"},
		EmailAddresses: []string{"root@example.invalid"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.1")},
		URIs:           []*url.URL{{Scheme: "spiffe", Host: "x", Path: "/admin"}},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: bc},
		},
	})
	csr, err := ParseClientCSR(csrPEM)
	if err != nil {
		t.Fatalf("ParseClientCSR: %v", err)
	}
	_, leaf, err := c.SignClient(csr, "registry-id", agentkind.Honeypot, time.Hour)
	if err != nil {
		t.Fatalf("SignClient: %v", err)
	}

	if leaf.Subject.CommonName != "registry-id" {
		t.Errorf("CommonName = %q, want the registry's id", leaf.Subject.CommonName)
	}
	if len(leaf.Subject.OrganizationalUnit) != 1 || leaf.Subject.OrganizationalUnit[0] != string(agentkind.Honeypot) {
		t.Errorf("OrganizationalUnit = %v, want exactly [honeypot]", leaf.Subject.OrganizationalUnit)
	}
	if len(leaf.Subject.Organization) != 0 {
		t.Errorf("Organization = %v, want none", leaf.Subject.Organization)
	}
	if len(leaf.DNSNames)+len(leaf.EmailAddresses)+len(leaf.IPAddresses)+len(leaf.URIs) != 0 {
		t.Errorf("SANs survived: dns=%v email=%v ip=%v uri=%v", leaf.DNSNames, leaf.EmailAddresses, leaf.IPAddresses, leaf.URIs)
	}
	if leaf.IsCA || leaf.BasicConstraintsValid {
		t.Errorf("IsCA=%v BasicConstraintsValid=%v, want neither", leaf.IsCA, leaf.BasicConstraintsValid)
	}
	if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
		t.Error("certificate's public key is not the CSR's")
	}
}

// TestParseClientCSRRefuses covers every CSR shape B1 refuses. Each
// case fails without its own check in ParseClientCSR/checkClientCSR.
func TestParseClientCSRRefuses(t *testing.T) {
	good := newCSR(t, newP256(t), nil)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}

	// A CSR whose signature does not match its key: flip one bit in the
	// signature at the end of the DER.
	block, _ := pem.Decode(good)
	tampered := append([]byte(nil), block.Bytes...)
	tampered[len(tampered)-2] ^= 0x01
	badSig := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered})

	// A CSR carrying key A but signed by key B: splice B's signature onto
	// A's request body.
	a := newCSR(t, newP256(t), &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}})
	b := newCSR(t, newP256(t), &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}})
	aReq, _ := pem.Decode(a)
	bReq, _ := pem.Decode(b)
	pa, err := x509.ParseCertificateRequest(aReq.Bytes)
	if err != nil {
		t.Fatalf("parse a: %v", err)
	}
	pb, err := x509.ParseCertificateRequest(bReq.Bytes)
	if err != nil {
		t.Fatalf("parse b: %v", err)
	}
	spliced, err := asn1.Marshal(struct {
		Raw       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{
		Raw:       asn1.RawValue{FullBytes: pa.RawTBSCertificateRequest},
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		Signature: asn1.BitString{Bytes: pb.Signature, BitLength: 8 * len(pb.Signature)},
	})
	if err != nil {
		t.Fatalf("marshal spliced CSR: %v", err)
	}
	wrongSigner := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: spliced})

	cases := map[string][]byte{
		"empty":               nil,
		"not PEM":             []byte("hello"),
		"certificate block":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}),
		"private key block":   pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
		"garbage DER":         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{1, 2, 3}}),
		"trailing block":      append(append([]byte(nil), good...), good...),
		"trailing junk":       append(append([]byte(nil), good...), []byte("junk")...),
		"PEM headers":         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: block.Bytes}),
		"RSA key":             newCSR(t, rsaKey, nil),
		"P-384 key":           newCSR(t, p384, nil),
		"Ed25519 key":         newCSR(t, edKey, nil),
		"tampered signature":  badSig,
		"signed by other key": wrongSigner,
		"oversized":           append(append([]byte(nil), good...), bytes.Repeat([]byte(" "), maxCSRPEMBytes)...),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			csr, err := ParseClientCSR(in)
			if err == nil {
				t.Fatalf("ParseClientCSR accepted it: %+v", csr.Subject)
			}
			if !errors.Is(err, ErrInvalidCSR) {
				t.Errorf("err = %v, want it to wrap ErrInvalidCSR", err)
			}
		})
	}

	t.Run("SignClient re-checks a parsed CSR", func(t *testing.T) {
		c := loadTestCA(t)
		der, _ := pem.Decode(newCSR(t, rsaKey, nil))
		csr, err := x509.ParseCertificateRequest(der.Bytes)
		if err != nil {
			t.Fatalf("parse RSA CSR: %v", err)
		}
		if _, _, err := c.SignClient(csr, "canary-1", agentkind.Honeypot, time.Hour); !errors.Is(err, ErrInvalidCSR) {
			t.Errorf("SignClient(RSA CSR) err = %v, want ErrInvalidCSR", err)
		}
		if _, _, err := c.SignClient(nil, "canary-1", agentkind.Honeypot, time.Hour); !errors.Is(err, ErrInvalidCSR) {
			t.Errorf("SignClient(nil) err = %v, want ErrInvalidCSR", err)
		}
	})
}
