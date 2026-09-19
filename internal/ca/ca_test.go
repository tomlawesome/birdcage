package ca

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestIssueClientReturnsClientAuthCertificate(t *testing.T) {
	dir := newTestDir(t)
	c, _, err := Load(dir, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	certPEM, keyPEM, err := c.IssueClient("canary-1", time.Hour)
	if err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("IssueClient returned empty PEM")
	}

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.Subject.CommonName != "canary-1" {
		t.Errorf("CommonName = %q, want %q", leaf.Subject.CommonName, "canary-1")
	}
	found := false
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			found = true
		}
	}
	if !found {
		t.Error("leaf does not have ExtKeyUsageClientAuth")
	}
}
