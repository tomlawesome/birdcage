// Package ca implements birdcage's own certificate authority for the
// canary ingest listener (issue #47 slice 1, design note decision 3;
// #62 owner decision "Drop them": birdcage mints its own certificates
// rather than an operator supplying cert/key files by hand).
//
// The CA's private key (ca-key.pem, on disk under the configured CA
// directory) is the only private key this package -- or, per #62, this
// slice of birdcage at all -- ever writes to a file. Every certificate
// issued after that (the ingest listener's serving leaf today; a
// canary's client certificate once a later slice provisions it) is
// minted in memory and handed to its caller as PEM or a
// tls.Certificate, never written anywhere.
package ca

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
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const (
	caKeyFileName  = "ca-key.pem"
	caCertFileName = "ca.pem"

	caCommonName = "birdcage-ca"
	caValidity   = 10 * 365 * 24 * time.Hour

	// caServerCommonName/caClientCommonNamePrefix name the leaf
	// certificates IssueServer/IssueClient mint -- cosmetic only, since
	// nothing in this codebase authorizes on CommonName; SANs (server)
	// and the enrolment record keyed by canary ID (client, a later
	// slice) do that.
	caServerCommonName = "birdcage-ingest"

	// dirPerm is the exact mode Load requires of the CA directory --
	// not "at least this restrictive", exact, so a directory that is
	// e.g. 0750 (readable by a group) fails loudly rather than being
	// silently accepted. keyPerm/certPerm are the exact modes Load
	// writes ca-key.pem/ca.pem with, set explicitly via Chmod after
	// creation since a file's O_CREATE mode argument is filtered by the
	// process umask and so isn't trustworthy on its own (#62: the key
	// file must never be created world- or group-readable).
	dirPerm  = 0o700
	keyPerm  = 0o600
	certPerm = 0o644
)

// CA is birdcage's certificate authority: one ECDSA P-256 key pair and
// self-signed certificate, produced by Load, used to sign every other
// certificate this package issues.
type CA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	der  []byte // cert.Raw -- kept explicitly so Pin/CertPEM never re-derive it
}

// Load loads the CA key and certificate from dir/ca-key.pem and
// dir/ca.pem. The first time it is called against a dir holding
// neither file, it generates a fresh ECDSA P-256 CA key and a
// self-signed CA certificate and persists both before returning --
// every later Load against the same dir reuses that CA (same Pin).
//
// dir must already exist and be mode 0700, owned by the calling
// process; Load never creates or loosens it, since a directory it
// didn't create itself might be shared with another user or process,
// and this is the one place in birdcage a private key touches disk.
//
// now is injected rather than calling time.Now directly so a test can
// drive the generated certificate's NotBefore/NotAfter without an real
// clock; nil means time.Now.
func Load(dir string, now func() time.Time) (*CA, error) {
	if now == nil {
		now = time.Now
	}

	if err := checkDir(dir); err != nil {
		return nil, err
	}

	keyPath := filepath.Join(dir, caKeyFileName)
	certPath := filepath.Join(dir, caCertFileName)

	keyPEM, keyErr := os.ReadFile(keyPath)
	certPEM, certErr := os.ReadFile(certPath)

	switch {
	case keyErr == nil && certErr == nil:
		return parseCA(keyPEM, certPEM)
	case os.IsNotExist(keyErr) && os.IsNotExist(certErr):
		return generateCA(dir, now())
	default:
		// Exactly one of the two present (or a read error that isn't
		// "missing") is never treated as "generate a fresh one" -- that
		// would silently orphan or overwrite whichever file did exist.
		if keyErr != nil && !os.IsNotExist(keyErr) {
			return nil, fmt.Errorf("ca: read %s: %w", keyPath, keyErr)
		}
		if certErr != nil && !os.IsNotExist(certErr) {
			return nil, fmt.Errorf("ca: read %s: %w", certPath, certErr)
		}
		return nil, fmt.Errorf("ca: %s has only one of %s/%s -- refusing to guess which is stale", dir, caKeyFileName, caCertFileName)
	}
}

// checkDir enforces Load's "must already exist, mode 0700, owned by the
// calling process" precondition.
func checkDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("ca: %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("ca: %s is not a directory", dir)
	}
	if perm := info.Mode().Perm(); perm != dirPerm {
		return fmt.Errorf("ca: %s has mode %04o, want %04o", dir, perm, dirPerm)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("ca: %s: cannot determine directory owner on this platform", dir)
	}
	if uid := os.Geteuid(); uid >= 0 && st.Uid != uint32(uid) {
		return fmt.Errorf("ca: %s is owned by uid %d, not this process (uid %d)", dir, st.Uid, uid)
	}
	return nil
}

func parseCA(keyPEM, certPEM []byte) (*CA, error) {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("ca: decode CA key PEM: no block found")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse CA key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("ca: decode CA certificate PEM: no block found")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse CA certificate: %w", err)
	}

	return &CA{key: key, cert: cert, der: certBlock.Bytes}, nil
}

func generateCA(dir string, now time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generate CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("ca: generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: caCommonName},
		NotBefore:             now.Add(-5 * time.Minute), // clock-skew slack
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("ca: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: parse generated CA certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("ca: marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	// Key written before certificate: if the process dies between the
	// two, the next Load sees "only one of the two present" and refuses
	// to guess rather than silently regenerating over a key that might
	// already be trusted elsewhere.
	if err := writeFileExcl(filepath.Join(dir, caKeyFileName), keyPEM, keyPerm); err != nil {
		return nil, fmt.Errorf("ca: write CA key: %w", err)
	}
	if err := writeFileExcl(filepath.Join(dir, caCertFileName), certPEM, certPerm); err != nil {
		return nil, fmt.Errorf("ca: write CA certificate: %w", err)
	}

	return &CA{key: key, cert: cert, der: der}, nil
}

// writeFileExcl writes data to path by creating a temp file in the same
// directory (so the rename below is same-filesystem and therefore
// atomic), exclusively -- os.CreateTemp itself uses O_EXCL -- setting
// perm explicitly, then renaming into place. A crash or kill at any
// point before the rename leaves at most a stray temp file, never a
// half-written ca-key.pem.
func writeFileExcl(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		if err != nil {
			os.Remove(tmpPath)
		}
	}()

	if err = tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return err
	}
	return nil
}

// Pin returns the lowercase hex SHA-256 digest of the CA certificate's
// DER encoding -- the value a later slice's enrolment command hands a
// canary operator to pin against, so a substituted or spoofed CA is
// detectable rather than trusted silently.
func (c *CA) Pin() string {
	sum := sha256.Sum256(c.der)
	return hex.EncodeToString(sum[:])
}

// CertPEM returns the CA certificate, PEM-encoded.
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
}

// Expiry returns the CA certificate's NotAfter, for boot-inventory
// logging.
func (c *CA) Expiry() time.Time {
	return c.cert.NotAfter
}

// Pool returns an x509.CertPool containing only the CA certificate --
// for verifying a leaf this package issued (tests, and later a
// client's RootCAs) and, once mTLS lands in a later slice, for
// tls.Config.ClientCAs.
func (c *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.cert)
	return pool
}

// IssueServer mints a fresh ECDSA P-256 key and server-auth leaf
// certificate, valid for ttl, entirely in memory -- #62's decision that
// only the CA key is ever a file. Each entry in hosts becomes an IP SAN
// if it parses as one, otherwise a DNS SAN, so both a literal address
// and a hostname work without the caller sorting them itself.
//
// The returned tls.Certificate's chain is the leaf followed by the CA
// certificate, in that order, so a client verifying the handshake finds
// the CA it already trusts inside the presented chain rather than
// needing it supplied out of band.
func (c *CA) IssueServer(hosts []string, ttl time.Duration) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ca: generate server key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ca: generate serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: caServerCommonName},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ca: create server certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ca: parse server certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der, c.der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// IssueClient mints a fresh ECDSA P-256 key and client-auth leaf
// certificate for canaryID (used as the certificate's CommonName),
// valid for ttl. Returned as PEM, nothing written to disk -- for a
// later slice's enrolment endpoint to hand a canary once mTLS lands;
// this slice does not call it from anywhere.
func (c *CA) IssueClient(canaryID string, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: generate client key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("ca: generate serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: canaryID},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: create client certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: marshal client key: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// ServerCertificateSource returns a tls.Config.GetCertificate function
// that mints a serving leaf for hosts on its first call, and re-mints
// (in memory -- the old value is simply dropped, nothing to clean up on
// disk) whenever the current leaf is within renewBefore of its
// NotAfter as measured by now(). now is injected, like Load's, so a
// test can drive renewal without an real clock; nil means time.Now.
// Safe for concurrent handshakes.
func (c *CA) ServerCertificateSource(hosts []string, ttl, renewBefore time.Duration, now func() time.Time) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if now == nil {
		now = time.Now
	}

	var (
		mu      sync.Mutex
		current *tls.Certificate
	)

	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		mu.Lock()
		defer mu.Unlock()

		if current == nil || !now().Before(current.Leaf.NotAfter.Add(-renewBefore)) {
			cert, err := c.IssueServer(hosts, ttl)
			if err != nil {
				return nil, err
			}
			current = &cert
		}
		return current, nil
	}
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
