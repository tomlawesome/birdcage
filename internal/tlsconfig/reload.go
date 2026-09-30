package tlsconfig

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// CertReloader serves an operator-supplied certificate/key pair
// (ModeCert) and reloads it from disk whenever either file's mtime
// changes, so renewing a certificate in place -- the normal operator
// workflow for e.g. a certbot renewal hook -- takes effect on the next
// handshake, no restart needed.
//
// A reload failure (the operator is mid-write, or the new pair doesn't
// parse) keeps serving the last good pair and logs a warning once per
// detected change, not on every handshake against a still-broken pair.
type CertReloader struct {
	certPath, keyPath string
	logger            *slog.Logger

	mu sync.Mutex
	// cert is the last good certificate -- always non-nil once New
	// returns successfully.
	cert *tls.Certificate
	// attemptedCertMTime/attemptedKeyMTime are the file mtimes (or the
	// zero value, standing for "could not stat") of the last pair this
	// reloader attempted to load, whether that attempt succeeded or
	// not. Comparing against these on every handshake -- rather than
	// against the mtimes of the currently-served cert -- is what makes
	// "warn once per change" hold even while the pair stays broken
	// across many handshakes.
	attemptedCertMTime, attemptedKeyMTime time.Time
}

// NewCertReloader loads certPath/keyPath once, immediately, and returns
// an error if that first load fails: unlike a later reload, there is no
// "last good pair" yet to fall back to, so a bad pair at startup is a
// startup error, matching issue #63's fail-closed rule.
func NewCertReloader(certPath, keyPath string, logger *slog.Logger) (*CertReloader, error) {
	r := &CertReloader{certPath: certPath, keyPath: keyPath, logger: logger}

	certMTime, keyMTime, err := r.statPair()
	if err != nil {
		return nil, fmt.Errorf("tlsconfig: stat dashboard TLS certificate/key: %w", err)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("tlsconfig: load dashboard TLS certificate/key: %w", err)
	}
	r.cert = &cert
	r.attemptedCertMTime, r.attemptedKeyMTime = certMTime, keyMTime
	return r, nil
}

// GetCertificate is a tls.Config.GetCertificate function: it stats both
// files on every call (cheap enough per handshake), and only re-reads
// and re-parses them when at least one mtime has moved since the last
// attempt. Safe for concurrent handshakes.
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	certMTime, keyMTime, statErr := r.statPair()
	if statErr == nil && certMTime.Equal(r.attemptedCertMTime) && keyMTime.Equal(r.attemptedKeyMTime) {
		return r.cert, nil
	}
	r.attemptedCertMTime, r.attemptedKeyMTime = certMTime, keyMTime

	if statErr != nil {
		r.logger.Warn(fmt.Sprintf("dashboard TLS certificate/key changed but could not be statted, still serving the last good pair: %v", statErr))
		return r.cert, nil
	}

	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		r.logger.Warn(fmt.Sprintf("dashboard TLS certificate/key changed but failed to reload, still serving the last good pair: %v", err))
		return r.cert, nil
	}
	r.cert = &cert
	return r.cert, nil
}

// statPair returns both files' mtimes, or a non-nil error naming
// whichever failed to stat -- the zero times returned alongside it are
// never used as real mtimes, only as GetCertificate's "could not stat"
// marker.
func (r *CertReloader) statPair() (certMTime, keyMTime time.Time, err error) {
	certInfo, err := os.Stat(r.certPath)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	keyInfo, err := os.Stat(r.keyPath)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return certInfo.ModTime(), keyInfo.ModTime(), nil
}
