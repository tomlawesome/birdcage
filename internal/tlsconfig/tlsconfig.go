// Package tlsconfig implements issue #63's rule for the dashboard HTTP
// listener (cmd/birdcage's httpServer): it must never be plain HTTP
// reachable off the loopback interface. Exactly three modes are
// permitted -- an operator-supplied certificate and key (Select's
// ModeCert), plain HTTP bound strictly to loopback or a unix socket
// (ModePlainLoopbackTCP / ModePlainUnixSocket), or ACME (not
// implemented yet, see Select's doc comment) -- and Select refuses
// startup with one message naming all three rather than ever choosing a
// fourth.
//
// This package is deliberately independent of internal/ingest, which
// applies the same TLS floor and HTTP/1.1-only posture to a different
// listener (the canary ingest/enrolment listeners, minted from
// birdcage's own CA rather than an operator-supplied pair) -- the two
// packages duplicate a few lines of tls.Config/http.Protocols setup
// rather than one importing the other, so a change to the ingest
// listener's certificate source can never accidentally reach the
// dashboard's.
package tlsconfig

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Mode is which of the three permitted ways (issue #63) the dashboard
// HTTP listener runs.
type Mode int

const (
	// ModeCert serves HTTPS on the configured address using an
	// operator-supplied certificate and key (BIRDCAGE_HTTP_TLS_CERT /
	// BIRDCAGE_HTTP_TLS_KEY).
	ModeCert Mode = iota + 1
	// ModePlainLoopbackTCP serves plain HTTP on a TCP address whose host
	// is 127.0.0.1, ::1 or localhost.
	ModePlainLoopbackTCP
	// ModePlainUnixSocket serves plain HTTP on a unix domain socket
	// (BIRDCAGE_HTTP_ADDR=unix:///path/to.sock).
	ModePlainUnixSocket
)

// unixSocketPrefix is BIRDCAGE_HTTP_ADDR's syntax for ModePlainUnixSocket:
// "unix://" followed by an absolute path, e.g. "unix:///run/birdcage.sock".
const unixSocketPrefix = "unix://"

// Selection is what Select decided: which mode applies, and the
// concrete listen target for it.
type Selection struct {
	Mode Mode
	// Addr is the TCP listen address for ModeCert and
	// ModePlainLoopbackTCP; empty for ModePlainUnixSocket.
	Addr string
	// UnixPath is the socket path for ModePlainUnixSocket; empty
	// otherwise.
	UnixPath string
}

// Select decides which of the three permitted dashboard-listener modes
// (issue #63, owner decision "we must never allow the GUI to run
// without https in some form") addr/certPath/keyPath describe, or
// returns a refusal naming all three modes and the two TLS variables.
// There is no fourth mode and no override: an address whose host is
// empty (the default BIRDCAGE_HTTP_ADDR=:8080), 0.0.0.0, or any
// non-loopback host, with no certificate configured, always refuses --
// it never falls back to a plaintext listener.
//
// certPath and keyPath must both be set or both be empty; exactly one
// set is a refusal, not a guess at what the operator meant.
//
// Refs #63: ACME mode is not implemented yet -- a dependency decision
// the owner has not made. When it lands it becomes this function's
// third selectable mode; today it is only named in the refusal message
// below, as "not yet available".
func Select(addr, certPath, keyPath string) (Selection, error) {
	if (certPath == "") != (keyPath == "") {
		return Selection{}, fmt.Errorf(
			"tlsconfig: BIRDCAGE_HTTP_TLS_CERT and BIRDCAGE_HTTP_TLS_KEY must both be set or both unset (got cert=%q key=%q)",
			certPath, keyPath,
		)
	}
	if certPath != "" {
		return Selection{Mode: ModeCert, Addr: addr}, nil
	}

	if path, ok := strings.CutPrefix(addr, unixSocketPrefix); ok {
		if !strings.HasPrefix(path, "/") {
			return Selection{}, refusal(addr)
		}
		return Selection{Mode: ModePlainUnixSocket, UnixPath: path}, nil
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil || !isLoopbackHost(host) {
		return Selection{}, refusal(addr)
	}
	return Selection{Mode: ModePlainLoopbackTCP, Addr: addr}, nil
}

func isLoopbackHost(host string) bool {
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

// refusal is Select's one refusal message, naming all three permitted
// modes and both TLS variables -- never a fourth possibility, and never
// a plaintext listener reachable off loopback.
func refusal(addr string) error {
	return fmt.Errorf(
		"tlsconfig: refusing to start the dashboard: BIRDCAGE_HTTP_ADDR=%s is neither loopback nor a unix socket, and no certificate is configured. "+
			"The dashboard must run one of three ways: "+
			"(1) HTTPS -- set BIRDCAGE_HTTP_TLS_CERT and BIRDCAGE_HTTP_TLS_KEY to PEM file paths; "+
			"(2) plain HTTP bound strictly to loopback -- BIRDCAGE_HTTP_ADDR with host 127.0.0.1, ::1 or localhost, or unix:///path/to.sock; "+
			"or (3) ACME (not yet available). It will never fall back to a plaintext listener reachable off loopback",
		addr,
	)
}

// HardenedTLSConfig returns the *tls.Config ModeCert's HTTPS listener
// uses: TLS 1.3 minimum, the same floor internal/ingest/tlsserver.go
// applies to the canary ingest listener. getCertificate supplies the
// serving certificate per handshake -- see CertReloader.GetCertificate.
func HardenedTLSConfig(getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: getCertificate,
	}
}

// HTTP1Only returns the *http.Protocols value that restricts a TLS
// server to HTTP/1.1 -- matching internal/ingest/tlsserver.go's
// reasoning: Go enables HTTP/2 automatically on TLS servers, and a
// browser dashboard gains nothing from this package taking on HTTP/2's
// own CVE class for a listener that isn't proxying anything latency
// sensitive enough to need it.
func HTTP1Only() *http.Protocols {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true) // HTTP/2 and unencrypted HTTP/2 both left false
	return protocols
}
