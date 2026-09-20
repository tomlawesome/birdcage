// Package tlsconfig implements issue #63's rule for the dashboard HTTP
// listener (cmd/birdcage's httpServer): it must never be plain HTTP
// reachable off the loopback interface. Four modes are permitted -- an
// operator-supplied certificate and key (Select's ModeCert), a
// certificate birdcage mints itself from its own CA (ModeMintedCert,
// the default when no operator certificate is configured and the
// address isn't loopback or a unix socket), or plain HTTP bound
// strictly to loopback or a unix socket (ModePlainLoopbackTCP /
// ModePlainUnixSocket) -- and Select never chooses a fifth. ACME was
// considered and dropped (owner decision, issue #63: "the point isn't
// to provide termination externally for everyone, the point is not to
// serve the dash in http ever"); it needs a third-party Go module this
// project has not approved and is out of scope.
//
// This package is deliberately independent of internal/ingest, which
// applies the same TLS floor and HTTP/1.1-only posture to a different
// listener (the canary ingest/enrolment listeners, also minted from
// birdcage's own CA) -- the two packages duplicate a few lines of
// tls.Config/http.Protocols setup rather than one importing the other,
// so a change to the ingest listener's certificate source can never
// accidentally reach the dashboard's.
package tlsconfig

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Mode is which of the four permitted ways (issue #63) the dashboard
// HTTP listener runs.
type Mode int

const (
	// ModeCert serves HTTPS on the configured address using an
	// operator-supplied certificate and key (BIRDCAGE_HTTP_TLS_CERT /
	// BIRDCAGE_HTTP_TLS_KEY).
	ModeCert Mode = iota + 1
	// ModeMintedCert serves HTTPS on the configured address using a leaf
	// certificate birdcage mints itself from its own CA (internal/ca) --
	// the default (issue #63, owner decision 2026-09-20) whenever no
	// operator certificate is configured and the address is neither
	// loopback nor a unix socket. A browser warns until the operator
	// installs birdcage's CA; see docs/configuration.md#dashboard-tls.
	ModeMintedCert
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

// Select decides which of the four permitted dashboard-listener modes
// (issue #63, owner decision "we must never allow the GUI to run
// without https in some form") addr/certPath/keyPath describe, or
// returns a refusal when addr itself cannot be used at all (not a
// valid host:port, or a unix socket with a relative path). There is no
// fifth mode and no plaintext override: an address whose host is empty
// (the default BIRDCAGE_HTTP_ADDR=:8080), 0.0.0.0, or any other
// non-loopback host, with no certificate configured, now selects
// ModeMintedCert rather than refusing -- birdcage mints its own
// certificate from its own CA (internal/ca) instead of ever falling
// back to a plaintext listener.
//
// certPath and keyPath must both be set or both be empty; exactly one
// set is a refusal, not a guess at what the operator meant.
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
	if err != nil {
		// Not a parseable host:port at all (no port, or empty) -- there
		// is no address here to mint a certificate for or bind either
		// way, so this is the one case Select still refuses outright.
		return Selection{}, refusal(addr)
	}
	if isLoopbackHost(host) {
		return Selection{Mode: ModePlainLoopbackTCP, Addr: addr}, nil
	}
	// Any other host -- including the default's empty host and
	// 0.0.0.0 -- gets a certificate birdcage mints itself rather than a
	// refusal or a plaintext listener. See internal/ca and
	// DashboardHosts for which names that certificate covers.
	return Selection{Mode: ModeMintedCert, Addr: addr}, nil
}

func isLoopbackHost(host string) bool {
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

// refusal is Select's message for an address that cannot be used at
// all: not a parseable host:port, and not an absolute unix socket
// path. Every other case now has a mode -- an operator certificate, a
// certificate birdcage mints from its own CA, or plain HTTP strictly
// on loopback or a unix socket -- so this never fires for "no
// certificate configured" alone.
func refusal(addr string) error {
	return fmt.Errorf(
		"tlsconfig: refusing to start the dashboard: BIRDCAGE_HTTP_ADDR=%q is not a usable address -- "+
			"it must be host:port (any host is accepted: birdcage mints its own certificate when none is configured, "+
			"unless the host is loopback, which serves plain HTTP instead) or unix:///path/to.sock with an absolute path",
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
