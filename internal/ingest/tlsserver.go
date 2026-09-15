package ingest

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// Timeouts and caps for the ingest listener specifically -- deliberately
// separate from cmd/birdcage/main.go's dashboard httpServer, which today
// sets only ReadHeaderTimeout. This listener faces boxes assumed to be
// compromised (issue #32's threat model), so every pre-auth bound
// net/http.Server offers is set explicitly (issue #32 research,
// 2026-09-15, "What the research changed" #2): a hostile client that
// never finishes sending headers, or a body, or a response read, or that
// opens a connection and idles it, is bounded the same way regardless of
// which phase it stalls in.
const (
	ingestReadHeaderTimeout = 5 * time.Second
	ingestReadTimeout       = 30 * time.Second
	ingestWriteTimeout      = 10 * time.Second
	ingestIdleTimeout       = 60 * time.Second
	// ingestMaxHeaderBytes bounds the total size of request headers this
	// server will parse, well above any real bearer-token-and-batch
	// request but far short of unbounded -- the countermeasure the CVE
	// research (CVE-2022-41717, CVE-2023-45288) names for header-driven
	// memory exhaustion.
	ingestMaxHeaderBytes = 16 * 1024
)

// NewTLSServer builds the *http.Server the ingest listener runs: HTTPS
// only, HTTP/1.1 only (Server.Protocols -- issue #32 research #1: Go
// enables HTTP/2 automatically on TLS servers, and the only client here
// is birdcage's own agent, so HTTP/2 buys nothing and inherits its own
// CVE class for free), TLS 1.3 floor, and every pre-auth timeout set
// (above).
//
// certFile/keyFile are loaded once, here, rather than left to
// ListenAndServeTLS to load at Serve time: an unloadable certificate or
// key must fail the caller loudly before anything binds a socket --
// issue #32's fail-closed rule, "the ingest listener refuses to start;
// no plaintext fallback". A caller that gets a non-nil error must not
// start any listener, plaintext or otherwise.
func NewTLSServer(addr string, handler http.Handler, certFile, keyFile string) (*http.Server, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("ingest: load TLS certificate/key: %w", err)
	}

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true) // HTTP/2 and unencrypted HTTP/2 both left false

	return &http.Server{
		Addr:    addr,
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
		},
		Protocols:         protocols,
		ReadHeaderTimeout: ingestReadHeaderTimeout,
		ReadTimeout:       ingestReadTimeout,
		WriteTimeout:      ingestWriteTimeout,
		IdleTimeout:       ingestIdleTimeout,
		MaxHeaderBytes:    ingestMaxHeaderBytes,
	}, nil
}
