package ingest

import (
	"crypto/tls"
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
// getCertificate supplies the serving certificate per handshake --
// since #47 slice 1, internal/ca.CA.ServerCertificateSource, which mints
// and renews it in memory, rather than a certFile/keyFile pair loaded
// from disk (issue #32's original placeholder, retired by #62's "Drop
// them"). Any fail-closed startup check belongs to whatever produced
// getCertificate (internal/ca.Load, called by the caller before this
// function) -- there is nothing left for NewTLSServer itself to fail on.
//
// No client certificate is required yet -- ClientAuth defaults to
// tls.NoClientCert. mTLS (verifying a canary's own client certificate
// against the CA's pool) is a later slice; Refs #47.
func NewTLSServer(addr string, handler http.Handler, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *http.Server {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true) // HTTP/2 and unencrypted HTTP/2 both left false

	return &http.Server{
		Addr:    addr,
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS13,
			GetCertificate: getCertificate,
		},
		Protocols:         protocols,
		ReadHeaderTimeout: ingestReadHeaderTimeout,
		ReadTimeout:       ingestReadTimeout,
		WriteTimeout:      ingestWriteTimeout,
		IdleTimeout:       ingestIdleTimeout,
		MaxHeaderBytes:    ingestMaxHeaderBytes,
	}
}
