package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Timeouts and caps for every call this client makes, mirroring
// internal/ingest/tlsserver.go's own reasoning in the other direction:
// the canary is a box assumed hostile and birdcage is not, but the
// network between them still deserves explicit bounds rather than
// net/http's unbounded defaults (#48 "What the research changed" #1:
// "explicit timeouts on dial, TLS handshake, response headers and
// body; a hard size cap on every response the agent reads").
const (
	dialTimeout           = 10 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	responseHeaderTimeout = 15 * time.Second
	idleConnTimeout       = 60 * time.Second
	// requestTimeout bounds one whole call -- dial through reading the
	// full response body -- so a connection that answers headers but
	// then stalls mid-body can't hang a call indefinitely.
	requestTimeout = 30 * time.Second
	// maxResponseBytes bounds every response body this package reads
	// (#48: "no unbounded reads"). Generous above any real response: a
	// full batch ack can name up to MaxEventsPerBatch ids twice over
	// (stored and rejected), and even that is a few KiB of hex strings
	// and short reasons, nowhere near this cap.
	maxResponseBytes = 128 * 1024
)

// Config controls how a Client dials birdcage.
type Config struct {
	// BaseURL is the ingest submux's origin, e.g.
	// "https://birdcage.example.com:8443" -- every route this package
	// calls (internal/ingest/http.go's four) is a path under it.
	BaseURL string
	// CACert is the PEM-encoded CA #47 installs on the canary.
	// birdcage's certificate must chain to it, and stock verification is
	// used with no custom callback (#32 research #8: "the ingest
	// certificate carries correct SANs ... so the agent runs stock
	// certificate verification with no custom callback" -- the carve-out
	// failure Beats CVE-2023-31421 is the record of).
	CACert []byte
}

// Client is the HTTPS client a canary's agent uses to talk to birdcage.
// One Client wraps a single *http.Client and is safe for concurrent use
// by multiple goroutines; it is meant to be built once per agent process
// and reused for the process's lifetime so connections are pooled across
// calls.
type Client struct {
	baseURL string
	http    *http.Client
}

// New builds a Client against cfg. It fails only if CACert cannot be
// parsed into at least one certificate; the network is never touched
// here.
func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("client: Config.BaseURL is required")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cfg.CACert) {
		return nil, errors.New("client: Config.CACert contains no usable certificate")
	}

	dialer := &net.Dialer{Timeout: dialTimeout}
	transport := &http.Transport{
		// Proxy intentionally nil, not http.ProxyFromEnvironment (the
		// net/http default): #48 "What the research changed" #1, "proxy
		// environment variables ignored -- the dial goes where enrolment
		// said and nowhere else."
		Proxy:       nil,
		DialContext: dialer.DialContext,
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS13, // matches internal/ingest/tlsserver.go's own floor
		},
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
		IdleConnTimeout:       idleConnTimeout,
		ForceAttemptHTTP2:     false,
		// An empty (non-nil) TLSNextProto stops the transport from ever
		// negotiating HTTP/2 via ALPN, belt-and-braces alongside
		// ForceAttemptHTTP2=false -- #48 "What the research changed" #1:
		// "HTTP/1.1 only, matching #32's server."
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}

	return &Client{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		http: &http.Client{
			Transport:     transport,
			Timeout:       requestTimeout,
			CheckRedirect: refuseRedirects,
		},
	}, nil
}

// refuseRedirects is the Client's CheckRedirect: #48 "What the research
// changed" #1, "the HTTP client refuses every redirect ... birdcage
// never redirects agent routes, so a redirect is an attack or a
// misconfiguration, and either way the token stays home" (GO-2025-3420;
// apt CVE-2019-3462 is the same class at fetch time). Fail-closed
// section: "Any redirect from birdcage -> treated exactly like
// verification failure."
func refuseRedirects(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("client: refusing redirect to %s (birdcage never redirects agent routes)", req.URL)
}

// errorBody mirrors internal/ingest/http.go's writeIngestError shape:
// {"error": "..."} is every non-200 ingest response's body.
type errorBody struct {
	Error string `json:"error"`
}

// post issues one authenticated POST against path relative to
// c.baseURL, with body as the raw request body (nil for none, matching
// internal/ingest's rotate and command-poll routes, which read little
// or nothing of it). It never treats a non-2xx status as a Go error
// itself -- interpreting the status code is every caller in this
// package's own job, since 400, 401, 429 and 5xx all mean different
// things on this wire (#32's transport semantics) -- but a request that
// never gets a response at all (dial failure, TLS failure, timeout, a
// refused redirect, a canceled context) is reported as a
// *RetryableError here, uniformly for every route.
func (c *Client) post(ctx context.Context, path, token string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("client: build request for %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, retryable(fmt.Errorf("%s: %w", path, err))
	}
	return resp, nil
}

// closeBody drains and closes resp.Body so the underlying connection can
// be reused by the pool, bounding the drain the same way every other
// read in this package is bounded.
func closeBody(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	_ = resp.Body.Close()
}

// decodeBounded decodes one JSON value from r into out, refusing to
// read more than maxResponseBytes (#48: "no unbounded reads"). birdcage
// is the party TLS just verified, but its response is still bytes off
// the network, and nothing on this client's read path trusts size
// unconditionally.
func decodeBounded(r io.Reader, out any) error {
	data, err := io.ReadAll(io.LimitReader(r, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	if len(data) > maxResponseBytes {
		return fmt.Errorf("response body exceeds %d-byte cap", maxResponseBytes)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode response body: %w", err)
	}
	return nil
}

// errorMessage reads a bounded {"error": "..."} body for a non-200
// response, falling back to the response's own status text if the body
// is absent or does not decode. The message is diagnostic only -- every
// caller in this package branches on resp.StatusCode, never on this
// string.
func errorMessage(resp *http.Response) string {
	var eb errorBody
	if err := decodeBounded(resp.Body, &eb); err != nil || eb.Error == "" {
		return resp.Status
	}
	return eb.Error
}
