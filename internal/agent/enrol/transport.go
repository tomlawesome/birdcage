package enrol

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Timeouts and caps mirroring internal/agent/client's own conventions
// (client.go) -- this package cannot import that one (standard library
// only), so the same numbers and the same reasoning are copied here rather
// than shared.
const (
	dialTimeout           = 10 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	responseHeaderTimeout = 10 * time.Second
	requestTimeout        = 10 * time.Second
	// maxResponseBytes bounds every response body this package reads (#48's
	// "no unbounded reads" rule, applied here too even though enrolment
	// bodies are tiny -- a PEM certificate and a short-lived secret, nowhere
	// near this cap).
	maxResponseBytes = 64 * 1024
)

// newHTTPClient builds an *http.Client against tlsConfig with the same
// hardening internal/agent/client.New applies: no proxy, HTTP/1.1 only
// (ALPN for HTTP/2 disabled), every redirect refused, and an overall
// per-call timeout.
func newHTTPClient(tlsConfig *tls.Config) *http.Client {
	dialer := &net.Dialer{Timeout: dialTimeout}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
		ForceAttemptHTTP2:     false,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	return &http.Client{
		Transport:     transport,
		Timeout:       requestTimeout,
		CheckRedirect: refuseRedirects,
	}
}

// refuseRedirects mirrors internal/agent/client's own refuseRedirects:
// birdcage's enrolment listener never redirects, so a redirect is an attack
// or a misconfiguration either way.
func refuseRedirects(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("enrol: refusing redirect to %s (birdcage never redirects enrolment routes)", req.URL)
}

// postJSON POSTs body (already-marshalled JSON) to baseURL+path and returns
// the response. A request that never gets a response at all (dial, TLS,
// timeout, refused redirect, canceled context) is reported as a
// *RetryableError, uniformly -- the only place in this package that
// classification happens for the request/response round trip itself.
func postJSON(ctx context.Context, httpClient *http.Client, baseURL, path string, body []byte) (*http.Response, error) {
	url := strings.TrimRight(baseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("enrol: build request for %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, retryable(fmt.Errorf("%s: %w", path, err))
	}
	return resp, nil
}

// closeBody drains and closes resp.Body so the underlying connection can be
// reused, bounding the drain the same way every other read in this package
// is bounded.
func closeBody(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	_ = resp.Body.Close()
}

// decodeBounded decodes one JSON value from r into out, refusing to read
// more than maxResponseBytes.
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

// wireErrorBody mirrors internal/enrol's own {"error": "..."} shape
// (writeError/writeRefused).
type wireErrorBody struct {
	Error string `json:"error"`
}

// errorMessage reads a bounded {"error": "..."} body for a non-200
// response, falling back to the response's own status text if the body is
// absent or does not decode. Diagnostic only.
func errorMessage(resp *http.Response) string {
	var eb wireErrorBody
	if err := decodeBounded(resp.Body, &eb); err != nil || eb.Error == "" {
		return resp.Status
	}
	return eb.Error
}
