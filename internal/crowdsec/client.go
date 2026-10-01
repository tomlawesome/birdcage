package crowdsec

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

// Timeouts and caps, the same numbers and reasoning as
// internal/agent/enrol/transport.go: nothing the LAPI sends back is
// large (an id, a boolean, a short list), and an operator-run command
// that hangs is worse than one that fails and says so.
const (
	dialTimeout           = 10 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	responseHeaderTimeout = 10 * time.Second
	requestTimeout        = 10 * time.Second
	// maxResponseBytes bounds every response body read here. Every
	// recent LAPI advisory (ADR-0014) is an unbounded read on the
	// server; the client does not repeat the mistake in the other
	// direction.
	maxResponseBytes = 64 * 1024
	// maxMessageLen bounds the LAPI's own error text before it reaches
	// an error string or an audit_log reason.
	maxMessageLen = 200
)

// The LAPI's v1 routes this package uses -- the only four. There is no
// delete route here, and there must never be one (ADR-0014, decision
// 3).
const (
	pathLogin          = "/v1/watchers/login"
	pathAllowlistCheck = "/v1/allowlists/check/"
	pathAlerts         = "/v1/alerts"
)

// Decision constants, mirroring `cscli decisions add` (ADR-0014,
// decision 5): origin cscli so the LAPI treats the ban as a manual
// decision and does not share it with CrowdSec's central API by
// default; a hundred years because CrowdSec requires a duration and
// has no "forever".
const (
	// PermanentDuration is the decision duration birdcage sends.
	PermanentDuration = "876000h"
	// ScenarioPrefix starts every scenario birdcage writes, so a human
	// reading `cscli decisions list` sees whose decision it is and so
	// the idempotence lookup can recognise its own.
	ScenarioPrefix = "birdcage: "

	decisionOrigin = "cscli"
	decisionType   = "ban"
	decisionScope  = "ip"
	alertKind      = "cscli"
	userAgent      = "birdcage"
)

// LAPIError is an answer from the LAPI that was not the one wanted:
// the stage it happened at, the HTTP status, and the LAPI's own
// message, already scrubbed and bounded. It never carries the body.
type LAPIError struct {
	Stage   string
	Status  int
	Message string
}

func (e *LAPIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("%s: LAPI answered %d", e.Stage, e.Status)
	}
	return fmt.Sprintf("%s: LAPI answered %d: %s", e.Stage, e.Status, e.Message)
}

// Client talks to one LAPI. Build one with NewClient.
type Client struct {
	cfg  Config
	http *http.Client
}

// NewClient builds a Client for cfg with the hardened transport above:
// TLS 1.2 minimum, certificate fully verified against cfg.RootCAs or
// the system roots, HTTP/1.1 only, no proxy, every redirect refused.
func NewClient(cfg Config) *Client {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    cfg.RootCAs,
	}
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
	return &Client{
		cfg: cfg,
		http: &http.Client{
			Transport:     transport,
			Timeout:       requestTimeout,
			CheckRedirect: refuseRedirects,
		},
	}
}

func refuseRedirects(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("crowdsec: refusing redirect to %s (a LAPI never redirects)", req.URL.Redacted())
}

// loginRequest and loginResponse are models.WatcherAuthRequest and
// WatcherAuthResponse. scenarios is sent empty, as cscli does for a
// machine that runs no scenarios.
type loginRequest struct {
	MachineID string   `json:"machine_id"`
	Password  string   `json:"password"`
	Scenarios []string `json:"scenarios"`
}

type loginResponse struct {
	Code   int    `json:"code"`
	Expire string `json:"expire"`
	Token  string `json:"token"`
}

// login exchanges the machine credential for a JWT. The token lives
// only in the caller's memory for one Block call.
func (c *Client) login(ctx context.Context) (string, error) {
	body, err := json.Marshal(loginRequest{MachineID: c.cfg.MachineID, Password: c.cfg.Password, Scenarios: []string{}})
	if err != nil {
		return "", fmt.Errorf("crowdsec: encode login: %w", err)
	}
	status, resp, err := c.do(ctx, http.MethodPost, pathLogin, "", body)
	if err != nil {
		return "", fmt.Errorf("login: %w", err)
	}
	if status == http.StatusUnauthorized {
		// The LAPI's own message here names the failure plainly, but
		// the credential is what is being discussed, so the stage
		// speaks for itself and the body is not quoted.
		return "", &LAPIError{Stage: "login", Status: status, Message: "the LAPI refused the machine credential"}
	}
	if status != http.StatusOK {
		return "", &LAPIError{Stage: "login", Status: status, Message: lapiMessage(resp)}
	}
	var out loginResponse
	if err := json.Unmarshal(resp, &out); err != nil || out.Token == "" {
		return "", &LAPIError{Stage: "login", Status: status, Message: "the LAPI answered 200 without a token"}
	}
	return out.Token, nil
}

// allowlistResponse is models.CheckAllowlistResponse.
type allowlistResponse struct {
	Allowlisted bool   `json:"allowlisted"`
	Reason      string `json:"reason"`
}

// allowlisted asks the LAPI's centralised allowlist about ip -- the
// call cscli makes and the LAPI itself skips for an alert that carries
// decisions (ADR-0014). A LAPI too old to have the route answers 404,
// which is returned as an error: fail closed, never "not allowlisted".
func (c *Client) allowlisted(ctx context.Context, token, ip string) (bool, string, error) {
	status, resp, err := c.do(ctx, http.MethodGet, pathAllowlistCheck+url.PathEscape(ip), token, nil)
	if err != nil {
		return false, "", fmt.Errorf("allowlist check: %w", err)
	}
	if status != http.StatusOK {
		msg := lapiMessage(resp)
		if status == http.StatusNotFound {
			msg = "no allowlist route; the LAPI is older than 1.6.6, which is the minimum ADR-0014 supports"
		}
		return false, "", &LAPIError{Stage: "allowlist check", Status: status, Message: msg}
	}
	var out allowlistResponse
	if err := json.Unmarshal(resp, &out); err != nil {
		return false, "", &LAPIError{Stage: "allowlist check", Status: status, Message: "the LAPI's answer was not the expected JSON"}
	}
	return out.Allowlisted, scrub(out.Reason), nil
}

// listedAlert and listedDecision are the parts of models.Alert and
// models.Decision the idempotence lookup reads. Duration is the LAPI's
// remaining-time string (it does not return `until` in a list).
type listedAlert struct {
	ID        int64            `json:"id"`
	Decisions []listedDecision `json:"decisions"`
}

type listedDecision struct {
	ID       int64  `json:"id"`
	Origin   string `json:"origin"`
	Scenario string `json:"scenario"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Type     string `json:"type"`
	Duration string `json:"duration"`
}

// ExistingBan is a live ban birdcage already placed on an address.
type ExistingBan struct {
	AlertID    int64
	DecisionID int64
	Scenario   string
	// Remaining is the LAPI's own remaining-duration string.
	Remaining string
}

// activeBirdcageBan looks for a live ban on ip that birdcage placed:
// origin cscli, type ban, scope ip, scenario starting ScenarioPrefix.
// The filter is on the LAPI side (ip, has_active_decision,
// decision_type); the origin and scenario are checked here because a
// human's own `cscli decisions add` for the same address is not
// birdcage's and must not stop birdcage recording its permanent one.
// Returns nil when there is none.
func (c *Client) activeBirdcageBan(ctx context.Context, token, ip string) (*ExistingBan, error) {
	q := url.Values{}
	q.Set("ip", ip)
	q.Set("has_active_decision", "true")
	q.Set("decision_type", decisionType)
	status, resp, err := c.do(ctx, http.MethodGet, pathAlerts+"?"+q.Encode(), token, nil)
	if err != nil {
		return nil, fmt.Errorf("existing-ban lookup: %w", err)
	}
	if status != http.StatusOK {
		return nil, &LAPIError{Stage: "existing-ban lookup", Status: status, Message: lapiMessage(resp)}
	}
	var alerts []listedAlert
	if err := json.Unmarshal(resp, &alerts); err != nil {
		return nil, &LAPIError{Stage: "existing-ban lookup", Status: status, Message: "the LAPI's answer was not the expected JSON"}
	}
	for _, a := range alerts {
		for _, d := range a.Decisions {
			if d.Origin == decisionOrigin && d.Type == decisionType &&
				strings.EqualFold(d.Scope, decisionScope) && d.Value == ip &&
				strings.HasPrefix(d.Scenario, ScenarioPrefix) {
				return &ExistingBan{AlertID: a.ID, DecisionID: d.ID, Scenario: scrub(d.Scenario), Remaining: scrub(d.Duration)}, nil
			}
		}
	}
	return nil, nil
}

// alertPayload, decisionPayload and sourcePayload are models.Alert,
// models.Decision and models.Source with exactly the fields `cscli
// decisions add` sets (ADR-0014, "How CrowdSec accepts a decision from
// outside"). Events is a non-nil empty slice on purpose: the swagger
// requires the key and an absent one is refused.
type alertPayload struct {
	Capacity        int32             `json:"capacity"`
	Decisions       []decisionPayload `json:"decisions"`
	Events          []struct{}        `json:"events"`
	EventsCount     int32             `json:"events_count"`
	Leakspeed       string            `json:"leakspeed"`
	Message         string            `json:"message"`
	Scenario        string            `json:"scenario"`
	ScenarioHash    string            `json:"scenario_hash"`
	ScenarioVersion string            `json:"scenario_version"`
	Simulated       bool              `json:"simulated"`
	Source          sourcePayload     `json:"source"`
	StartAt         string            `json:"start_at"`
	StopAt          string            `json:"stop_at"`
	CreatedAt       string            `json:"created_at"`
	Remediation     bool              `json:"remediation"`
	Kind            string            `json:"kind"`
}

type decisionPayload struct {
	Duration string `json:"duration"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Type     string `json:"type"`
	Scenario string `json:"scenario"`
	Origin   string `json:"origin"`
}

type sourcePayload struct {
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	IP       string `json:"ip"`
	Range    string `json:"range"`
	AsName   string `json:"as_name"`
	AsNumber string `json:"as_number"`
	Cn       string `json:"cn"`
}

// addBan posts one permanent ban on ip with the given scenario text
// and returns the LAPI's id for the alert it created, or "" if the
// 201 came back without one.
func (c *Client) addBan(ctx context.Context, token, ip, scenario string, now time.Time) (string, error) {
	stamp := now.UTC().Format(time.RFC3339)
	payload := []alertPayload{{
		Capacity: 0,
		Decisions: []decisionPayload{{
			Duration: PermanentDuration,
			Scope:    decisionScope,
			Value:    ip,
			Type:     decisionType,
			Scenario: scenario,
			Origin:   decisionOrigin,
		}},
		Events:          []struct{}{},
		EventsCount:     1,
		Leakspeed:       "0",
		Message:         scenario,
		Scenario:        scenario,
		ScenarioHash:    "",
		ScenarioVersion: "",
		Simulated:       false,
		Source:          sourcePayload{Scope: decisionScope, Value: ip, IP: ip},
		StartAt:         stamp,
		StopAt:          stamp,
		CreatedAt:       stamp,
		Remediation:     true,
		Kind:            alertKind,
	}}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("crowdsec: encode alert: %w", err)
	}
	status, resp, err := c.do(ctx, http.MethodPost, pathAlerts, token, body)
	if err != nil {
		return "", fmt.Errorf("post decision: %w", err)
	}
	if status != http.StatusCreated {
		return "", &LAPIError{Stage: "post decision", Status: status, Message: lapiMessage(resp)}
	}
	var ids []string
	if err := json.Unmarshal(resp, &ids); err != nil || len(ids) == 0 {
		return "", nil
	}
	return scrub(ids[0]), nil
}

// do sends one request and returns the status and the bounded body.
// A request that never gets a response (dial, TLS, timeout, refused
// redirect, cancelled context) is returned as a plain error whose text
// carries the path and the transport's reason -- never a body, never
// a header.
func (c *Client) do(ctx context.Context, method, path, token string, body []byte) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.LAPIURL+path, reader)
	if err != nil {
		return 0, nil, fmt.Errorf("crowdsec: build request for %s: %w", path, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("crowdsec: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return 0, nil, fmt.Errorf("crowdsec: read %s response: %w", path, err)
	}
	if len(data) > maxResponseBytes {
		return 0, nil, fmt.Errorf("crowdsec: %s response exceeded %d bytes", path, maxResponseBytes)
	}
	return resp.StatusCode, data, nil
}

// lapiMessage extracts the LAPI's own "message" field from an error
// body, scrubbed and bounded, and nothing else from the body.
func lapiMessage(body []byte) string {
	var out struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return ""
	}
	return scrub(out.Message)
}

// scrub drops control characters and bounds the length, so a LAPI's
// text can sit in an error string, a terminal line and an audit_log
// reason without carrying anything it should not.
func scrub(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) {
			continue
		}
		if n >= maxMessageLen {
			b.WriteString("...")
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
