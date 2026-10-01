package crowdsec

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/db/dbtest"
	"github.com/tomlawesome/birdcage/internal/neverblock"
)

// fakeLAPI is a stand-in for the four v1 routes this package uses. It
// is self-written, so it can only prove that the client agrees with
// this file's reading of the swagger and of cscli; the live journey
// (scripts/e2e/crowdsec.sh) is what proves it against the real LAPI.
type fakeLAPI struct {
	t        *testing.T
	password string
	token    string

	mu       sync.Mutex
	requests []recordedRequest
	// knobs
	allowlisted    bool
	allowReason    string
	allowStatus    int
	existing       []listedAlert
	postStatus     int
	postBody       string
	loginStatus    int
	alertsGetError int
}

type recordedRequest struct {
	Method string
	Path   string
	Query  string
	Auth   string
	Body   []byte
}

func newFakeLAPI(t *testing.T) (*fakeLAPI, *httptest.Server) {
	f := &fakeLAPI{t: t, password: "hunter2-not-real", token: "jwt-token-value", allowStatus: 200, postStatus: 201, loginStatus: 200}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	// The untrusted-certificate test makes the server log a handshake
	// error it has every right to; it is not a finding, so it is
	// silenced rather than left to look like one.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeLAPI) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.requests = append(f.requests, recordedRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Auth: r.Header.Get("Authorization"), Body: body})
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == pathLogin:
		var in loginRequest
		if err := json.Unmarshal(body, &in); err != nil {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"message":"bad json"}`)
			return
		}
		if f.loginStatus != 200 {
			w.WriteHeader(f.loginStatus)
			fmt.Fprint(w, `{"message":"login broke"}`)
			return
		}
		if in.MachineID != "birdcage" || in.Password != f.password {
			w.WriteHeader(401)
			fmt.Fprintf(w, `{"code":401,"message":"incorrect Username or Password: %s"}`, in.Password)
			return
		}
		fmt.Fprintf(w, `{"code":200,"expire":"%s","token":"%s"}`, time.Now().Add(time.Hour).Format(time.RFC3339), f.token)
	case r.Header.Get("Authorization") != "Bearer "+f.token:
		w.WriteHeader(401)
		fmt.Fprint(w, `{"message":"missing or bad token"}`)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, pathAllowlistCheck):
		if f.allowStatus != 200 {
			w.WriteHeader(f.allowStatus)
			fmt.Fprint(w, `{"message":"allowlist broke"}`)
			return
		}
		_ = json.NewEncoder(w).Encode(allowlistResponse{Allowlisted: f.allowlisted, Reason: f.allowReason})
	case r.Method == http.MethodGet && r.URL.Path == pathAlerts:
		if f.alertsGetError != 0 {
			w.WriteHeader(f.alertsGetError)
			fmt.Fprint(w, `{"message":"list broke"}`)
			return
		}
		out := f.existing
		if out == nil {
			out = []listedAlert{}
		}
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodPost && r.URL.Path == pathAlerts:
		w.WriteHeader(f.postStatus)
		if f.postBody != "" {
			fmt.Fprint(w, f.postBody)
			return
		}
		if f.postStatus == 201 {
			fmt.Fprint(w, `["42"]`)
			return
		}
		fmt.Fprint(w, `{"message":"post broke"}`)
	default:
		w.WriteHeader(404)
		fmt.Fprint(w, `{"message":"no such route"}`)
	}
}

func (f *fakeLAPI) calls() []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedRequest(nil), f.requests...)
}

func (f *fakeLAPI) paths() []string {
	var out []string
	for _, r := range f.calls() {
		out = append(out, r.Method+" "+r.Path)
	}
	return out
}

func configFor(srv *httptest.Server, password string) Config {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return Config{LAPIURL: srv.URL, MachineID: "birdcage", Password: password, RootCAs: pool}
}

func blockerFor(srv *httptest.Server, password string) *Blocker {
	fixed := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	return New(NewClient(configFor(srv, password)), neverblock.New(neverblock.Config{}), func() time.Time { return fixed })
}

func forEachEngine(t *testing.T, fn func(t *testing.T, database *db.DB)) {
	t.Helper()
	for _, tgt := range dbtest.Targets(t) {
		t.Run(tgt.Name, func(t *testing.T) { fn(t, tgt.DB) })
	}
}

type auditRow struct {
	Action, Target, Reason, TriggeredBy string
}

func auditRows(t *testing.T, database *db.DB) []auditRow {
	t.Helper()
	rows, err := database.Query(`SELECT action, target, reason, triggered_by FROM audit_log ORDER BY id`)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.Action, &r.Target, &r.Reason, &r.TriggeredBy); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func onlyAudit(t *testing.T, database *db.DB, action string) auditRow {
	t.Helper()
	rows := auditRows(t, database)
	if len(rows) != 1 || rows[0].Action != action {
		t.Fatalf("audit rows = %+v, want exactly one %s", rows, action)
	}
	return rows[0]
}

func TestBlockAddsAPermanentBanLikeCscli(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f, srv := newFakeLAPI(t)
		out, err := blockerFor(srv, f.password).Block(context.Background(), database, "203.0.113.9", "e2e probe", "cli", neverblock.Inputs{})
		if err != nil {
			t.Fatalf("Block: %v", err)
		}
		if out.Status != StatusAdded || out.AlertID != "42" || out.Duration != PermanentDuration || out.Target != "203.0.113.9" {
			t.Fatalf("Outcome = %+v", out)
		}

		want := []string{"POST " + pathLogin, "GET " + pathAllowlistCheck + "203.0.113.9", "GET " + pathAlerts, "POST " + pathAlerts}
		if got := f.paths(); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("calls = %v, want %v", got, want)
		}

		calls := f.calls()
		if calls[2].Query != "decision_type=ban&has_active_decision=true&ip=203.0.113.9" {
			t.Errorf("lookup query = %q", calls[2].Query)
		}
		for _, c := range calls[1:] {
			if c.Auth != "Bearer "+f.token {
				t.Errorf("%s %s sent Authorization %q", c.Method, c.Path, c.Auth)
			}
		}

		// The payload is the one cscli decisions add sends, field for
		// field (ADR-0014, decision 5).
		var posted []map[string]any
		if err := json.Unmarshal(calls[3].Body, &posted); err != nil || len(posted) != 1 {
			t.Fatalf("posted body = %s (%v)", calls[3].Body, err)
		}
		a := posted[0]
		for key, want := range map[string]any{
			"capacity": float64(0), "events_count": float64(1), "leakspeed": "0",
			"message": "birdcage: e2e probe", "scenario": "birdcage: e2e probe",
			"scenario_hash": "", "scenario_version": "", "simulated": false,
			"start_at": "2026-10-01T12:00:00Z", "stop_at": "2026-10-01T12:00:00Z", "created_at": "2026-10-01T12:00:00Z",
			"remediation": true, "kind": "cscli",
		} {
			if a[key] != want {
				t.Errorf("alert[%q] = %v, want %v", key, a[key], want)
			}
		}
		if events, ok := a["events"].([]any); !ok || len(events) != 0 {
			t.Errorf("alert[events] = %v, want an empty array", a["events"])
		}
		src := a["source"].(map[string]any)
		if src["scope"] != "ip" || src["value"] != "203.0.113.9" || src["ip"] != "203.0.113.9" {
			t.Errorf("source = %v", src)
		}
		decs := a["decisions"].([]any)
		if len(decs) != 1 {
			t.Fatalf("decisions = %v", decs)
		}
		d := decs[0].(map[string]any)
		for key, want := range map[string]any{
			"duration": PermanentDuration, "scope": "ip", "value": "203.0.113.9", "type": "ban",
			"scenario": "birdcage: e2e probe", "origin": "cscli",
		} {
			if d[key] != want {
				t.Errorf("decision[%q] = %v, want %v", key, d[key], want)
			}
		}

		row := onlyAudit(t, database, ActionAdded)
		if row.Target != "203.0.113.9" || row.TriggeredBy != "cli" {
			t.Errorf("audit row = %+v", row)
		}
		for _, want := range []string{"e2e probe", "LAPI alert 42", PermanentDuration, "machine birdcage"} {
			if !strings.Contains(row.Reason, want) {
				t.Errorf("audit reason %q lacks %q", row.Reason, want)
			}
		}
		if strings.Contains(row.Reason, f.password) || strings.Contains(row.Reason, f.token) {
			t.Errorf("audit reason carries a secret: %q", row.Reason)
		}
	})
}

func TestBlockCanonicalisesTheAddress(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f, srv := newFakeLAPI(t)
		out, err := blockerFor(srv, f.password).Block(context.Background(), database, " ::ffff:203.0.113.9 ", "mapped", "cli", neverblock.Inputs{})
		if err != nil {
			t.Fatalf("Block: %v", err)
		}
		if out.Target != "203.0.113.9" {
			t.Fatalf("Target = %q, want the unmapped IPv4 form", out.Target)
		}
		var posted []alertPayload
		if err := json.Unmarshal(f.calls()[3].Body, &posted); err != nil {
			t.Fatal(err)
		}
		if posted[0].Decisions[0].Value != "203.0.113.9" {
			t.Fatalf("posted value = %q", posted[0].Decisions[0].Value)
		}
		if onlyAudit(t, database, ActionAdded).Target != "203.0.113.9" {
			t.Fatal("audit target is not canonical")
		}
	})
}

func TestBlockIPv6(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f, srv := newFakeLAPI(t)
		out, err := blockerFor(srv, f.password).Block(context.Background(), database, "2001:DB8::1", "v6", "cli", neverblock.Inputs{})
		if err != nil {
			t.Fatalf("Block: %v", err)
		}
		if out.Target != "2001:db8::1" {
			t.Fatalf("Target = %q", out.Target)
		}
		if got := f.calls()[1].Path; got != pathAllowlistCheck+"2001:db8::1" {
			t.Fatalf("allowlist path = %q", got)
		}
	})
}

func TestBlockExistingBanIsNotPostedTwice(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f, srv := newFakeLAPI(t)
		f.existing = []listedAlert{{ID: 7, Decisions: []listedDecision{
			// A human's own 4h cscli ban on the same address: not birdcage's.
			{ID: 70, Origin: "cscli", Scenario: "manual 'ban' from 'localhost'", Scope: "Ip", Value: "203.0.113.9", Type: "ban", Duration: "3h59m0s"},
			{ID: 71, Origin: "cscli", Scenario: "birdcage: earlier", Scope: "Ip", Value: "203.0.113.9", Type: "ban", Duration: "875999h0m0s"},
		}}}
		out, err := blockerFor(srv, f.password).Block(context.Background(), database, "203.0.113.9", "again", "cli", neverblock.Inputs{})
		if err != nil {
			t.Fatalf("Block: %v", err)
		}
		if out.Status != StatusExists || out.AlertID != "7" || out.Duration != "875999h0m0s" {
			t.Fatalf("Outcome = %+v", out)
		}
		for _, p := range f.paths() {
			if p == "POST "+pathAlerts {
				t.Fatal("a second decision was posted")
			}
		}
		row := onlyAudit(t, database, ActionExists)
		if !strings.Contains(row.Reason, "alert 7") || !strings.Contains(row.Reason, "decision 71") {
			t.Errorf("audit reason = %q", row.Reason)
		}
	})
}

func TestBlockSomeoneElsesBanDoesNotCount(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f, srv := newFakeLAPI(t)
		f.existing = []listedAlert{{ID: 7, Decisions: []listedDecision{
			{ID: 70, Origin: "crowdsec", Scenario: "crowdsecurity/ssh-bf", Scope: "Ip", Value: "203.0.113.9", Type: "ban", Duration: "3h59m0s"},
			{ID: 72, Origin: "cscli", Scenario: "manual 'ban' from 'localhost'", Scope: "Ip", Value: "203.0.113.9", Type: "ban", Duration: "1h"},
		}}}
		out, err := blockerFor(srv, f.password).Block(context.Background(), database, "203.0.113.9", "mine", "cli", neverblock.Inputs{})
		if err != nil {
			t.Fatalf("Block: %v", err)
		}
		if out.Status != StatusAdded {
			t.Fatalf("Outcome = %+v, want a new permanent ban beside the temporary ones", out)
		}
	})
}

func TestBlockRefusesTheFloorWithoutContactingTheLAPI(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f, srv := newFakeLAPI(t)
		_, err := blockerFor(srv, f.password).Block(context.Background(), database, "10.0.0.5", "internal", "cli", neverblock.Inputs{})
		if !errors.Is(err, neverblock.ErrRefused) {
			t.Fatalf("err = %v, want neverblock.ErrRefused", err)
		}
		if len(f.calls()) != 0 {
			t.Fatalf("the LAPI was contacted: %v", f.paths())
		}
		row := onlyAudit(t, database, neverblock.AuditAction)
		if row.Target != "10.0.0.5" || row.TriggeredBy != "cli" {
			t.Errorf("audit row = %+v", row)
		}
	})
}

func TestBlockRefusesAdminSessionAddress(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f, srv := newFakeLAPI(t)
		in := neverblock.Inputs{AdminSession: mustAddr("203.0.113.77")}
		_, err := blockerFor(srv, f.password).Block(context.Background(), database, "203.0.113.77", "oops", "cli", in)
		if !errors.Is(err, neverblock.ErrRefused) {
			t.Fatalf("err = %v, want neverblock.ErrRefused", err)
		}
		if len(f.calls()) != 0 {
			t.Fatal("the LAPI was contacted")
		}
	})
}

func TestBlockBadTargetsWriteNoAuditRow(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f, srv := newFakeLAPI(t)
		b := blockerFor(srv, f.password)
		for _, target := range []string{"", "203.0.113.0/24", "example.com", "fe80::1%eth0", "203.0.113"} {
			if _, err := b.Block(context.Background(), database, target, "x", "cli", neverblock.Inputs{}); err == nil {
				t.Errorf("Block(%q) returned no error", target)
			}
		}
		for _, reason := range []string{"", "   ", "two\nlines", strings.Repeat("r", maxReasonLen+1)} {
			if _, err := b.Block(context.Background(), database, "203.0.113.9", reason, "cli", neverblock.Inputs{}); err == nil {
				t.Errorf("Block(reason %q) returned no error", reason)
			}
		}
		if _, err := b.Block(context.Background(), database, "203.0.113.9", "fine", "", neverblock.Inputs{}); err == nil {
			t.Error("Block with empty triggeredBy returned no error")
		}
		if len(f.calls()) != 0 {
			t.Fatalf("the LAPI was contacted: %v", f.paths())
		}
		if rows := auditRows(t, database); len(rows) != 0 {
			t.Fatalf("audit rows = %+v, want none for a usage error", rows)
		}
	})
}

func TestBlockAllowlistedInCrowdSecIsRefused(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f, srv := newFakeLAPI(t)
		f.allowlisted, f.allowReason = true, "my-allowlist"
		_, err := blockerFor(srv, f.password).Block(context.Background(), database, "203.0.113.9", "x", "cli", neverblock.Inputs{})
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "my-allowlist") {
			t.Fatalf("err = %v", err)
		}
		for _, p := range f.paths() {
			if p == "POST "+pathAlerts {
				t.Fatal("a decision was posted for an allowlisted address")
			}
		}
		row := onlyAudit(t, database, ActionRefused)
		if !strings.Contains(row.Reason, "my-allowlist") {
			t.Errorf("audit reason = %q", row.Reason)
		}
	})
}

func TestBlockFailuresAreRecordedAndNothingPosted(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(f *fakeLAPI) (password string)
		stage  string
		status int
	}{
		{"wrong password", func(f *fakeLAPI) string { return "wrong-password" }, "login", 401},
		{"login 500", func(f *fakeLAPI) string { f.loginStatus = 500; return f.password }, "login", 500},
		{"allowlist route missing (old LAPI)", func(f *fakeLAPI) string { f.allowStatus = 404; return f.password }, "allowlist check", 404},
		{"allowlist 500", func(f *fakeLAPI) string { f.allowStatus = 500; return f.password }, "allowlist check", 500},
		{"lookup 500", func(f *fakeLAPI) string { f.alertsGetError = 500; return f.password }, "existing-ban lookup", 500},
		{"post 422", func(f *fakeLAPI) string { f.postStatus = 422; return f.password }, "post decision", 422},
		{"post 403", func(f *fakeLAPI) string { f.postStatus = 403; return f.password }, "post decision", 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forEachEngine(t, func(t *testing.T, database *db.DB) {
				f, srv := newFakeLAPI(t)
				password := tc.setup(f)
				_, err := blockerFor(srv, password).Block(context.Background(), database, "203.0.113.9", "x", "cli", neverblock.Inputs{})
				var le *LAPIError
				if !errors.As(err, &le) || le.Stage != tc.stage || le.Status != tc.status {
					t.Fatalf("err = %v, want LAPIError at %q with %d", err, tc.stage, tc.status)
				}
				if strings.Contains(err.Error(), password) || strings.Contains(err.Error(), f.token) {
					t.Fatalf("error carries a secret: %q", err)
				}
				if tc.stage != "post decision" {
					for _, p := range f.paths() {
						if p == "POST "+pathAlerts {
							t.Fatal("a decision was posted after an earlier failure")
						}
					}
				}
				row := onlyAudit(t, database, ActionFailed)
				if !strings.Contains(row.Reason, tc.stage) || !strings.Contains(row.Reason, fmt.Sprint(tc.status)) {
					t.Errorf("audit reason = %q", row.Reason)
				}
				if strings.Contains(row.Reason, password) || strings.Contains(row.Reason, f.token) {
					t.Errorf("audit reason carries a secret: %q", row.Reason)
				}
			})
		})
	}
}

func TestBlockUntrustedCertificateFailsClosed(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f, srv := newFakeLAPI(t)
		cfg := configFor(srv, f.password)
		cfg.RootCAs = x509.NewCertPool() // trusts nothing
		b := New(NewClient(cfg), neverblock.New(neverblock.Config{}), nil)
		_, err := b.Block(context.Background(), database, "203.0.113.9", "x", "cli", neverblock.Inputs{})
		if err == nil || !strings.Contains(err.Error(), "login") {
			t.Fatalf("err = %v, want a login-stage transport failure", err)
		}
		if len(f.calls()) != 0 {
			t.Fatal("the handshake should have failed before any request was served")
		}
		row := onlyAudit(t, database, ActionFailed)
		if !strings.Contains(row.Reason, "login") {
			t.Errorf("audit reason = %q", row.Reason)
		}
	})
}

func TestBlock201WithoutIDStillRecordsTheBan(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f, srv := newFakeLAPI(t)
		f.postBody = `[]`
		out, err := blockerFor(srv, f.password).Block(context.Background(), database, "203.0.113.9", "x", "cli", neverblock.Inputs{})
		if err != nil {
			t.Fatalf("Block: %v", err)
		}
		if out.Status != StatusAdded || out.AlertID != "" {
			t.Fatalf("Outcome = %+v", out)
		}
		if !strings.Contains(onlyAudit(t, database, ActionAdded).Reason, "without an alert id") {
			t.Fatal("audit reason does not say the id was missing")
		}
	})
}

func TestBlockPasswordNeverLeavesExceptInLoginBody(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f, srv := newFakeLAPI(t)
		if _, err := blockerFor(srv, f.password).Block(context.Background(), database, "203.0.113.9", "x", "cli", neverblock.Inputs{}); err != nil {
			t.Fatal(err)
		}
		for i, c := range f.calls() {
			if i == 0 {
				continue
			}
			if strings.Contains(string(c.Body), f.password) || strings.Contains(c.Query, f.password) {
				t.Errorf("%s %s carried the password", c.Method, c.Path)
			}
		}
	})
}

func TestScrub(t *testing.T) {
	if got := scrub("a\x1bb\r\nc\x7f"); got != "abc" {
		t.Fatalf("scrub = %q", got)
	}
	long := strings.Repeat("x", maxMessageLen+50)
	if got := scrub(long); len(got) != maxMessageLen+3 || !strings.HasSuffix(got, "...") {
		t.Fatalf("scrub(long) = %d chars", len(got))
	}
}

func mustAddr(s string) netip.Addr {
	return netip.MustParseAddr(s)
}
