package ingest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/ca"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// Issue #130 (ADR-0012 Part B): every test here runs the real ingest
// mux (newHandler, every route behind requireBearerToken) behind a real
// TLS 1.3 listener requiring client certificates, with certificates
// signed by internal/ca over keys the "agent" generated itself.

// testClock is a settable clock shared by the handler and a test.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type credFixture struct {
	database *db.DB
	ca       *ca.CA
	srv      *httptest.Server
	clock    *testClock
}

func newCredFixture(t *testing.T, database *db.DB, opts ...Option) *credFixture {
	t.Helper()
	testCA := newTestCA(t)
	clock := &testClock{t: time.Now().UTC()}
	mux := newHandler(database, nil, clock.now, defaultLimiterLimits, store.NewSelfTestIndex(), nil, append([]Option{WithClientCertSigner(testCA)}, opts...)...)
	srv := newMTLSServer(t, testCA, testCA.Pool(), mux)
	t.Cleanup(srv.Close)
	return &credFixture{database: database, ca: testCA, srv: srv, clock: clock}
}

// node is one agent's credential: its own key's certificate and its
// bearer token.
type node struct {
	id    string
	token string
	cert  tls.Certificate
}

// enrolNode registers a canary and gives it what provisioning gives it:
// a recorded certificate over the agent's own key and a token bound to
// that certificate.
func (f *credFixture) enrolNode(t *testing.T, id string, kind agentkind.Kind) node {
	t.Helper()
	enrollCanaryKind(t, f.database, id, kind)
	cert := clientCertificate(t, f.ca, id, kind)
	rec := registerCert(t, f.database, id, cert)
	raw, _, err := store.MintCanaryTokenForCert(context.Background(), f.database, id, rec.Fingerprint, time.Now().UTC())
	if err != nil {
		t.Fatalf("MintCanaryTokenForCert: %v", err)
	}
	return node{id: id, token: raw, cert: cert}
}

// post sends body to path as n, from localIP when set (a second loopback
// address stands in for a second host).
func (f *credFixture) post(t *testing.T, path, token string, cert tls.Certificate, body any, localIP string) (int, []byte) {
	t.Helper()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if localIP != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(localIP)}
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext:       dialer.DialContext,
			TLSClientConfig:   &tls.Config{RootCAs: f.ca.Pool(), Certificates: []tls.Certificate{cert}},
			DisableKeepAlives: true,
		},
		Timeout: 5 * time.Second,
	}
	var reader io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(http.MethodPost, f.srv.URL+path, reader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }() // test teardown
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, out
}

func (f *credFixture) heartbeat(t *testing.T, token string, cert tls.Certificate) int {
	t.Helper()
	status, _ := f.post(t, "/ingest/heartbeat", token, cert, map[string]any{}, "")
	return status
}

func auditCount(t *testing.T, database *db.DB, action, target string) int {
	t.Helper()
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = ? AND target = ?`, action, target).Scan(&n); err != nil {
		t.Fatalf("count %s audit rows: %v", action, err)
	}
	return n
}

func canaryState(t *testing.T, database *db.DB, id string, at time.Time) store.Canary {
	t.Helper()
	canaries, err := store.ListCanaries(context.Background(), database, at, time.Hour)
	if err != nil {
		t.Fatalf("ListCanaries: %v", err)
	}
	return findCanaryByID(t, canaries, id)
}

func hasState(c store.Canary, state store.HealthState) bool {
	for _, s := range c.ActiveStates {
		if s == string(state) {
			return true
		}
	}
	return false
}

// TestCertificateNotOnRecordIsRefused is ADR-0012 B2's "a certificate
// birdcage did not issue or has revoked is 401 regardless of its
// signature". Both certificates here are genuinely signed by birdcage's
// CA, with the right CN and OU; neither is on record.
func TestCertificateNotOnRecordIsRefused(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)

		t.Run("node enrolled before issue 130", func(t *testing.T) {
			// What an existing node holds after the upgrade: a CA-signed
			// certificate with no row and a token with no binding.
			enrollCanary(t, database, "old-node")
			raw := mintToken(t, database, "old-node")
			cert := clientCertificate(t, f.ca, "old-node", agentkind.Honeypot)
			if got := f.heartbeat(t, raw, cert); got != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", got)
			}
			if auditCount(t, database, "ingest.cert_unknown", "old-node") != 1 {
				t.Error("no ingest.cert_unknown audit row")
			}
		})

		t.Run("unrecorded certificate beside a recorded one", func(t *testing.T) {
			n := f.enrolNode(t, "live-node", agentkind.Honeypot)
			if got := f.heartbeat(t, n.token, n.cert); got != http.StatusOK {
				t.Fatalf("recorded certificate: status = %d, want 200", got)
			}
			forged := clientCertificate(t, f.ca, "live-node", agentkind.Honeypot)
			if got := f.heartbeat(t, n.token, forged); got != http.StatusUnauthorized {
				t.Errorf("unrecorded certificate: status = %d, want 401", got)
			}
			if auditCount(t, database, "ingest.cert_unknown", "live-node") != 1 {
				t.Error("no ingest.cert_unknown audit row")
			}
		})
	})
}

// TestTokenBoundToAnotherCertificateIsRefused is ADR-0012 B3: a live
// token over a live certificate of the same node is still a 401 when the
// token is not bound to it -- "a copied key with a token from a
// different rotation generation is inert".
func TestTokenBoundToAnotherCertificateIsRefused(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		n := f.enrolNode(t, "node-a", agentkind.Honeypot)

		// A second live certificate of the same node, recorded without
		// carrying the token across (so the token stays on the first).
		later := clientCertificate(t, f.ca, "node-a", agentkind.Honeypot)
		leaf, _ := x509.ParseCertificate(later.Certificate[0])
		if _, err := store.RecordClientCert(context.Background(), database, "node-a", leaf); err != nil {
			t.Fatalf("RecordClientCert: %v", err)
		}
		if got := f.heartbeat(t, n.token, later); got != http.StatusUnauthorized {
			t.Errorf("token bound to the older certificate over the newer: status = %d, want 401", got)
		}
		if auditCount(t, database, "ingest.token_cert_mismatch", "node-a") != 1 {
			t.Error("no ingest.token_cert_mismatch audit row")
		}

		// An unbound token (minted outside enrolment and rotation) over the
		// node's own recorded certificate.
		unbound, _, err := store.MintCanaryToken(context.Background(), database, "node-a", time.Now().UTC())
		if err != nil {
			t.Fatalf("MintCanaryToken: %v", err)
		}
		if got := f.heartbeat(t, unbound, n.cert); got != http.StatusUnauthorized {
			t.Errorf("unbound token: status = %d, want 401", got)
		}

		// And the honest pair still works.
		if got := f.heartbeat(t, n.token, n.cert); got != http.StatusOK {
			t.Errorf("bound pair: status = %d, want 200", got)
		}
	})
}

func renewBody(t *testing.T) (*ecdsa.PrivateKey, map[string]string) {
	t.Helper()
	key, csrPEM := newAgentCSRPEM(t)
	return key, map[string]string{"csr_pem": string(csrPEM)}
}

func (f *credFixture) renew(t *testing.T, n node) (int, tls.Certificate, renewResponse) {
	t.Helper()
	key, body := renewBody(t)
	status, out := f.post(t, "/ingest/renew", n.token, n.cert, body, "")
	if status != http.StatusOK {
		return status, tls.Certificate{}, renewResponse{}
	}
	var resp renewResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal renew response: %v; body %s", err, out)
	}
	return status, keyPair(t, []byte(resp.ClientCertPEM), key), resp
}

// TestRenewIsOneWay is ADR-0012 B2 end to end: renewal returns a
// certificate over the agent's new key and carries the token to it; the
// old certificate keeps working until the new one's first use and is
// refused from then on, flagged as cert_conflict while the successor is
// live.
func TestRenewIsOneWay(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		n := f.enrolNode(t, "node-a", agentkind.Honeypot)
		if got := f.heartbeat(t, n.token, n.cert); got != http.StatusOK {
			t.Fatalf("before renewal: status = %d, want 200", got)
		}

		status, newCert, resp := f.renew(t, n)
		if status != http.StatusOK {
			t.Fatalf("renew: status = %d, want 200", status)
		}
		if strings.Contains(resp.ClientCertPEM, "PRIVATE KEY") {
			t.Error("renew response carries a private key")
		}
		leaf, err := x509.ParseCertificate(newCert.Certificate[0])
		if err != nil {
			t.Fatalf("parse renewed leaf: %v", err)
		}
		if leaf.Subject.CommonName != "node-a" || len(leaf.Subject.OrganizationalUnit) != 1 || leaf.Subject.OrganizationalUnit[0] != string(agentkind.Honeypot) {
			t.Errorf("renewed subject = %v, want CN node-a, OU [honeypot]", leaf.Subject)
		}
		notAfter, err := time.Parse(time.RFC3339, resp.NotAfter)
		if err != nil || !notAfter.Equal(leaf.NotAfter.UTC()) {
			t.Errorf("not_after = %q (%v), want the certificate's %s", resp.NotAfter, err, leaf.NotAfter.UTC())
		}
		if got := leaf.NotAfter.Sub(leaf.NotBefore); got < DefaultClientCertTTL || got > DefaultClientCertTTL+10*time.Minute {
			t.Errorf("renewed validity = %s, want about seven days", got)
		}
		if auditCount(t, database, "ingest.cert_issued", "node-a") != 1 {
			t.Error("no ingest.cert_issued audit row")
		}

		// Renewal in flight: the old certificate still pairs with the
		// carried token.
		if got := f.heartbeat(t, n.token, n.cert); got != http.StatusOK {
			t.Errorf("old certificate before the new one's first use: status = %d, want 200", got)
		}

		// First use of the new certificate completes the renewal.
		if got := f.heartbeat(t, n.token, newCert); got != http.StatusOK {
			t.Fatalf("new certificate: status = %d, want 200", got)
		}
		if auditCount(t, database, "ingest.cert_renewed", "node-a") != 1 {
			t.Error("no ingest.cert_renewed audit row")
		}

		// From then on the old certificate is refused and flagged.
		if got := f.heartbeat(t, n.token, n.cert); got != http.StatusUnauthorized {
			t.Errorf("old certificate after the new one's first use: status = %d, want 401", got)
		}
		if auditCount(t, database, "ingest.cert_conflict", "node-a") != 1 {
			t.Error("no ingest.cert_conflict audit row")
		}
		c := canaryState(t, database, "node-a", time.Now().UTC())
		if !hasState(c, store.StateTokenConflict) {
			t.Errorf("active states = %v, want token_conflict (widened to certificates)", c.ActiveStates)
		}
		if got := f.heartbeat(t, n.token, newCert); got != http.StatusOK {
			t.Errorf("new certificate after the conflict: status = %d, want 200 (never auto-revoked)", got)
		}
	})
}

// TestRotationDuringRenewalBindsToTheNewCertificate: a token rotated
// over the outgoing certificate while a renewal is in flight is bound to
// the certificate the agent is switching to, so the agent's next pair
// (new token, new certificate) works.
func TestRotationDuringRenewalBindsToTheNewCertificate(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		n := f.enrolNode(t, "node-a", agentkind.Honeypot)
		status, newCert, _ := f.renew(t, n)
		if status != http.StatusOK {
			t.Fatalf("renew: status = %d", status)
		}
		status, out := f.post(t, "/ingest/rotate", n.token, n.cert, nil, "")
		if status != http.StatusOK {
			t.Fatalf("rotate over the outgoing certificate: status = %d; %s", status, out)
		}
		var rot rotateResponse
		if err := json.Unmarshal(out, &rot); err != nil {
			t.Fatalf("unmarshal rotate: %v", err)
		}
		if got := f.heartbeat(t, rot.Token, newCert); got != http.StatusOK {
			t.Errorf("rotated token over the new certificate: status = %d, want 200", got)
		}
	})
}

// TestRenewRefusals covers each way a renewal is refused without
// issuing anything.
func TestRenewRefusals(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		n := f.enrolNode(t, "node-a", agentkind.Honeypot)

		countCerts := func() int {
			certs, err := store.ListClientCertsForCanary(context.Background(), database, "node-a")
			if err != nil {
				t.Fatalf("ListClientCertsForCanary: %v", err)
			}
			return len(certs)
		}

		// The key already in use: renewing over it would extend a copy.
		sameKeyDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, n.cert.PrivateKey)
		if err != nil {
			t.Fatalf("CreateCertificateRequest(same key): %v", err)
		}
		sameKey := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: sameKeyDER}))

		cases := map[string]any{
			"same key":      map[string]string{"csr_pem": sameKey},
			"no csr":        map[string]string{},
			"garbage csr":   map[string]string{"csr_pem": "nope"},
			"unknown field": map[string]string{"csr_pem": sameKey, "client_key_pem": "x"},
		}
		for name, body := range cases {
			if status, out := f.post(t, "/ingest/renew", n.token, n.cert, body, ""); status != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400; %s", name, status, out)
			}
		}
		if got := countCerts(); got != 1 {
			t.Errorf("certificates after refused renewals = %d, want 1", got)
		}

		// A copied certificate that is not on record cannot renew itself
		// back onto the record.
		forged := clientCertificate(t, f.ca, "node-a", agentkind.Honeypot)
		_, body := renewBody(t)
		if status, _ := f.post(t, "/ingest/renew", n.token, forged, body, ""); status != http.StatusUnauthorized {
			t.Errorf("renew over an unrecorded certificate: status = %d, want 401", status)
		}

		// No signer wired: the route fails closed.
		g := newCredFixture(t, database)
		mux := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)
		unsigned := newMTLSServer(t, g.ca, g.ca.Pool(), mux)
		defer unsigned.Close()
		m := g.enrolNode(t, "node-b", agentkind.Honeypot)
		g.srv = unsigned
		if status, _ := g.post(t, "/ingest/renew", m.token, m.cert, body, ""); status != http.StatusServiceUnavailable {
			t.Errorf("renew with no signer: status = %d, want 503", status)
		}
		if got := countCerts(); got != 1 {
			t.Errorf("certificates after refused renewals = %d, want 1", got)
		}
	})
}

// TestRenewKeepsTheRegisteredKind: a scanner renews as a scanner --
// the OU is re-read from the registry, never from the CSR.
func TestRenewKeepsTheRegisteredKind(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		n := f.enrolNode(t, "scanner-a", agentkind.Scanner)
		status, newCert, _ := f.renew(t, n)
		if status != http.StatusOK {
			t.Fatalf("renew: status = %d, want 200", status)
		}
		leaf, _ := x509.ParseCertificate(newCert.Certificate[0])
		if ou := leaf.Subject.OrganizationalUnit; len(ou) != 1 || ou[0] != string(agentkind.Scanner) {
			t.Errorf("OU = %v, want [scanner]", ou)
		}
	})
}

// TestCopyThatRenewsCutsTheRealNodeOff is ADR-0012 B2's "a copy used to
// renew cuts the real node off, which is loud (B4)".
func TestCopyThatRenewsCutsTheRealNodeOff(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		real := f.enrolNode(t, "node-a", agentkind.Honeypot)
		copied := real // key, certificate and token, all of it

		status, attackerCert, _ := f.renew(t, copied)
		if status != http.StatusOK {
			t.Fatalf("copy renews: status = %d", status)
		}
		if got := f.heartbeat(t, copied.token, attackerCert); got != http.StatusOK {
			t.Fatalf("copy's new certificate: status = %d", got)
		}
		if got := f.heartbeat(t, real.token, real.cert); got != http.StatusUnauthorized {
			t.Errorf("real node after the copy renewed: status = %d, want 401", got)
		}
		c := canaryState(t, database, "node-a", time.Now().UTC())
		if c.Status != string(store.StateTokenConflict) {
			t.Errorf("status = %q, want token_conflict", c.Status)
		}
	})
}

// TestDualUseFromTwoAddressesIsFlaggedNeverRefused is ADR-0012 B4's
// second signal: one live certificate from two source addresses within
// sixty seconds. Both requests succeed -- nothing is refused or revoked
// on it -- and the canary shows credential_conflict naming both
// addresses. A second loopback address stands in for a second host.
func TestDualUseFromTwoAddressesIsFlaggedNeverRefused(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		n := f.enrolNode(t, "node-a", agentkind.Honeypot)

		if status, _ := f.post(t, "/ingest/heartbeat", n.token, n.cert, map[string]any{}, "127.0.0.1"); status != http.StatusOK {
			t.Fatalf("first holder: status = %d", status)
		}
		f.clock.advance(30 * time.Second)
		if status, _ := f.post(t, "/ingest/heartbeat", n.token, n.cert, map[string]any{}, "127.0.0.2"); status != http.StatusOK {
			t.Fatalf("second holder: status = %d, want 200 (flagged, never refused)", status)
		}
		if auditCount(t, database, "ingest.credential_dual_use", "node-a") != 1 {
			t.Fatal("no ingest.credential_dual_use audit row")
		}

		c := canaryState(t, database, "node-a", f.clock.now())
		if !hasState(c, store.StateCredentialConflict) {
			t.Fatalf("active states = %v, want credential_conflict", c.ActiveStates)
		}
		if c.CredentialConflict == nil || strings.Join(c.CredentialConflict.Addresses, ",") != "127.0.0.1,127.0.0.2" {
			t.Errorf("credential_conflict = %+v, want addresses [127.0.0.1 127.0.0.2]", c.CredentialConflict)
		}

		// Nothing was revoked.
		if got := f.heartbeat(t, n.token, n.cert); got != http.StatusOK {
			t.Errorf("after the flag: status = %d, want 200", got)
		}

		// It clears by itself once the dual use stops.
		cleared := canaryState(t, database, "node-a", f.clock.now().Add(3*time.Minute))
		if hasState(cleared, store.StateCredentialConflict) || cleared.CredentialConflict != nil {
			t.Errorf("three minutes later: states %v, detail %+v; want cleared", cleared.ActiveStates, cleared.CredentialConflict)
		}
	})
}

// TestAddressChangeOutsideTheWindowIsNotDualUse: a node whose address
// changes more than sixty seconds after its last request is one holder
// that moved.
func TestAddressChangeOutsideTheWindowIsNotDualUse(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		n := f.enrolNode(t, "node-a", agentkind.Honeypot)
		f.post(t, "/ingest/heartbeat", n.token, n.cert, map[string]any{}, "127.0.0.1")
		f.clock.advance(61 * time.Second)
		f.post(t, "/ingest/heartbeat", n.token, n.cert, map[string]any{}, "127.0.0.2")
		if got := auditCount(t, database, "ingest.credential_dual_use", "node-a"); got != 0 {
			t.Errorf("credential_dual_use rows = %d, want 0", got)
		}
	})
}

// TestDualUseByTwoAgentBuildsIsFlagged: the same certificate heartbeating
// as two agent versions within the window.
func TestDualUseByTwoAgentBuildsIsFlagged(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		n := f.enrolNode(t, "node-a", agentkind.Honeypot)
		for _, v := range []string{"1.0.0", "1.0.0", "0.9.9-copy"} {
			if status, _ := f.post(t, "/ingest/heartbeat", n.token, n.cert, map[string]any{"agent_version": v}, ""); status != http.StatusOK {
				t.Fatalf("heartbeat %s: status = %d", v, status)
			}
			f.clock.advance(10 * time.Second)
		}
		c := canaryState(t, database, "node-a", f.clock.now())
		if c.CredentialConflict == nil || strings.Join(c.CredentialConflict.Versions, ",") != "1.0.0,0.9.9-copy" {
			t.Fatalf("credential_conflict = %+v, want versions [1.0.0 0.9.9-copy]", c.CredentialConflict)
		}
		if c.CredentialConflict.Addresses != nil {
			t.Errorf("addresses = %v, want none (one address throughout)", c.CredentialConflict.Addresses)
		}
	})
}

// TestRevokeCanaryCredentialsEndsBothHolders is ADR-0012 B5: after the
// store revocation every request from the real node and its copy is a
// 401.
func TestRevokeCanaryCredentialsEndsBothHolders(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		n := f.enrolNode(t, "node-a", agentkind.Honeypot)
		other := f.enrolNode(t, "node-b", agentkind.Honeypot)
		status, renewed, _ := f.renew(t, n) // a pending successor too
		if status != http.StatusOK {
			t.Fatalf("renew: %d", status)
		}

		tx, err := database.Begin(context.Background())
		if err != nil {
			t.Fatalf("Begin: %v", err)
		}
		if _, err := store.RevokeCanaryCredentials(context.Background(), tx, "node-a", time.Now().UTC()); err != nil {
			t.Fatalf("RevokeCanaryCredentials: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}

		for name, cert := range map[string]tls.Certificate{"original": n.cert, "renewed": renewed} {
			if got := f.heartbeat(t, n.token, cert); got != http.StatusUnauthorized {
				t.Errorf("%s certificate after revoke: status = %d, want 401", name, got)
			}
		}
		_, body := renewBody(t)
		if status, _ := f.post(t, "/ingest/renew", n.token, n.cert, body, ""); status != http.StatusUnauthorized {
			t.Errorf("renew after revoke: status = %d, want 401", status)
		}
		if got := f.heartbeat(t, other.token, other.cert); got != http.StatusOK {
			t.Errorf("another node after revoke: status = %d, want 200", got)
		}
	})
}

// TestDualUseTrackerWindow pins observe's boundary without the network.
func TestDualUseTrackerWindow(t *testing.T) {
	tr := newDualUseTracker()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, dual := tr.observe("fp", "a", false, t0); dual {
		t.Fatal("first observation flagged")
	}
	if _, dual := tr.observe("fp", "a", false, t0.Add(time.Second)); dual {
		t.Error("same address flagged")
	}
	if prev, dual := tr.observe("fp", "b", false, t0.Add(dualUseWindow+time.Second)); !dual || prev != "a" {
		t.Errorf("at exactly the window: dual=%v prev=%q, want true, a", dual, prev)
	}
	if _, dual := tr.observe("fp", "a", false, t0.Add(3*dualUseWindow)); dual {
		t.Error("change after the window flagged")
	}
	if _, dual := tr.observe("other-fp", "b", false, t0.Add(3*dualUseWindow)); dual {
		t.Error("another certificate's address flagged")
	}
	if _, dual := tr.observe("fp", "v1", true, t0); dual {
		t.Error("first version flagged")
	}
	if prev, dual := tr.observe("fp", "v2", true, t0.Add(time.Second)); !dual || prev != "v1" {
		t.Errorf("version change: dual=%v prev=%q, want true, v1", dual, prev)
	}
	if _, dual := tr.observe("fp", "", true, t0.Add(2*time.Second)); dual {
		t.Error("empty version flagged")
	}
}
