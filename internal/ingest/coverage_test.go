package ingest

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// This file closes coverage gaps issue #130 opened (ADR-0012 Part B):
// POST /ingest/renew's refusal paths, the auth.go helpers around it,
// dual-use tracker pruning, and a handful of heartbeat/batch branches
// that were never reached. Every test drives the real handler -- either
// through the real mTLS harness (credFixture, mtls_test.go's helpers) or
// h.ServeHTTP directly (the same plain-httptest pattern every other test
// in this package already uses for routes that don't need a presented
// certificate) -- and any store/db failure is a real one (a dropped
// table), never a mock.

// postRaw is credFixture.post with the body sent verbatim, for the
// trailing-data cases below: post's own body parameter is always
// json.Marshal'd, which can never produce trailing data after a valid
// JSON value.
func (f *credFixture) postRaw(t *testing.T, path, token string, cert tls.Certificate, rawBody string) (int, []byte) {
	t.Helper()
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: f.ca.Pool(), Certificates: []tls.Certificate{cert}},
			DisableKeepAlives: true,
		},
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest(http.MethodPost, f.srv.URL+path, strings.NewReader(rawBody))
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

// TestWithClientCertTTLOption is renew.go's trivial option: a positive
// ttl overrides certTTL, and ttl <= 0 is ignored (WithClientCertTTL's own
// doc comment).
func TestWithClientCertTTLOption(t *testing.T) {
	h := &ingestHandler{certTTL: DefaultClientCertTTL}
	WithClientCertTTL(2 * time.Hour)(h)
	if h.certTTL != 2*time.Hour {
		t.Errorf("certTTL = %s, want 2h", h.certTTL)
	}
	WithClientCertTTL(0)(h)
	if h.certTTL != 2*time.Hour {
		t.Errorf("certTTL after ttl=0 = %s, want unchanged 2h", h.certTTL)
	}
	WithClientCertTTL(-time.Minute)(h)
	if h.certTTL != 2*time.Hour {
		t.Errorf("certTTL after a negative ttl = %s, want unchanged 2h", h.certTTL)
	}
}

// TestRenewWithoutPresentedCertificateIsUnauthorized: a live token with
// no client certificate on the connection (r.TLS == nil, the same
// httptest exemption every other handler test in this package takes)
// reaches handleRenew with clientCertFromContext returning ok == false --
// nothing to renew and nothing the token was checked against.
func TestRenewWithoutPresentedCertificateIsUnauthorized(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/renew", raw, `{"csr_pem":"x"}`))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusUnauthorized, rec.Body.String())
		}
	})
}

// TestRenewRejectsTrailingData is POST /ingest/renew's own version of
// every other body-shaped route's "trailing data" refusal.
func TestRenewRejectsTrailingData(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		n := f.enrolNode(t, "node-a", agentkind.Honeypot)
		_, body := renewBody(t)
		raw := fmt.Sprintf(`{"csr_pem":%q}{}`, body["csr_pem"])

		status, out := f.postRaw(t, "/ingest/renew", n.token, n.cert, raw)
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d; %s", status, http.StatusBadRequest, out)
		}
	})
}

// TestRenewCertIssuedAuditFailureReturns503 is issue #130's own version
// of TestRotateAuditFailureReturns503LeavesPresentedTokenWorkingAndNoUsableNewToken
// (rotate_test.go): item 10's fail-closed rule extends to a renewal's
// own audit write. audit_log is dropped -- a real, deterministic store
// failure isolated to the write path only (auth's own reads never touch
// it on a clean request) -- so the transaction must roll back and leave
// no new certificate behind.
func TestRenewCertIssuedAuditFailureReturns503(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		n := f.enrolNode(t, "node-a", agentkind.Honeypot)

		if _, err := database.Exec(`DROP TABLE audit_log`); err != nil {
			t.Fatalf("drop audit_log: %v", err)
		}

		_, body := renewBody(t)
		status, out := f.post(t, "/ingest/renew", n.token, n.cert, body, "")
		if status != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want %d; %s", status, http.StatusServiceUnavailable, out)
		}

		var count int
		if err := database.QueryRow(`SELECT COUNT(*) FROM client_certs WHERE agent_id = ?`, "node-a").Scan(&count); err != nil {
			t.Fatalf("count client_certs: %v", err)
		}
		if count != 1 {
			t.Errorf("client_certs rows for node-a after a failed renewal = %d, want 1 (the transaction must have rolled back)", count)
		}
	})
}

// TestRenewSupersededCertAuditFailureReturns503 targets the loop's own
// audit write (issue #130 review's "each superseded certificate is
// audited here, uncoalesced and fail closed"): a first renewal leaves a
// pending, unused certificate; a second renewal supersedes it and must
// audit that before recording its own new certificate. With audit_log
// dropped, the whole transaction -- including the supersede -- must roll
// back, leaving the pending certificate exactly as it was.
func TestRenewSupersededCertAuditFailureReturns503(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		n := f.enrolNode(t, "node-a", agentkind.Honeypot)

		status, _, _ := f.renew(t, n) // leaves a pending, never-used certificate
		if status != http.StatusOK {
			t.Fatalf("first renewal: status = %d", status)
		}
		before, err := store.ListClientCertsForCanary(context.Background(), database, "node-a")
		if err != nil {
			t.Fatalf("ListClientCertsForCanary: %v", err)
		}
		pending := before[len(before)-1]
		if !pending.Live() {
			t.Fatal("pending certificate is not live before the second renewal")
		}

		if _, err := database.Exec(`DROP TABLE audit_log`); err != nil {
			t.Fatalf("drop audit_log: %v", err)
		}

		_, body := renewBody(t)
		status, out := f.post(t, "/ingest/renew", n.token, n.cert, body, "")
		if status != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want %d; %s", status, http.StatusServiceUnavailable, out)
		}

		after, err := store.ListClientCertsForCanary(context.Background(), database, "node-a")
		if err != nil {
			t.Fatalf("ListClientCertsForCanary: %v", err)
		}
		if len(after) != len(before) {
			t.Fatalf("client_certs rows = %d, want unchanged %d", len(after), len(before))
		}
		for _, c := range after {
			if c.ID == pending.ID && !c.Live() {
				t.Errorf("pending certificate %d was revoked despite the renewal failing", c.ID)
			}
		}
	})
}

// TestAuthHelperEdgeCases exercises three small pure functions directly,
// exactly like this package's own TestDualUseTrackerWindow does for
// dualUseTracker: the "certs/header carries nothing at all" shape each
// defends is never produced by the real mTLS harness (a listener with
// ClientAuth: RequireAndVerifyClientCert never calls its handler with an
// empty certificate slice, and a bearer header without the token half
// never gets this far), so this is the only way to reach it.
func TestAuthHelperEdgeCases(t *testing.T) {
	if raw, ok := bearerToken("Bearer "); ok || raw != "" {
		t.Errorf("bearerToken(%q) = %q, %v, want \"\", false", "Bearer ", raw, ok)
	}
	if k, ok := certificateKind(nil); ok || k != "" {
		t.Errorf("certificateKind(nil) = %q, %v, want \"\", false", k, ok)
	}
	if ou := presentedOrganizationalUnit(nil); ou != nil {
		t.Errorf("presentedOrganizationalUnit(nil) = %v, want nil", ou)
	}
}

// TestCheckClientCertificateLookupFailureReturns503 is ADR-0012 B2's own
// fail-closed rule for checkClientCertificate's first store read: a
// database failure at the fingerprint lookup is a 503, never the 401 an
// unrecorded certificate gets. client_certs is dropped -- a real failure
// isolated to this one lookup, since the token lookup and CN check ahead
// of it in requireBearerToken never touch that table.
func TestCheckClientCertificateLookupFailureReturns503(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		testCA := newTestCA(t)
		enrollCanary(t, database, "node-a")
		raw := mintToken(t, database, "node-a")
		cert := clientCertificate(t, testCA, "node-a", agentkind.Honeypot)
		registerCert(t, database, "node-a", cert)

		if _, err := database.Exec(`DROP TABLE client_certs`); err != nil {
			t.Fatalf("drop client_certs: %v", err)
		}

		limiters := newLimiterRegistry(defaultLimiterLimits)
		coalescer := newAuditCoalescer()
		route := ingestRoute{pattern: "POST /probe", kinds: []agentkind.Kind{agentkind.Honeypot}, handler: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}}
		mux := http.NewServeMux()
		mux.Handle(route.pattern, requireBearerToken(database, time.Now, limiters, coalescer, newDualUseTracker(), nil, route))
		srv := newMTLSServer(t, testCA, testCA.Pool(), mux)
		defer srv.Close()

		resp, err := mtlsRequest(t, srv, testCA.Pool(), "/probe", raw, cert)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }() // test teardown
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
		}
	})
}

// TestDualUseTrackerPrunesStaleEntries pins observe's own bound: past
// dualUseTrackerPruneAt entries, the next observe call drops every entry
// whose window has closed before inserting its own -- pure in-memory
// behavior, no database or network involved, exactly like
// TestDualUseTrackerWindow above.
func TestDualUseTrackerPrunesStaleEntries(t *testing.T) {
	tr := newDualUseTracker()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < dualUseTrackerPruneAt+1; i++ {
		tr.observe(fmt.Sprintf("fp-%d", i), "addr", false, base)
	}
	tr.observe("fp-new", "addr", false, base.Add(2*dualUseWindow))

	tr.mu.Lock()
	n := len(tr.seen)
	tr.mu.Unlock()
	if n != 1 {
		t.Errorf("tracker size after pruning = %d, want 1 (every stale entry dropped, the new one kept)", n)
	}
}

// TestHeartbeatTrailingDataRejected covers handleHoneypotHeartbeat's own
// trailing-data refusal, exactly like every other body-shaped route's.
func TestHeartbeatTrailingDataRejected(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/heartbeat", raw, `{"agent_version":"1.0.0"}{}`))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	})
}

// TestCommonHeartbeatTrailingDataRejected is the same refusal for a
// Scanner's common-only shape.
func TestCommonHeartbeatTrailingDataRejected(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "scanner-a", agentkind.Scanner)
		raw := mintTokenForKind(t, database, "scanner-a", agentkind.Scanner)
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/heartbeat", raw, `{"agent_version":"1.0.0"}{}`))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	})
}

// TestCommonHeartbeatPayloadCanaryIDMismatchIgnored is
// handleCommonHeartbeat's own version of
// TestHandleHeartbeatIdentityIsAlwaysTheTokens: a Scanner's common
// heartbeat naming a different canary in its body is logged and
// otherwise ignored -- identity is always the token's.
func TestCommonHeartbeatPayloadCanaryIDMismatchIgnored(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "scanner-a", agentkind.Scanner)
		raw := mintTokenForKind(t, database, "scanner-a", agentkind.Scanner)
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/heartbeat", raw, `{"canary_id":"someone-else","agent_version":"1.0.0"}`))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		var version string
		if err := database.QueryRow(`SELECT agent_version FROM agents WHERE id = ?`, "scanner-a").Scan(&version); err != nil {
			t.Fatalf("scan canaries row: %v", err)
		}
		if version != "1.0.0" {
			t.Errorf("agent_version = %q, want it recorded against the token's own canary regardless of the payload", version)
		}
	})
}

// TestHeartbeatLastSeenAddrParseFailureDoesNotFailRequest:
// recordLastSeenAddr's own net.SplitHostPort failure is logged and
// otherwise ignored -- a secondary signal, never part of what
// "accepted" means for a heartbeat.
func TestHeartbeatLastSeenAddrParseFailureDoesNotFailRequest(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		req := ingestRequest(http.MethodPost, "/ingest/heartbeat", raw, `{"agent_version":"1.0.0"}`)
		req.RemoteAddr = "no-host-port-here"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (a malformed peer address must not fail the heartbeat); body %q", rec.Code, http.StatusOK, rec.Body.String())
		}
	})
}

// TestHandleBatchTrailingDataRejected is handleBatch's own trailing-data
// refusal.
func TestHandleBatchTrailingDataRejected(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, batchRequest(raw, batchBody(validEventID1)+`{}`))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	})
}

// TestHandleBatchEmptyEventsRejected is issue #32 item 8's "a batch must
// contain at least one event" rule.
func TestHandleBatchEmptyEventsRejected(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, batchRequest(raw, `{"events":[]}`))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	})
}

// TestHandleBatchTooManyEventsRejected is item 8's upper bound: a batch
// over maxEventsPerBatch is refused outright, before any event in it is
// validated or stored.
func TestHandleBatchTooManyEventsRejected(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		var events []string
		for i := 0; i < maxEventsPerBatch+1; i++ {
			events = append(events, validEventJSON(fmt.Sprintf("%064x", i+1)))
		}
		body := fmt.Sprintf(`{"events":[%s]}`, strings.Join(events, ","))

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, batchRequest(raw, body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	})
}

// TestHandleBatchEmptyServiceStoresAsUnknown is issue #53's own rule,
// carried into this route: an event with no service is not rubbish --
// it stores as "unknown", the same convention the syslog parser has
// always used.
func TestHandleBatchEmptyServiceStoresAsUnknown(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		body := fmt.Sprintf(`{"events":[{"event_id":%q,"source_ip":"203.0.113.9","dest_port":22,"raw":"hit"}]}`, validEventID1)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, batchRequest(raw, body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		var service string
		if err := database.QueryRow(`SELECT service FROM alerts WHERE instance_id = ? AND event_id = ?`, "canary-a", validEventID1).Scan(&service); err != nil {
			t.Fatalf("scan alerts row: %v", err)
		}
		if service != "unknown" {
			t.Errorf("service = %q, want %q", service, "unknown")
		}
	})
}

// TestHandleBatchEventsLimitCrossedReturns429AndRecorded is item 8's
// events/min cap, distinct from TestHandleBatchOverLimitReturns429AndIsRecorded's
// requests/min cap: a tiny EventsPerMinute with a generous
// RequestsPerMinute isolates handleBatch's own allowEvents check.
func TestHandleBatchEventsLimitCrossedReturns429AndRecorded(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		tiny := limiterLimits{RequestsPerMinute: 3000, EventsPerMinute: 1}
		h := newHandler(database, nil, time.Now, tiny, store.NewSelfTestIndex(), nil)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, batchRequest(raw, batchBody(validEventID1)))
		if rec.Code != http.StatusOK {
			t.Fatalf("1st batch (within the fresh burst): status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, batchRequest(raw, batchBody(validEventID2)))
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("2nd batch: status = %d, want %d (body %q)", rec.Code, http.StatusTooManyRequests, rec.Body.String())
		}

		var count int
		if err := database.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = ? AND target = ?`,
			"ingest.rate_limited", "canary-a").Scan(&count); err != nil {
			t.Fatalf("count audit_log rows: %v", err)
		}
		if count == 0 {
			t.Fatal("no audit_log row recorded for the events/min rate limit crossing")
		}
	})
}
