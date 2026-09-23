package enrol

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/tomlawesome/birdcage/internal/db"
)

// TestSourceLimitersAllowBoundary proves the real cap this package ships
// with: helloRequestsPerMinute allowed calls for one address succeed, the
// next is refused, and a different address is unaffected -- run directly
// against sourceLimiters rather than through the HTTP handler, since a
// token bucket's Allow() is synchronous (no sleeping) and helloRequestsPerMinute
// calls is a fast, deterministic loop either way.
func TestSourceLimitersAllowBoundary(t *testing.T) {
	s := newSourceLimiters()
	for i := 0; i < helloRequestsPerMinute; i++ {
		if !s.allow("192.0.2.1") {
			t.Fatalf("allow() call %d/%d = false, want true (still inside the burst)", i+1, helloRequestsPerMinute)
		}
	}
	if s.allow("192.0.2.1") {
		t.Errorf("allow() call %d = true, want false (burst exhausted)", helloRequestsPerMinute+1)
	}
	if !s.allow("192.0.2.2") {
		t.Error("allow() for a different address = false, want true (buckets are per-address)")
	}
}

// TestShouldAuditCooldown proves the audit-write debounce: the first
// refusal for an address is always auditable, a second one inside the
// cooldown is not, and one after the cooldown is again.
func TestShouldAuditCooldown(t *testing.T) {
	s := newSourceLimiters()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if !s.shouldAudit("192.0.2.1", t0) {
		t.Error("shouldAudit at t0 = false, want true (first refusal for this address)")
	}
	if s.shouldAudit("192.0.2.1", t0.Add(helloAuditCooldown-time.Second)) {
		t.Error("shouldAudit one second inside the cooldown = true, want false")
	}
	if !s.shouldAudit("192.0.2.1", t0.Add(helloAuditCooldown)) {
		t.Error("shouldAudit exactly at the cooldown boundary = false, want true")
	}
	if !s.shouldAudit("192.0.2.2", t0) {
		t.Error("shouldAudit for a different address = false, want true (cooldowns are per-address)")
	}
}

// TestSourceAddrFallsBackOnUnparseableRemoteAddr: a RemoteAddr with no
// port (should never happen against a real listener, but httptest and a
// misbehaving proxy can both produce one) still yields a rate-limit key,
// rather than the limiter silently applying to nothing.
func TestSourceAddrFallsBackOnUnparseableRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/enrol/hello", nil)
	req.RemoteAddr = "not-a-host-port"
	if got := sourceAddr(req); got != "not-a-host-port" {
		t.Errorf("sourceAddr(unparseable) = %q, want the raw value back", got)
	}

	req.RemoteAddr = "203.0.113.9:5555"
	if got := sourceAddr(req); got != "203.0.113.9" {
		t.Errorf("sourceAddr(host:port) = %q, want the host only", got)
	}
}

// TestHandleHelloRateLimitedRefusesAndAudits: with this source address's
// bucket already exhausted, POST /enrol/hello refuses with 429 (not the
// uniform token-refusal body -- this is a different failure class, never
// reached the token at all) and writes exactly one audit entry per
// helloAuditCooldown, not one per request.
func TestHandleHelloRateLimitedRefusesAndAudits(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		setAddresses(t, database)
		testCA := newTestCA(t)

		now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		// Built directly rather than through NewHandler (which returns
		// http.Handler, the mux, not *handler) so this test can reach the
		// unexported limiters field and pre-exhaust one address's bucket
		// -- calling handleHello directly is equally valid, since
		// NewHandler's mux does nothing but route to it.
		h := &handler{
			db: database, ca: testCA, ingestURL: "https://canary.example:8443",
			now: func() time.Time { return now }, logger: slog.Default(), limiters: newSourceLimiters(),
		}
		h.limiters.byAddr["192.0.2.1"] = rate.NewLimiter(0, 0) // httptest.NewRequest's default RemoteAddr host

		rec := httptest.NewRecorder()
		h.handleHello(rec, httptest.NewRequest(http.MethodPost, "/enrol/hello", helloRequestBody("whatever")))
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusTooManyRequests, rec.Body.String())
		}
		if n := countHelloRateLimitedRows(t, database); n != 1 {
			t.Fatalf("enrolment.hello_rate_limited audit rows after one refusal = %d, want 1", n)
		}

		// A second refusal moments later, still inside the cooldown, must
		// not write a second entry.
		rec2 := httptest.NewRecorder()
		h.handleHello(rec2, httptest.NewRequest(http.MethodPost, "/enrol/hello", helloRequestBody("whatever")))
		if rec2.Code != http.StatusTooManyRequests {
			t.Fatalf("second status = %d, want %d", rec2.Code, http.StatusTooManyRequests)
		}
		if n := countHelloRateLimitedRows(t, database); n != 1 {
			t.Fatalf("enrolment.hello_rate_limited audit rows after a second refusal inside the cooldown = %d, want still 1", n)
		}
	})
}

func countHelloRateLimitedRows(t *testing.T, database *db.DB) int {
	t.Helper()
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'enrolment.hello_rate_limited'`).Scan(&n); err != nil {
		t.Fatalf("count enrolment.hello_rate_limited audit rows: %v", err)
	}
	return n
}
