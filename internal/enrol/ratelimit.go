// ratelimit.go is POST /enrol/hello's per-source-address cap (issue #47:
// "Rate-limit /enrol/hello by source IP"). This endpoint authenticates
// nothing before store.FirstContact resolves the presented token --
// unlike internal/ingest's requests/min cap, there is no canary identity
// yet to key on (enrol.go's own NewHandler doc comment, unchanged until
// now: "No rate limiting by source address yet ... isn't reusable here
// without inventing a new per-source-address one") -- so the key here is
// the request's own source address instead.
//
// The #47 thread that asks for this names no number of its own (searched
// the issue body and every note; nothing). Rather than invent an
// unratified figure, this reuses internal/ingest's own requests/min cap
// (issue #32 item 8: 3,000/min) and the exact same shape --  one lazily
// created golang.org/x/time/rate token bucket per key, full on creation
// -- see internal/ingest/ratelimit.go's limiterRegistry, which this
// mirrors rather than imports: internal/enrol stays structurally
// isolated from internal/ingest (enrol.go's own package doc comment), and
// limiterRegistry is unexported there in any case. Flagged here, per this
// build's report, as a contested number rather than a settled one.
package enrol

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// helloRequestsPerMinute is the per-source-address cap -- see this file's
// own package doc comment for why it borrows internal/ingest's figure.
const helloRequestsPerMinute = 3000

// helloAuditCooldown bounds how often a sustained flood of refused
// requests from one source address writes an audit entry: the limiter
// itself only throttles *allowed* requests, so without this a flood
// past the cap could still turn into an unbounded audit_log insert flood
// -- the same defect class internal/ingest/auditcoalesce.go exists to
// fix on that package's own rate-limited path, mirrored here at the
// simplest shape that fixes it rather than importing that package's
// unexported coalescer.
const helloAuditCooldown = time.Minute

// sourceLimiters hands out (and lazily creates) one token bucket per
// source address seen at POST /enrol/hello, and separately tracks the
// last time each address's refusal was audited (helloAuditCooldown
// apart) -- internal/ingest's limiterRegistry, minus the per-canary
// events/min half that endpoint has no equivalent of, keyed on address
// instead of an authenticated identity. Like that registry, it never
// shrinks: an enrolment listener sees a small, operator-scale set of
// source addresses over its life, not an attacker-scale one worth
// evicting.
type sourceLimiters struct {
	mu        sync.Mutex
	byAddr    map[string]*rate.Limiter
	lastAudit map[string]time.Time
}

func newSourceLimiters() *sourceLimiters {
	return &sourceLimiters{byAddr: make(map[string]*rate.Limiter), lastAudit: make(map[string]time.Time)}
}

// allow reports whether addr may make one more POST /enrol/hello request
// right now.
func (s *sourceLimiters) allow(addr string) bool {
	s.mu.Lock()
	lim, ok := s.byAddr[addr]
	if !ok {
		lim = rate.NewLimiter(rate.Limit(float64(helloRequestsPerMinute)/60.0), helloRequestsPerMinute)
		s.byAddr[addr] = lim
	}
	s.mu.Unlock()
	return lim.Allow()
}

// shouldAudit reports whether a refusal for addr at now should write an
// audit entry -- at most once per helloAuditCooldown, so a sustained
// flood past the cap costs this package one row a minute, not one per
// refused request. now is a parameter (not time.Now()) so this stays on
// the handler's own injectable clock, matching every other handler in
// this codebase.
func (s *sourceLimiters) shouldAudit(addr string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	last, ok := s.lastAudit[addr]
	if ok && now.Sub(last) < helloAuditCooldown {
		return false
	}
	s.lastAudit[addr] = now
	return true
}

// sourceAddr returns the host part of r.RemoteAddr -- net.SplitHostPort,
// the same extraction internal/ingest/heartbeat.go's own last-seen-address
// write uses -- falling back to the raw value on a parse failure so a
// request that somehow arrives with an unparseable RemoteAddr is still
// rate-limited under some key rather than skipping the limiter entirely.
func sourceAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
