package ingest

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// limiterLimits is the pair of per-canary caps issue #32 item 8 sets:
// 3,000 requests/min and 60,000 events/min. A real handler always uses
// defaultLimiterLimits; tests inject a much smaller pair so a limit can
// be crossed in a handful of calls instead of thousands (see
// TestHandleBatchOverLimitReturns429AndIsRecorded).
type limiterLimits struct {
	RequestsPerMinute int
	EventsPerMinute   int
}

// defaultLimiterLimits are the limits issue #32 item 8 specifies,
// unchanged from research: 3,000 requests/min, 60,000 events/min.
var defaultLimiterLimits = limiterLimits{RequestsPerMinute: 3000, EventsPerMinute: 60000}

// canaryLimiters is one canary's pair of token buckets. Both are
// initialized full (burst == the per-minute cap), so a canary that has
// been quiet can immediately send a minute's worth of traffic -- the
// same shape golang.org/x/time/rate's own docs recommend for a
// requests-per-interval limit, and the reason a fresh canaryLimiters is
// never "already partially spent".
type canaryLimiters struct {
	requests *rate.Limiter
	events   *rate.Limiter
}

// limiterRegistry hands out (and lazily creates) the canaryLimiters for
// each canary ID seen -- keyed on the authenticated token's canary,
// never on anything the caller supplies (issue #32 research: "keying the
// limiter on the authenticated token's canary sidesteps the classic
// spoofable-key failure"). It never shrinks: a canary that stops
// sending traffic leaves one small struct behind, an accepted, bounded
// cost (the fleet size is finite and human-managed, unlike an
// unauthenticated per-IP table would be).
type limiterRegistry struct {
	mu     sync.Mutex
	limits limiterLimits
	byID   map[string]*canaryLimiters
}

func newLimiterRegistry(limits limiterLimits) *limiterRegistry {
	return &limiterRegistry{limits: limits, byID: make(map[string]*canaryLimiters)}
}

func (r *limiterRegistry) get(canaryID string) *canaryLimiters {
	r.mu.Lock()
	defer r.mu.Unlock()
	cl, ok := r.byID[canaryID]
	if !ok {
		cl = &canaryLimiters{
			requests: rate.NewLimiter(perMinute(r.limits.RequestsPerMinute), r.limits.RequestsPerMinute),
			events:   rate.NewLimiter(perMinute(r.limits.EventsPerMinute), r.limits.EventsPerMinute),
		}
		r.byID[canaryID] = cl
	}
	return cl
}

// perMinute converts a "N per minute" cap into the rate.Limit (a
// per-second float) golang.org/x/time/rate takes.
func perMinute(n int) rate.Limit {
	return rate.Limit(float64(n) / 60.0)
}

// allowRequest reports whether canaryID may make one more request right
// now against the requests/min cap.
func (r *limiterRegistry) allowRequest(canaryID string) bool {
	return r.get(canaryID).requests.Allow()
}

// allowEvents reports whether canaryID may process n more events right
// now against the events/min cap. n can exceed the configured burst (a
// single batch larger than the per-minute cap): AllowN reports false in
// that case rather than ever allowing it, so an oversized batch is
// rejected by the rate limit exactly as a flood of small ones would be.
func (r *limiterRegistry) allowEvents(canaryID string, n int) bool {
	return r.get(canaryID).events.AllowN(time.Now(), n)
}
