package ingest

import (
	"strconv"
	"sync"
	"time"
)

// auditCoalesceInterval bounds how often the coalescer in this file lets
// a repeating (canaryID, action) pair write to audit_log -- issue #57:
// recordTokenConflictIfSuccessorActive and recordRateLimitCrossed used to
// append one row per HTTP request at a rate the caller controls, and
// audit_log is append-only by database trigger (migration 0002's BEFORE
// UPDATE / BEFORE DELETE), so those rows could never be reclaimed. A
// caller needing no working credential (a revoked token is enough for
// the token-conflict path) could flood the table for free.
//
// 1 minute is not an arbitrary choice: two health-state windows in
// internal/store/health.go read only the MOST RECENT matching audit_log
// row for a (action, target) pair -- throttledWindow (5 minutes, action
// "ingest.rate_limited") and tokenConflictQuietPeriod (24 hours, action
// "ingest.token_conflict"). While a flood is ongoing, this coalescer
// guarantees a fresh row at least once per auditCoalesceInterval, so the
// newest row is never more than one interval old. At 1 minute that is
// comfortably inside throttledWindow -- the tighter of the two windows by
// a wide margin -- so both health states keep reading exactly as they did
// when every request wrote its own row. That equivalence is the point:
// this changes the write volume, not what either health state reports.
// See TestFloodedRateLimitStillReadsThrottled and
// TestFloodedTokenConflictStillReadsTokenConflict.
const auditCoalesceInterval = 1 * time.Minute

// auditCoalesceKey identifies one coalescing bucket. recordRateLimitCrossed
// is called for both the requests/min and events/min caps and writes
// action "ingest.rate_limited" either way -- the same action
// latestAuditSince queries on for the throttled state -- so both share one
// bucket per canary; that matches what the health state can see, since it
// only ever looks at the most recent "ingest.rate_limited" row regardless
// of which cap crossed.
type auditCoalesceKey struct {
	canaryID string
	action   string
}

// auditCoalesceEntry is one key's coalescing state: when a row was last
// actually written for it, and how many occurrences have arrived and been
// suppressed since.
type auditCoalesceEntry struct {
	lastWrite  time.Time
	suppressed int
}

// auditCoalescer decides, per (canaryID, action), whether an occurrence
// should write its own audit_log row or be folded into the count the next
// write reports. Guarded by a single mutex, the same coarse-grained shape
// limiterRegistry uses (ratelimit.go) for the same reason: the map is
// written from every concurrent ingest request.
//
// Like limiterRegistry, this map never shrinks -- a canary or action that
// stops occurring just leaves one small struct behind. That is an
// accepted, bounded cost: the key space is the enrolled fleet times a
// handful of fixed action strings, not anything a caller controls.
type auditCoalescer struct {
	mu    sync.Mutex
	state map[auditCoalesceKey]*auditCoalesceEntry
}

func newAuditCoalescer() *auditCoalescer {
	return &auditCoalescer{state: make(map[auditCoalesceKey]*auditCoalesceEntry)}
}

// admit reports whether the occurrence of (canaryID, action) happening at
// now should write its own audit_log row, and if so how many occurrences
// -- including this one -- it represents since the previous written row.
//
// The first occurrence for a key always admits (write=true, occurrences=1):
// a health state must never wait out a coalescing interval for its first
// signal. Every later occurrence within auditCoalesceInterval of the last
// write is counted, not written (write=false); the next occurrence once
// the interval has elapsed admits again and reports the full count folded
// into it.
func (c *auditCoalescer) admit(canaryID, action string, now time.Time) (write bool, occurrences int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := auditCoalesceKey{canaryID: canaryID, action: action}
	e, ok := c.state[key]
	if !ok {
		c.state[key] = &auditCoalesceEntry{lastWrite: now}
		return true, 1
	}
	if now.Sub(e.lastWrite) < auditCoalesceInterval {
		e.suppressed++
		return false, 0
	}
	occurrences = e.suppressed + 1
	e.lastWrite = now
	e.suppressed = 0
	return true, occurrences
}

// coalescedReason appends an occurrence-count clause to base when a
// written row stands in for more than itself, so a reader can see the
// real scale of what was folded into it even though most of the
// occurrences never got their own row. noun names what's being counted
// (e.g. "crossings", "presentations"). A row that represents only itself
// (occurrences <= 1) is returned unchanged -- "1 of 1" reads as noise,
// not information.
func coalescedReason(base string, occurrences int, noun string) string {
	if occurrences <= 1 {
		return base
	}
	return base + " (1 of " + formatCount(occurrences) + " " + noun + " since the previous entry)"
}

// formatCount renders n (always >= 2 as admit produces it) with thousands
// separators, e.g. 4175 -> "4,175", so a large folded count reads as the
// scale it represents at a glance, not as a string of digits a reader has
// to parse.
func formatCount(n int) string {
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	lead := len(s) % 3
	if lead == 0 {
		lead = 3
	}
	out := s[:lead]
	for i := lead; i < len(s); i += 3 {
		out += "," + s[i:i+3]
	}
	return out
}
