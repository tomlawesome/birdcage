package poisoner

import (
	"sort"
	"sync"
	"time"
)

// Provisional pacing numbers.
//
// PROVISIONAL; #121 replaces them with measured values. Issue #86 decision
// 36 (owner, 2026-09-23) took these as guesses on purpose rather than
// waiting for a capture: the owner rejected an earlier "a few times a day"
// precisely because it had no evidence behind it, and these have none
// either. They are bounds on a rate that is otherwise taken from the
// segment, so being wrong makes the canary slightly too quiet or slightly
// too talkative, not wrong about what it detects.
const (
	// DefaultFloorGap is the longest a canary goes without a burst during
	// working hours: one burst every two hours. The floor exists because
	// pace-matching has nothing to match on a quiet segment -- an
	// all-Linux segment has no LLMNR traffic at all -- and a canary that
	// never asks can never be answered.
	//
	// PROVISIONAL; #121 replaces it with a measured value.
	DefaultFloorGap = 2 * time.Hour

	// DefaultCeilingGap is the shortest gap between bursts: two bursts an
	// hour. The ceiling exists because matching the median host is only
	// safe while the median is sane; one very chatty segment should not
	// turn the canary into the loudest thing on it.
	//
	// PROVISIONAL; #121 replaces it with a measured value.
	DefaultCeilingGap = 30 * time.Minute

	// minTalkingHosts is how many distinct hosts must have asked
	// something in the rolling window before their median is used at all.
	// Below it there is no median worth the name -- one host's habits are
	// not the segment's -- so the floor is used instead. Issue #86
	// decision 36's "fewer than three hosts are talking".
	//
	// PROVISIONAL; #121 replaces it with a measured value.
	minTalkingHosts = 3
)

// Burst size. Issue #86 decision 33: "two to five lookups within a
// minute (a user opening an old share retries)".
const (
	minBurstLookups = 2
	maxBurstLookups = 5

	// burstSpread is the window a burst's lookups are spread across --
	// "within a minute". The lookups are not evenly spaced inside it; see
	// Schedule.BurstGaps.
	burstSpread = time.Minute
)

// Rolling-window geometry.
const (
	// paceWindow is the "rolling day" of issue #86 decision 35.
	paceWindow = 24 * time.Hour

	// paceBuckets splits that day into hourly buckets, so expiring the
	// oldest hour is dropping one map rather than walking a list of
	// timestamps. A count is therefore accurate to the hour, which is far
	// finer than the rate it feeds.
	paceBuckets = 24

	// paceBucketWidth follows from the two above.
	paceBucketWidth = paceWindow / paceBuckets

	// maxTrackedHosts bounds how many distinct source addresses one
	// bucket remembers. A segment with more than this many hosts asking
	// in one hour is not a segment this pacing is calibrated for, and an
	// attacker who can spoof source addresses must not be able to make
	// this map the reason the canary runs out of memory. Hosts past the
	// cap are not counted, which can only make the measured median
	// smaller -- the safe direction, because a smaller median means a
	// quieter canary.
	maxTrackedHosts = 1024
)

// paceCounter counts bait-protocol queries per source host over a rolling
// day. Safe for concurrent use: one goroutine per listening socket calls
// Observe, and the burst scheduler calls Median.
type paceCounter struct {
	mu sync.Mutex

	// buckets is a ring of hourly counts, buckets[cur] being the one now
	// falling. A host's window total is its count summed across all of
	// them.
	buckets [paceBuckets]map[string]int
	cur     int

	// curStart is when the current bucket began, rounded down to the
	// bucket width so that two counters started at different moments
	// still agree about bucket boundaries.
	curStart time.Time

	// overflowed records that some host was not counted because a bucket
	// was full. Reported once at startup rather than per datagram.
	overflowed bool
}

// newPaceCounter starts a counter whose first bucket begins at now.
func newPaceCounter(now time.Time) *paceCounter {
	c := &paceCounter{curStart: now.Truncate(paceBucketWidth)}
	c.buckets[0] = make(map[string]int)
	return c
}

// Observe counts one query from host.
//
// host is the source address as a string, which is all the identity this
// counter has or wants: it never resolves it, connects to it or stores
// anything else about it.
func (c *paceCounter) Observe(host string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.advance(now)
	bucket := c.buckets[c.cur]
	if _, seen := bucket[host]; !seen && len(bucket) >= maxTrackedHosts {
		c.overflowed = true
		return
	}
	bucket[host]++
}

// Median returns the median host's query count over the rolling window,
// and how many distinct hosts contributed to it.
//
// The median, never the mean and never the maximum: issue #86 decision 35
// is explicit that the canary "matches the MEDIAN host, never the
// busiest", because one noisy host -- a misconfigured print server, or the
// attacker's own scanner -- would otherwise set the canary's rate. For an
// even number of hosts this takes the lower of the two middle values, so
// the answer is always a rate some real host actually had.
func (c *paceCounter) Median(now time.Time) (queries, hosts int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.advance(now)

	totals := make(map[string]int)
	for _, bucket := range c.buckets {
		for host, n := range bucket {
			totals[host] += n
		}
	}
	if len(totals) == 0 {
		return 0, 0
	}
	counts := make([]int, 0, len(totals))
	for _, n := range totals {
		counts = append(counts, n)
	}
	sort.Ints(counts)
	return counts[(len(counts)-1)/2], len(counts)
}

// Overflowed reports whether any host went uncounted because a bucket hit
// maxTrackedHosts.
func (c *paceCounter) Overflowed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.overflowed
}

// advance rolls the ring forward to cover now, clearing the buckets it
// passes. Called under c.mu by both Observe and Median, so a counter that
// has heard nothing for a day still reports an empty window rather than
// day-old counts.
func (c *paceCounter) advance(now time.Time) {
	at := now.Truncate(paceBucketWidth)
	if !at.After(c.curStart) {
		// Same bucket, or a clock that went backwards. A backwards step
		// is left alone deliberately: re-bucketing on it would throw away
		// real counts over something the canary cannot verify.
		if c.buckets[c.cur] == nil {
			c.buckets[c.cur] = make(map[string]int)
		}
		return
	}
	steps := int(at.Sub(c.curStart) / paceBucketWidth)
	if steps >= paceBuckets {
		// Longer than the whole window: nothing in it is still in date.
		for i := range c.buckets {
			c.buckets[i] = nil
		}
		c.cur = 0
		c.buckets[0] = make(map[string]int)
		c.curStart = at
		return
	}
	for i := 0; i < steps; i++ {
		c.cur = (c.cur + 1) % paceBuckets
		c.buckets[c.cur] = make(map[string]int)
	}
	c.curStart = at
}

// PaceSettings are the per-canary pacing settings. All three are settings
// rather than constants because issue #86 decision 36 says so: the floor
// and the ceiling are guesses that an operator on an unusual segment must
// be able to correct without waiting for a release, and working hours are
// a fact about the operator's office, not about the software.
type PaceSettings struct {
	// FloorGap is the longest gap between bursts during working hours.
	FloorGap time.Duration

	// CeilingGap is the shortest gap between bursts.
	CeilingGap time.Duration

	// Hours are the hours, in the canary's own timezone, during which
	// bursts happen at all.
	Hours WorkingHours
}

// DefaultPaceSettings is what a canary enrolled without pacing settings
// gets.
func DefaultPaceSettings() PaceSettings {
	return PaceSettings{
		FloorGap:   DefaultFloorGap,
		CeilingGap: DefaultCeilingGap,
		Hours:      DefaultWorkingHours(),
	}
}

// normalise fills in any zero field from the defaults and makes sure the
// ceiling is not looser than the floor, which would otherwise make the two
// clamps in matchedGap fight.
func (s PaceSettings) normalise() PaceSettings {
	if s.FloorGap <= 0 {
		s.FloorGap = DefaultFloorGap
	}
	if s.CeilingGap <= 0 {
		s.CeilingGap = DefaultCeilingGap
	}
	if s.CeilingGap > s.FloorGap {
		// An operator who set a ceiling looser than the floor asked for
		// two contradictory things; the quieter one wins, because being
		// too quiet is the failure that only costs detection latency.
		s.CeilingGap = s.FloorGap
	}
	if s.Hours.zero() {
		s.Hours = DefaultWorkingHours()
	}
	return s
}

// matchedGap turns a measured median into the gap before the next burst.
//
// The chain is: the median host asked `queries` times in a rolling day, so
// matching it means asking about that many times too; a burst is
// meanBurstLookups lookups, so that is the number of bursts a day; spread
// over the working hours a day actually has, that is the gap between them.
// Then the floor and the ceiling clamp it.
func matchedGap(queries, hosts int, s PaceSettings) time.Duration {
	s = s.normalise()
	if hosts < minTalkingHosts || queries <= 0 {
		// Nothing to match: a quiet segment, or one where only one or two
		// hosts ask anything. The floor is the whole rate here.
		return s.FloorGap
	}

	working := s.Hours.DailySpan()
	if working <= 0 {
		return s.FloorGap
	}

	// A burst is minBurstLookups to maxBurstLookups lookups drawn evenly,
	// so its mean size is (2+5)/2 = 3.5. Dividing by 3.5 is multiplying by
	// 2 and dividing by 7, which keeps the whole calculation in integers:
	// 7 is minBurstLookups+maxBurstLookups.
	burstsPerDay := (2 * queries) / (minBurstLookups + maxBurstLookups)
	if burstsPerDay <= 0 {
		return s.FloorGap
	}
	gap := working / time.Duration(burstsPerDay)

	if gap > s.FloorGap {
		return s.FloorGap
	}
	if gap < s.CeilingGap {
		return s.CeilingGap
	}
	return gap
}
