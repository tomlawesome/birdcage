package portscan

import (
	"container/list"
	"net/netip"
	"time"
)

// Detection thresholds. All three are documented, tunable implementation
// choices in the sense docs/security-by-design.md means, not settled
// facts: they are the numbers issue #65 proposed, and an operator with a
// noisier segment should be able to move them without the shape of the
// detector changing.
const (
	// DefaultThreshold is how many *distinct* non-listening destination
	// ports one source must touch inside DefaultWindow before it counts
	// as a scan. Distinct ports, not packets: a single retried
	// connection to one closed port is a misconfigured client, and
	// five separate closed ports is somebody looking.
	DefaultThreshold = 5

	// DefaultWindow is the sliding window those distinct ports must fall
	// inside. It slides per source: each port carries the time it was
	// last seen and ages out of the count on its own.
	DefaultWindow = 30 * time.Second

	// DefaultCooldown is the minimum gap between two events for the same
	// source. A scan is a continuous act, and this box exists to be
	// flooded (#48's "Constraints that are not negotiable"): nmap across
	// 65535 ports is one event plus one per minute while it runs, never
	// one per packet. The first detection fires immediately; everything
	// after it waits out this gap.
	DefaultCooldown = 60 * time.Second

	// DefaultMaxSources bounds the tracking table. Every entry is keyed
	// by a source address the packet itself claims, and a source address
	// is trivially spoofed, so without a bound a single flood of forged
	// SYNs from random addresses would grow this table until the agent
	// is the thing that falls over -- the exact failure
	// queue.MemQueue's own caps exist to prevent, one layer earlier.
	// Least-recently-seen entries are evicted first.
	DefaultMaxSources = 4096
)

// detection is one scan the tracker has decided to report. The tracker
// produces it; event.go turns it into OpenCanary's JSON.
type detection struct {
	Src     netip.Addr
	SrcPort uint16
	Dst     netip.Addr
	// FirstPort is the first non-listening destination port seen from
	// this source in the window that produced this detection -- the
	// event's dst_port, so a reader of a single alert sees a real port
	// the scanner touched rather than an invented placeholder.
	FirstPort uint16
	// Ports is every distinct non-listening destination port still
	// inside the window, in first-seen order.
	Ports []uint16
	// Protocol is ProtoTCP or ProtoUDP. The tracker keys on it, so a
	// host sweeping TCP and UDP produces two detections rather than one
	// event whose PROTO is a coin flip.
	Protocol string
}

// trackerKey identifies one source's activity in one protocol.
type trackerKey struct {
	src   netip.Addr
	proto string
}

// sourceState is one key's sliding window.
type sourceState struct {
	// seen is the last time each distinct port was touched, and order is
	// the same ports in first-seen order. Both are pruned together by
	// prune, so order never holds a port seen has forgotten.
	seen  map[uint16]time.Time
	order []uint16

	// lastEmit is when this key last produced a detection, and emitted
	// says whether it ever has -- distinguishing "due now, never fired"
	// from "fired at the zero time".
	lastEmit time.Time
	emitted  bool

	// elem is this key's position in the tracker's recency list, so
	// touching a source is O(1) rather than a scan of the table.
	elem *list.Element

	// lastSrcPort and lastDst are carried onto the detection: the
	// scanner's own source port and the address it aimed at, as of the
	// packet that tripped the threshold.
	lastSrcPort uint16
	lastDst     netip.Addr
}

// tracker is the sliding-window detector. It is not safe for concurrent
// use: exactly one capture goroutine calls Observe, and the tracker
// holds no state anything else reads.
type tracker struct {
	threshold  int
	window     time.Duration
	cooldown   time.Duration
	maxSources int

	// now is injected so the tests can drive the window, the cooldown
	// and the eviction bound with a fake clock instead of sleeping --
	// three behaviours whose whole content is timing, which real sleeps
	// would test slowly and flakily.
	now func() time.Time

	states map[trackerKey]*sourceState
	// recency holds trackerKey values, least-recently-seen at the front,
	// which is the eviction order when the table is full.
	recency *list.List
}

// trackerConfig is the tracker's tunables. A zero field takes the
// matching Default above, so a caller that only wants a different
// threshold says only that.
type trackerConfig struct {
	Threshold  int
	Window     time.Duration
	Cooldown   time.Duration
	MaxSources int
	Now        func() time.Time
}

func newTracker(cfg trackerConfig) *tracker {
	if cfg.Threshold <= 0 {
		cfg.Threshold = DefaultThreshold
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultWindow
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = DefaultCooldown
	}
	if cfg.MaxSources <= 0 {
		cfg.MaxSources = DefaultMaxSources
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &tracker{
		threshold:  cfg.Threshold,
		window:     cfg.Window,
		cooldown:   cfg.Cooldown,
		maxSources: cfg.MaxSources,
		now:        cfg.Now,
		states:     make(map[trackerKey]*sourceState),
		recency:    list.New(),
	}
}

// Observe records one connection attempt to a port that is not one of
// ours, and reports a detection when this source has just crossed the
// threshold and is not inside its cooldown. The caller filters listening
// ports out before calling: this function's entire input is "somebody
// touched a port nothing is on".
func (t *tracker) Observe(p packet) (detection, bool) {
	now := t.now()
	key := trackerKey{src: p.Src, proto: p.Protocol}

	st, ok := t.states[key]
	if !ok {
		st = &sourceState{seen: make(map[uint16]time.Time)}
		st.elem = t.recency.PushBack(key)
		t.states[key] = st
		t.evictOverCap()
	} else {
		t.recency.MoveToBack(st.elem)
	}

	st.lastSrcPort = p.SrcPort
	st.lastDst = p.Dst

	// Prune first, then record: a port last touched outside the window
	// should not keep the count up, and re-touching a port that has just
	// aged out makes it a fresh first sighting rather than an
	// immortal one.
	st.prune(now, t.window)
	if _, already := st.seen[p.DstPort]; !already {
		st.order = append(st.order, p.DstPort)
	}
	st.seen[p.DstPort] = now

	if len(st.seen) < t.threshold {
		return detection{}, false
	}
	if st.emitted && now.Sub(st.lastEmit) < t.cooldown {
		return detection{}, false
	}
	st.lastEmit = now
	st.emitted = true

	return detection{
		Src:       p.Src,
		SrcPort:   st.lastSrcPort,
		Dst:       st.lastDst,
		FirstPort: st.order[0],
		Ports:     append([]uint16(nil), st.order...),
		Protocol:  p.Protocol,
	}, true
}

// prune drops every port last seen more than window ago, from both the
// map and the order slice, keeping the two in step. The slice is rebuilt
// in place rather than allocated: it is bounded by however many distinct
// ports one source touched inside one window, which a real scan makes
// large and a rebuild per packet would make expensive to allocate.
func (st *sourceState) prune(now time.Time, window time.Duration) {
	cutoff := now.Add(-window)
	kept := st.order[:0]
	for _, port := range st.order {
		if last, ok := st.seen[port]; ok && last.After(cutoff) {
			kept = append(kept, port)
			continue
		}
		delete(st.seen, port)
	}
	st.order = kept
}

// evictOverCap drops least-recently-seen entries until the table is
// within maxSources. A loop rather than a single removal because a
// lowered cap (a future reconfiguration) should settle in one call
// rather than one entry per packet.
func (t *tracker) evictOverCap() {
	for len(t.states) > t.maxSources {
		oldest := t.recency.Front()
		if oldest == nil {
			return
		}
		t.recency.Remove(oldest)
		delete(t.states, oldest.Value.(trackerKey))
	}
}

// size is the number of tracked (source, protocol) pairs. Test-facing:
// it is how the eviction bound is asserted.
func (t *tracker) size() int { return len(t.states) }
