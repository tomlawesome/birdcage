package portscan

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// fakeClock drives the window, the cooldown and the eviction bound
// without sleeping. All three behaviours are entirely made of timing, so
// real sleeps would make this file both slow and flaky while testing
// nothing extra.
type fakeClock struct{ t time.Time }

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// hit is one connection attempt from src to dstPort, as the detector
// would hand it to the tracker after the listening-port test.
func hit(src string, srcPort, dstPort uint16, proto string) packet {
	return packet{
		Src:      netip.MustParseAddr(src),
		Dst:      netip.MustParseAddr("203.0.113.9"),
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: proto,
	}
}

func TestTrackerFiresOnceAtTheThreshold(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	tr := newTracker(trackerConfig{Now: clock.Now})

	// Four distinct ports is under DefaultThreshold and must stay quiet:
	// a handful of refused connections is a misconfigured client, and
	// this box would be useless if it cried scan at one.
	for i, port := range []uint16{21, 23, 25, 3389} {
		if _, ok := tr.Observe(hit("198.51.100.5", 44123, port, ProtoTCP)); ok {
			t.Fatalf("fired after %d distinct ports, want silence below the threshold of %d", i+1, DefaultThreshold)
		}
		clock.Advance(time.Second)
	}

	det, ok := tr.Observe(hit("198.51.100.5", 44124, 5900, ProtoTCP))
	if !ok {
		t.Fatal("did not fire on the fifth distinct port")
	}
	if got, want := len(det.Ports), DefaultThreshold; got != want {
		t.Errorf("detection lists %d ports, want %d", got, want)
	}
	if det.FirstPort != 21 {
		t.Errorf("FirstPort = %d, want 21 (the first non-listening port seen)", det.FirstPort)
	}
	if det.SrcPort != 44124 {
		t.Errorf("SrcPort = %d, want the source port of the packet that tripped it", det.SrcPort)
	}
	if det.Protocol != ProtoTCP {
		t.Errorf("Protocol = %q, want %q", det.Protocol, ProtoTCP)
	}
}

// TestTrackerRepeatedPortIsNotAScan is the distinction the whole
// threshold rests on: five packets is not five ports.
func TestTrackerRepeatedPortIsNotAScan(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	tr := newTracker(trackerConfig{Now: clock.Now})

	for i := 0; i < 50; i++ {
		if _, ok := tr.Observe(hit("198.51.100.5", 44123, 9999, ProtoTCP)); ok {
			t.Fatalf("fired on retry %d against a single port", i)
		}
		clock.Advance(100 * time.Millisecond)
	}
}

// TestTrackerWindowSlides: ports touched longer ago than the window must
// stop counting, or a host that touches one closed port every ten
// minutes eventually looks like a scanner.
func TestTrackerWindowSlides(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	tr := newTracker(trackerConfig{Now: clock.Now})

	// Four ports, then wait out the window, then four more. Eight
	// distinct ports in total, never more than four inside any window.
	for _, port := range []uint16{21, 23, 25, 3389} {
		if _, ok := tr.Observe(hit("198.51.100.5", 44123, port, ProtoTCP)); ok {
			t.Fatal("fired below the threshold")
		}
	}
	clock.Advance(DefaultWindow + time.Second)
	for _, port := range []uint16{5900, 8080, 8443, 9999} {
		if _, ok := tr.Observe(hit("198.51.100.5", 44123, port, ProtoTCP)); ok {
			t.Fatal("fired on ports whose window-mates had already aged out")
		}
	}

	// A fifth port inside the second window does fire, proving the
	// window aged the first four out rather than losing the source
	// altogether.
	if _, ok := tr.Observe(hit("198.51.100.5", 44123, 1234, ProtoTCP)); !ok {
		t.Fatal("did not fire on the fifth port of the second window")
	}
}

// TestTrackerRateCap is the flood defence at the detection layer: an
// nmap sweep of every port is one event plus one a minute, not one per
// port. Without it a single scan would produce tens of thousands of
// queued events and evict every real alert ahead of them.
func TestTrackerRateCap(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	tr := newTracker(trackerConfig{Now: clock.Now})

	fired := 0
	// A continuous scan: one new port every 100ms for ten minutes. The
	// window keeps sliding, so the threshold is met continuously, and
	// only the cooldown limits how often that is reported.
	const step = 100 * time.Millisecond
	const total = 10 * time.Minute
	for elapsed, port := time.Duration(0), uint16(1024); elapsed <= total; elapsed, port = elapsed+step, port+1 {
		if _, ok := tr.Observe(hit("198.51.100.5", 44123, port, ProtoTCP)); ok {
			fired++
		}
		clock.Advance(step)
	}

	// The first event lands on the packet that reaches the threshold,
	// which is the fifth -- four steps in, not at zero -- and everything
	// after it waits out a full cooldown.
	firstFire := time.Duration(DefaultThreshold-1) * step
	want := 1 + int((total-firstFire)/DefaultCooldown)
	if fired != want {
		t.Fatalf("fired %d times over %s, want %d (one at the threshold, then one per %s)", fired, total, want, DefaultCooldown)
	}
	// Stated without arithmetic as well, so a change to the defaults that
	// quietly turns this into a per-packet firehose cannot also quietly
	// rewrite what the test expects.
	if fired > 20 {
		t.Fatalf("fired %d times for one ten-minute scan; the rate cap is not holding", fired)
	}
}

// TestTrackerSeparatesProtocols: a host sweeping TCP and UDP is two
// detections, because one event's PROTO cannot honestly describe both.
func TestTrackerSeparatesProtocols(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	tr := newTracker(trackerConfig{Now: clock.Now})

	var tcpFired, udpFired bool
	for _, port := range []uint16{21, 23, 25, 3389, 5900} {
		if _, ok := tr.Observe(hit("198.51.100.5", 44123, port, ProtoTCP)); ok {
			tcpFired = true
		}
		if _, ok := tr.Observe(hit("198.51.100.5", 44123, port, ProtoUDP)); ok {
			udpFired = true
		}
		clock.Advance(time.Second)
	}
	if !tcpFired || !udpFired {
		t.Fatalf("tcp fired = %v, udp fired = %v; want both", tcpFired, udpFired)
	}
	if tr.size() != 2 {
		t.Fatalf("tracking %d entries, want 2 (one per protocol)", tr.size())
	}
}

// TestTrackerBoundsTheTable is the memory bound. A source address is
// whatever the packet claims, so a flood of forged addresses is free to
// send and would otherwise grow this table without limit -- the agent
// becoming the thing that falls over, which is the failure the queue's
// own caps exist one layer later to prevent.
func TestTrackerBoundsTheTable(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	const cap = 64
	tr := newTracker(trackerConfig{MaxSources: cap, Now: clock.Now})

	// Ten times the cap in distinct spoofed sources.
	for i := 0; i < cap*10; i++ {
		src := fmt.Sprintf("198.51.100.%d", i%256)
		if i >= 256 {
			src = fmt.Sprintf("198.51.%d.%d", i/256, i%256)
		}
		tr.Observe(hit(src, 44123, 9999, ProtoTCP))
		clock.Advance(time.Millisecond)
	}

	if tr.size() > cap {
		t.Fatalf("tracking %d sources, want at most %d", tr.size(), cap)
	}
	if tr.recency.Len() != tr.size() {
		t.Fatalf("recency list holds %d entries but the table holds %d; eviction left them out of step", tr.recency.Len(), tr.size())
	}
}

// TestTrackerEvictsLeastRecentlySeen: the source still scanning must
// survive a flood of one-shot spoofed addresses, or the bound above
// becomes a way to hide behind noise.
func TestTrackerEvictsLeastRecentlySeen(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	tr := newTracker(trackerConfig{MaxSources: 16, Now: clock.Now})

	const scanner = "198.51.100.5"
	// Four ports from the real scanner, each followed by eight
	// never-seen-again spoofed addresses, so the scanner stays active
	// while 32 one-shot sources churn through a 16-entry table.
	noise := 0
	for _, port := range []uint16{21, 23, 25, 3389} {
		tr.Observe(hit(scanner, 44123, port, ProtoTCP))
		for i := 0; i < 8; i++ {
			noise++
			tr.Observe(hit(fmt.Sprintf("203.0.113.%d", noise), 44123, 9999, ProtoTCP))
		}
		clock.Advance(time.Second)
	}
	if tr.size() > 16 {
		t.Fatalf("tracking %d sources, want at most 16", tr.size())
	}

	// The scanner's fifth port still fires, so its first four were never
	// evicted despite 32 other sources passing through the table.
	if _, ok := tr.Observe(hit(scanner, 44123, 5900, ProtoTCP)); !ok {
		t.Fatal("the continuously-active scanner was evicted by one-shot noise")
	}
}
