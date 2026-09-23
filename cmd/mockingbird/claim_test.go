package main

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/agent/queue"
)

// TestClaimTracker_ExactlyOneCandidateClaims is note 19897's exactly-one
// rule, positive case: a window with a single matching candidate claims
// it -- pending while the window is open, then decided (marker attached,
// no longer pending) once resolved.
func TestClaimTracker_ExactlyOneCandidateClaims(t *testing.T) {
	tr := newClaimTracker()
	w := tr.startWindow("portscan", "192.0.2.10", "the-marker")

	if tr.pending("ev-1") {
		// pending() only reports true for a candidate a window has
		// actually recorded -- nothing has been observed yet.
		t.Fatal("pending(ev-1) = true before observe, want false")
	}

	tr.observe("ev-1", "portscan", "192.0.2.10")
	if !tr.pending("ev-1") {
		t.Fatal("pending(ev-1) = false once recorded as a candidate of an open window, want true")
	}

	tr.resolveWindow(w)

	if tr.pending("ev-1") {
		t.Fatal("pending(ev-1) = true after the window resolved, want false")
	}
	marker, ok := tr.marker("ev-1")
	if !ok || marker != "the-marker" {
		t.Fatalf("marker(ev-1) = (%q, %v), want (\"the-marker\", true)", marker, ok)
	}
}

// TestClaimTracker_TwoCandidatesNeitherClaimed: two matching candidates
// inside the same window means the exactly-one rule fails, so neither is
// claimed and both ship as ordinary events.
func TestClaimTracker_TwoCandidatesNeitherClaimed(t *testing.T) {
	tr := newClaimTracker()
	w := tr.startWindow("ntp", "192.0.2.10", "the-marker")

	tr.observe("ev-1", "ntp", "192.0.2.10")
	tr.observe("ev-2", "ntp", "192.0.2.10")
	tr.resolveWindow(w)

	for _, id := range []string{"ev-1", "ev-2"} {
		if tr.pending(id) {
			t.Errorf("pending(%s) = true after resolve, want false", id)
		}
		if _, ok := tr.marker(id); ok {
			t.Errorf("marker(%s) claimed, want neither candidate claimed when two arrived", id)
		}
	}
}

// TestClaimTracker_ZeroCandidatesNoClaim: a window that closes having
// seen nothing claims nothing -- the ordinary "the agent's own probe
// never got a matching hit back" case.
func TestClaimTracker_ZeroCandidatesNoClaim(t *testing.T) {
	tr := newClaimTracker()
	w := tr.startWindow("portscan", "192.0.2.10", "the-marker")
	tr.resolveWindow(w)

	if len(tr.claimed) != 0 {
		t.Fatalf("claimed = %v, want empty after a window with no candidates resolved", tr.claimed)
	}
}

// TestClaimTracker_WindowClosesLateEventUnclaimed: an event whose
// observe call lands after resolveWindow already ran -- the window has
// closed -- must not retroactively join it. This is note 19897's "an
// agent restart mid-window loses the claim state -- events go out
// unclaimed" safe direction, exercised without an actual restart: once
// resolved, a window is simply gone, so nothing can join it late.
func TestClaimTracker_WindowClosesLateEventUnclaimed(t *testing.T) {
	tr := newClaimTracker()
	w := tr.startWindow("portscan", "192.0.2.10", "the-marker")
	tr.resolveWindow(w) // window closes with zero candidates

	tr.observe("late-ev", "portscan", "192.0.2.10") // arrives after the window closed

	if tr.pending("late-ev") {
		t.Fatal("pending(late-ev) = true for an event observed after its window resolved, want false")
	}
	if _, ok := tr.marker("late-ev"); ok {
		t.Fatal("a late-arriving event was claimed, want unclaimed")
	}
}

// TestClaimTracker_NonMatchingCandidateIgnored: a candidate whose
// service or address doesn't match the window is never recorded against
// it -- an unrelated event arriving during the same window must not be
// able to trip the two-or-more case for a probe it has nothing to do
// with.
func TestClaimTracker_NonMatchingCandidateIgnored(t *testing.T) {
	tr := newClaimTracker()
	w := tr.startWindow("portscan", "192.0.2.10", "the-marker")

	tr.observe("ev-wrong-service", "ntp", "192.0.2.10")
	tr.observe("ev-wrong-address", "portscan", "203.0.113.5")
	tr.observe("ev-match", "portscan", "192.0.2.10")
	tr.resolveWindow(w)

	marker, ok := tr.marker("ev-match")
	if !ok || marker != "the-marker" {
		t.Fatalf("marker(ev-match) = (%q, %v), want (\"the-marker\", true)", marker, ok)
	}
	for _, id := range []string{"ev-wrong-service", "ev-wrong-address"} {
		if _, ok := tr.marker(id); ok {
			t.Errorf("marker(%s) claimed, want unclaimed (does not match the window)", id)
		}
	}
}

// TestClaimTracker_Forget proves forget removes a claimed marker so the
// map does not grow forever across a fleet's lifetime of daily
// self-tests, and is a harmless no-op for an id that was never claimed.
func TestClaimTracker_Forget(t *testing.T) {
	tr := newClaimTracker()
	w := tr.startWindow("portscan", "192.0.2.10", "the-marker")
	tr.observe("ev-1", "portscan", "192.0.2.10")
	tr.resolveWindow(w)

	tr.forget("ev-1")
	if _, ok := tr.marker("ev-1"); ok {
		t.Fatal("marker(ev-1) still found after forget")
	}
	tr.forget("never-claimed") // must not panic
}

// TestClaimTracker_Active reports whether any window is currently open
// -- the short-circuit intake.go's observeClaim relies on to skip
// decoding an event's fields outside a self-test's brief window.
func TestClaimTracker_Active(t *testing.T) {
	tr := newClaimTracker()
	if tr.active() {
		t.Fatal("active() = true on a fresh tracker, want false")
	}
	w := tr.startWindow("portscan", "192.0.2.10", "the-marker")
	if !tr.active() {
		t.Fatal("active() = false with one open window, want true")
	}
	tr.resolveWindow(w)
	if tr.active() {
		t.Fatal("active() = true after the only window resolved, want false")
	}
}

// TestRunSelfTestWindowOpensBeforeSweep proves runSelfTest opens an
// attributed target's claim window before the sweep that produces its
// event, not after it (the defect MR !60's pipeline 1524 showed: the
// portscan detector fires mid-sweep, and a window opened once the sweep
// returned found nothing to claim). The ssh target here dials a local
// listener that accepts and never speaks, so the sweep is held open
// until the test releases it -- and the test only releases it once the
// portscan window is already active and its candidate observed. Under
// the old ordering active() could not become true until the sweep
// returned, which this test never allows before observing, so the
// deadline below fails it rather than the assertion at the end.
func TestRunSelfTestWindowOpensBeforeSweep(t *testing.T) {
	origWindow := selfTestClaimWindow
	selfTestClaimWindow = 50 * time.Millisecond
	defer func() { selfTestClaimWindow = origWindow }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	held := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			held <- c // never written to: the ssh probe blocks reading the banner
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	in, _ := newTestIntake(t, queue.Config{})
	params := fmt.Sprintf(`{"run_id":"r1","address":"127.0.0.1","targets":[{"service":"ssh","dest_port":%d,"marker":"m-ssh"},{"service":"portscan","dest_port":0,"marker":"m-portscan"}]}`, port)
	finished := make(chan error, 1)
	go func() {
		finished <- runSelfTest(context.Background(), in, &client.Command{ID: "cmd-1", Kind: kindSelfTest, Params: []byte(params)})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for !in.claims.active() {
		if time.Now().After(deadline) {
			t.Fatal("no claim window opened while the sweep was still running")
		}
		time.Sleep(time.Millisecond)
	}
	in.claims.observe("ev-1", "portscan", "127.0.0.1")

	// Release the sweep only now: the window was open before it ended.
	select {
	case c := <-held:
		_ = c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("the ssh probe never dialed the held listener")
	}

	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("runSelfTest = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runSelfTest did not return after the sweep was released")
	}

	marker, ok := in.claims.marker("ev-1")
	if !ok || marker != "m-portscan" {
		t.Fatalf("marker(ev-1) = (%q, %v), want (\"m-portscan\", true)", marker, ok)
	}
}
