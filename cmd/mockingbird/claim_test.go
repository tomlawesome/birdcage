package main

import (
	"testing"
	"time"
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

// TestClaimTracker_OpenBlocksUntilDoneCloses proves open (the shape
// command.go's runSelfTest actually calls) is the blocking
// startWindow+resolveWindow pair above -- ended early by done rather
// than by waiting out the real selfTestClaimWindow, so this test costs
// no wall-clock time regardless of that var's value.
func TestClaimTracker_OpenBlocksUntilDoneCloses(t *testing.T) {
	origWindow := selfTestClaimWindow
	selfTestClaimWindow = time.Hour // would hang the test if done did not end it first
	defer func() { selfTestClaimWindow = origWindow }()

	tr := newClaimTracker()
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		tr.open(done, "portscan", "192.0.2.10", "the-marker")
		close(finished)
	}()

	// Give open's own startWindow a chance to run before observing --
	// deterministic because pending() reads the tracker's own state, not
	// a timer: this loop only ever ends once startWindow has actually
	// registered the window (or the test's own deadline below fires
	// first, which fails loudly rather than hanging).
	deadline := time.Now().Add(2 * time.Second)
	for !tr.active() {
		if time.Now().After(deadline) {
			t.Fatal("open never registered its window")
		}
	}

	tr.observe("ev-1", "portscan", "192.0.2.10")
	close(done)

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("open did not return after done closed")
	}

	marker, ok := tr.marker("ev-1")
	if !ok || marker != "the-marker" {
		t.Fatalf("marker(ev-1) = (%q, %v), want (\"the-marker\", true)", marker, ok)
	}
}
