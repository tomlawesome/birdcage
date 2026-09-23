package main

import (
	"sync"
	"time"
)

// selfTestClaimWindow is how long the agent watches its own intake for
// the single candidate event an attributed-grade probe (ntp, portscan)
// produced, before giving up and letting every candidate go out
// unclaimed (#46 slice 3, note 19897's "attributed" grade -- see
// internal/agent/probe/attribution.go's own doc comment for why these
// two services carry no marker of their own). var, not const, so a test
// can shrink it -- command.go's commandPollInterval is this file's own
// precedent for the same reason.
var selfTestClaimWindow = 5 * time.Second

// claimWindow is one attributed probe's bounded watch: the marker to
// attach if exactly one candidate turns up, the facts a candidate must
// match (note 19897: "same service, source_ip equal to the canary's own
// address"), and the candidate ids seen so far, in arrival order.
type claimWindow struct {
	service string
	address string // the canary's own address the probe dialed -- selftest.Params.Address
	marker  string

	candidates []string // queue.Event ids
}

// claimTracker correlates attributed probes with the events they
// produce, entirely in memory -- an agent restart loses every open
// window, which is the safe direction (note 19897: "An agent restart
// mid-window loses the claim state -- events go out unclaimed").
//
// observe is called by every intake road that could carry an attributed
// service's event, before that event is handed to the sender, so a
// candidate is recorded before the sender's next Peek can possibly reach
// it. open registers one window and blocks the caller until
// selfTestClaimWindow elapses (or ctx ends first), deciding that
// window's exactly-one rule (note 19897: exactly one candidate claims
// the event; zero or two-or-more leaves every candidate to go out
// unclaimed, real) before returning.
//
// pending and marker are the sender's own two questions for one queued
// event id: is its claim still being decided (hold it back this round),
// and if decided, what marker (if any) does it carry.
type claimTracker struct {
	mu      sync.Mutex
	windows []*claimWindow   // still open, undecided
	claimed map[string]string // event id -> marker, decided windows only
}

// newClaimTracker returns an empty tracker.
func newClaimTracker() *claimTracker {
	return &claimTracker{claimed: make(map[string]string)}
}

// active reports whether any window is currently open -- the cheap
// short-circuit an intake road checks before paying for a JSON decode on
// every event, since a self-test's attributed window is open only for a
// few seconds, at most twice a day.
func (t *claimTracker) active() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.windows) > 0
}

// open registers one window for (service, address, marker) and blocks
// until selfTestClaimWindow elapses or done closes, then resolves it --
// the shape command.go's runSelfTest actually calls. Split into
// startWindow and resolveWindow below so a test can drive the exact same
// decision deterministically, without depending on selfTestClaimWindow's
// real wall-clock duration or a goroutine race between registration and
// the test's own observe calls.
func (t *claimTracker) open(done <-chan struct{}, service, address, marker string) {
	w := t.startWindow(service, address, marker)
	select {
	case <-time.After(selfTestClaimWindow):
	case <-done:
	}
	t.resolveWindow(w)
}

// startWindow registers one window and returns it immediately, before
// any candidate can possibly have arrived -- the caller decides when to
// stop watching by calling resolveWindow.
func (t *claimTracker) startWindow(service, address, marker string) *claimWindow {
	w := &claimWindow{service: service, address: address, marker: marker}
	t.mu.Lock()
	t.windows = append(t.windows, w)
	t.mu.Unlock()
	return w
}

// resolveWindow decides w's exactly-one rule (note 19897) and removes it
// from t.windows: exactly one candidate claims the event (recorded in
// t.claimed); anything else -- zero, or two-or-more -- decides nothing,
// and every candidate is simply no longer pending once this returns, so
// the sender's next Peek sends it as an ordinary event. A candidate
// observed after this call (a late event, arriving once the window has
// already closed) can never join w -- see observe's own doc comment --
// so it stays unclaimed too, the safe direction.
func (t *claimTracker) resolveWindow(w *claimWindow) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, cur := range t.windows {
		if cur == w {
			t.windows = append(t.windows[:i], t.windows[i+1:]...)
			break
		}
	}
	if len(w.candidates) == 1 {
		t.claimed[w.candidates[0]] = w.marker
	}
}

// observe records id as a candidate of every currently open window whose
// service and address it matches (note 19897's own candidate rule --
// arrival is implicit: observe is only ever called for an event just
// now handed to the intake road, so "inside the window" is exactly
// "while that window is still in t.windows"). A window resolveWindow has
// already removed is not in t.windows any more, so a late-arriving
// event -- one whose observe call lands after the window closed -- finds
// no window to join and is never claimed, the safe direction.
func (t *claimTracker) observe(id, service, sourceIP string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, w := range t.windows {
		if w.service == service && w.address == sourceIP {
			w.candidates = append(w.candidates, id)
		}
	}
}

// pending reports whether id belongs to a still-open, undecided window
// -- the sender's cue to leave it queued for another round rather than
// send it unclaimed while its claim is still being decided.
func (t *claimTracker) pending(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, w := range t.windows {
		for _, c := range w.candidates {
			if c == id {
				return true
			}
		}
	}
	return false
}

// marker returns the marker claimed for id, if any.
func (t *claimTracker) marker(id string) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	m, ok := t.claimed[id]
	return m, ok
}

// forget drops id's claim record, if any -- called once an id reaches a
// terminal resolution (Ack or Reject; sender.go's applyVerdicts), so
// t.claimed does not grow forever across a fleet's lifetime of daily
// self-tests. A no-op for an id that was never claimed.
func (t *claimTracker) forget(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.claimed, id)
}
