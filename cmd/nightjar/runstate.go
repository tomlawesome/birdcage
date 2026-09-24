// runstate.go tracks the ordered scan (if any) currently in flight, so
// the ordinary heartbeat loop (heartbeat.go) can satisfy the rest of
// ADR-0012 decision 9: "[Nightjar] repeats the current stage on every
// ordinary tick until the run is answered." newStageReporter
// (command.go) updates this on every stage change; runScanOnce
// (scanner.go) clears it once the run's snapshot has been posted --
// answered, from Nightjar's own point of view, whatever birdcage's
// handler goes on to decide about the run itself.
//
// Not persisted: a restart mid-run loses this in-memory record, but
// loses nothing birdcage cannot recover on its own -- the run stays open
// server side and the 30-minute pending-retry guard (ADR-0012 decision
// 3) mints a fresh order if this one goes quiet.
package main

import "sync"

type currentRunTracker struct {
	mu    sync.Mutex
	runID string
	stage string
}

func newCurrentRunTracker() *currentRunTracker {
	return &currentRunTracker{}
}

// set records runID as now at stage.
func (t *currentRunTracker) set(runID, stage string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.runID = runID
	t.stage = stage
}

// clear drops any in-flight run -- called once its snapshot is posted.
func (t *currentRunTracker) clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.runID = ""
	t.stage = ""
}

// get returns the current run id and stage, both empty when no ordered
// scan is in flight.
func (t *currentRunTracker) get() (runID, stage string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.runID, t.stage
}
