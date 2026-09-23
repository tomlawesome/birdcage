package main

import (
	"testing"

	"github.com/tomlawesome/birdcage/internal/agent/queue"
)

// TestCurrentSelfReportMapsEveryLiveField proves currentSelfReport is a
// faithful mapping from the real Intake/Queue/ledger/tailer state to the
// wire SelfReport, not a check of one hard-coded field: every field this
// test can drive away from its Go zero value is driven to a distinct
// value, so a field left unmapped, or mapped from the wrong source,
// shows up as a mismatch rather than passing by coincidence.
func TestCurrentSelfReportMapsEveryLiveField(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 1, MaxBytes: 1 << 20})

	// A one-event queue: each push after the first evicts the previous
	// one, so three pushes leave Dropped=2 and one event still queued.
	in.Queue.Push(queue.Event{ID: "aaaa", Payload: []byte(`{"a":1}`)})
	in.Queue.Push(queue.Event{ID: "bbbb", Payload: []byte(`{"b":1}`)})
	in.Queue.Push(queue.Event{ID: "cccc", Payload: []byte(`{"c":1}`)})
	in.Queue.Reject("cccc") // Rejected=1, and empties the queue: QueueDepth=0.

	// Collisions must be the sum Intake.Collisions documents: the live
	// ledger's own count (1, from appending the same id twice) plus
	// whatever a prior, discarded ledger already contributed (3).
	in.Ledger().Append("dup-id", queue.Position{})
	in.Ledger().Append("dup-id", queue.Position{})
	in.collisionsBase.Add(3)

	in.setLastEventID("last-event-id")

	report := currentSelfReport("v9.9.9", in, nil)

	if report.AgentVersion != "v9.9.9" {
		t.Errorf("AgentVersion = %q, want %q -- the version passed to currentSelfReport must pass through unchanged", report.AgentVersion, "v9.9.9")
	}
	if report.LastEventID != "last-event-id" {
		t.Errorf("LastEventID = %q, want %q", report.LastEventID, "last-event-id")
	}
	if report.QueueDepth != in.Queue.Depth() {
		t.Errorf("QueueDepth = %d, want %d (in.Queue.Depth())", report.QueueDepth, in.Queue.Depth())
	}
	if report.QueueDepth != 0 {
		t.Errorf("QueueDepth = %d, want 0 (the one queued event was rejected)", report.QueueDepth)
	}
	if report.Dropped != int64(in.Queue.Dropped()) {
		t.Errorf("Dropped = %d, want %d (int64(in.Queue.Dropped()))", report.Dropped, in.Queue.Dropped())
	}
	if report.Dropped != 2 {
		t.Errorf("Dropped = %d, want 2 (two evictions in a one-event queue)", report.Dropped)
	}
	if report.Rejected != int64(in.Queue.RejectedCount()) {
		t.Errorf("Rejected = %d, want %d (int64(in.Queue.RejectedCount()))", report.Rejected, in.Queue.RejectedCount())
	}
	if report.Rejected != 1 {
		t.Errorf("Rejected = %d, want 1", report.Rejected)
	}
	if report.EventIDCollisions != int64(in.Collisions()) {
		t.Errorf("EventIDCollisions = %d, want %d (int64(in.Collisions()))", report.EventIDCollisions, in.Collisions())
	}
	if report.EventIDCollisions != 4 {
		t.Errorf("EventIDCollisions = %d, want 4 (1 live collision + 3 carried over)", report.EventIDCollisions)
	}
	if !report.LogReadOK {
		t.Error("LogReadOK = false, want true (the tailer's own default before a Follow session ever runs)")
	}
	if !report.PositionFound {
		t.Error("PositionFound = false, want true (the tailer's own default before a Follow session ever runs)")
	}
}
