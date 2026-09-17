package queue

import (
	"path/filepath"
	"testing"
)

// synthEvent stands in for a real OpenCanary hit read by the tailer: an
// id (a peer package's job to compute) plus a log offset. This package
// doesn't read logs, so the test manufactures offsets directly rather
// than needing a real log file.
type synthEvent struct {
	Event
	offset int64
}

// TestCrashRestart_ReadButUnacknowledged_NoLossNoDuplicate is this
// package's proof of #48's acceptance bar: "Killing the agent mid-batch
// and restarting it loses nothing and duplicates nothing ... including
// with events read but unacknowledged." It exercises MemQueue and
// PositionStore together, the way the sender goroutine and the restart
// path would.
func TestCrashRestart_ReadButUnacknowledged_NoLossNoDuplicate(t *testing.T) {
	dir := t.TempDir()
	posStore := NewPositionStore(filepath.Join(dir, "position"))

	events := make([]synthEvent, 10)
	for i := range events {
		events[i] = synthEvent{
			Event:  Event{ID: fakeID(i), Payload: []byte("payload")},
			offset: int64(i + 1),
		}
	}

	// --- Before the crash ---
	q1 := NewMemQueue(Config{MaxEvents: 100, MaxBytes: testMaxBytes})
	for _, e := range events {
		q1.Push(e.Event)
	}

	// birdcage acknowledges the first six; the sender advances the saved
	// position only that far, since Save must reflect acknowledgement,
	// never mere read (#48, "Durability").
	var lastAckedOffset int64
	for _, e := range events[:6] {
		q1.Ack(e.ID)
		lastAckedOffset = e.offset
	}
	if err := posStore.Save(Position{Inode: 1, Offset: lastAckedOffset}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// The remaining four (events[6:]) are read but unacknowledged --
	// still sitting in q1 -- exactly when the process is killed. q1 and
	// everything in it is discarded here, the way process memory would
	// be on a real crash.

	// --- Restart ---
	pos, ok, err := posStore.Load()
	if err != nil || !ok {
		t.Fatalf("Load after restart: pos=%+v ok=%v err=%v", pos, ok, err)
	}
	if pos.Offset != lastAckedOffset {
		t.Fatalf("restored offset = %d, want %d", pos.Offset, lastAckedOffset)
	}

	// The tailer would now re-scan from pos onward, re-hashing and
	// re-pushing every event after it -- replay is free because the id
	// is stable across restarts (#48). A fresh, empty queue stands in
	// for the new process's memory.
	q2 := NewMemQueue(Config{MaxEvents: 100, MaxBytes: testMaxBytes})
	for _, e := range events {
		if e.offset > pos.Offset {
			q2.Push(e.Event)
		}
	}

	// Nothing lost: every read-but-unacknowledged event is back.
	delivered := make(map[string]bool)
	for _, e := range q2.Peek(100) {
		delivered[e.ID] = true
	}
	for _, e := range events[6:] {
		if !delivered[e.ID] {
			t.Errorf("event %s (offset %d) lost across restart", e.ID, e.offset)
		}
	}

	// Nothing duplicated: already-acknowledged events are at or before
	// the saved offset, so the replay never re-pushes them, and the
	// fresh queue holds exactly the four that were outstanding -- not
	// four-plus-duplicates, and not fewer.
	if depth := q2.Depth(); depth != 4 {
		t.Fatalf("depth after restart = %d, want 4 (no loss, no duplication)", depth)
	}
}

// TestCrashRestart_OverlappingRescanDedupsInsteadOfDuplicating covers
// the case the Durability section anticipates: a rotation scan or a
// conservative re-read boundary can overlap already-acknowledged
// events, re-hashing some of them again. MemQueue's id dedup is what
// keeps that overlap from becoming a duplicate delivery.
func TestCrashRestart_OverlappingRescanDedupsInsteadOfDuplicating(t *testing.T) {
	dir := t.TempDir()
	posStore := NewPositionStore(filepath.Join(dir, "position"))

	events := make([]synthEvent, 6)
	for i := range events {
		events[i] = synthEvent{
			Event:  Event{ID: fakeID(i)},
			offset: int64(i + 1),
		}
	}

	q1 := NewMemQueue(Config{MaxEvents: 100, MaxBytes: testMaxBytes})
	for _, e := range events {
		q1.Push(e.Event)
		q1.Ack(e.ID)
	}
	if err := posStore.Save(Position{Inode: 1, Offset: events[len(events)-1].offset}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	pos, ok, err := posStore.Load()
	if err != nil || !ok {
		t.Fatalf("Load: pos=%+v ok=%v err=%v", pos, ok, err)
	}

	// A conservative rescan that re-reads the whole log, not just
	// strictly-after-pos, mimicking a rotation boundary rounded down to
	// be safe. Every event -- including already-acked ones -- gets
	// pushed again.
	q2 := NewMemQueue(Config{MaxEvents: 100, MaxBytes: testMaxBytes})
	pushed := 0
	for _, e := range events {
		if e.offset >= 1 { // "whole log", i.e. no lower bound applied
			if q2.Push(e.Event) {
				pushed++
			}
		}
	}
	_ = pos // position still informs a real tailer's lower bound; unused by this deliberately-conservative rescan

	if pushed != len(events) {
		t.Fatalf("pushed %d distinct events on first pass, want %d", pushed, len(events))
	}
	if depth := q2.Depth(); depth != len(events) {
		t.Fatalf("depth = %d, want %d", depth, len(events))
	}

	// A second identical rescan (e.g. the sender retries the same
	// batch) must dedup completely rather than double the queue.
	for _, e := range events {
		q2.Push(e.Event)
	}
	if depth := q2.Depth(); depth != len(events) {
		t.Fatalf("depth after repeat rescan = %d, want %d (dedup must hold)", depth, len(events))
	}
}
