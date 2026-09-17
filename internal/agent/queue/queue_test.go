package queue

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// fakeID returns a syntactically plausible 64-char lowercase hex event
// id for test fixtures. This package never computes real ids (a peer
// package does); tests only need distinct, id-shaped strings.
func fakeID(n int) string {
	return fmt.Sprintf("%064x", n+1)
}

// testMaxBytes is a byte cap generous enough that none of the
// count-cap-focused tests below (small or empty Payloads, at most a few
// thousand events) ever trips it, so their behavior is unchanged by
// gap 4's addition of a second cap. Tests that exercise the byte cap
// itself set their own tight MaxBytes instead.
const testMaxBytes = 1 << 30 // 1 GiB

func TestPush_DedupByID(t *testing.T) {
	q := NewMemQueue(Config{MaxEvents: 10, MaxBytes: testMaxBytes})
	id := fakeID(1)

	if added := q.Push(Event{ID: id, Payload: []byte("first")}); !added {
		t.Fatalf("first push of a new id returned false")
	}
	// Same id arriving a second time -- the webhook road and the log
	// road both delivering the same OpenCanary hit is exactly this case
	// (#48: "the same hit arriving by both roads ... resolves to one
	// stored alert").
	if added := q.Push(Event{ID: id, Payload: []byte("second")}); added {
		t.Fatalf("duplicate push of an existing id returned true")
	}
	if depth := q.Depth(); depth != 1 {
		t.Fatalf("depth = %d, want 1", depth)
	}
}

func TestPush_CapDropsOldest(t *testing.T) {
	const capacity = 3
	q := NewMemQueue(Config{MaxEvents: capacity, MaxBytes: testMaxBytes})

	for i := 0; i < 5; i++ {
		q.Push(Event{ID: fakeID(i)})
	}

	if depth := q.Depth(); depth != capacity {
		t.Fatalf("depth = %d, want %d", depth, capacity)
	}
	if dropped := q.Dropped(); dropped != 2 {
		t.Fatalf("dropped = %d, want 2", dropped)
	}

	// The two oldest (0, 1) should be gone; the three newest (2, 3, 4)
	// should remain, oldest-first.
	got := q.Peek(capacity)
	want := []string{fakeID(2), fakeID(3), fakeID(4)}
	if len(got) != len(want) {
		t.Fatalf("peeked %d events, want %d", len(got), len(want))
	}
	for i, e := range got {
		if e.ID != want[i] {
			t.Errorf("peek[%d].ID = %s, want %s", i, e.ID, want[i])
		}
	}
}

func TestAck_RemovesEvent(t *testing.T) {
	q := NewMemQueue(Config{MaxEvents: 10, MaxBytes: testMaxBytes})
	id := fakeID(1)
	q.Push(Event{ID: id})

	q.Ack(id)
	if depth := q.Depth(); depth != 0 {
		t.Fatalf("depth after Ack = %d, want 0", depth)
	}

	// Acking again, or acking an id that was never queued, must be a
	// harmless no-op -- birdcage's ack and the agent's own retry cadence
	// can race, and this must never panic or corrupt queue state.
	q.Ack(id)
	q.Ack(fakeID(999))
}

func TestReject_CountsAndRemoves(t *testing.T) {
	q := NewMemQueue(Config{MaxEvents: 10, MaxBytes: testMaxBytes})
	id := fakeID(1)
	q.Push(Event{ID: id})

	q.Reject(id)
	if depth := q.Depth(); depth != 0 {
		t.Fatalf("depth after Reject = %d, want 0", depth)
	}
	if rejected := q.RejectedCount(); rejected != 1 {
		t.Fatalf("rejected = %d, want 1", rejected)
	}

	// Rejecting an id already gone (already acked, already rejected, or
	// never queued) must not double-count -- #48's "0 dropped silently"
	// accounting depends on each drop being counted exactly once.
	q.Reject(id)
	if rejected := q.RejectedCount(); rejected != 1 {
		t.Fatalf("rejected after re-reject = %d, want 1 (must not double count)", rejected)
	}
}

func TestPeek_DoesNotRemove(t *testing.T) {
	q := NewMemQueue(Config{MaxEvents: 10, MaxBytes: testMaxBytes})
	q.Push(Event{ID: fakeID(1)})

	q.Peek(10)
	q.Peek(10)
	if depth := q.Depth(); depth != 1 {
		t.Fatalf("depth after repeated Peek = %d, want 1 (Peek must not remove)", depth)
	}
}

func TestPeek_LimitsAndOrders(t *testing.T) {
	q := NewMemQueue(Config{MaxEvents: 10, MaxBytes: testMaxBytes})
	for i := 0; i < 5; i++ {
		q.Push(Event{ID: fakeID(i)})
	}

	got := q.Peek(2)
	if len(got) != 2 {
		t.Fatalf("peeked %d events, want 2", len(got))
	}
	if got[0].ID != fakeID(0) || got[1].ID != fakeID(1) {
		t.Fatalf("peek order = %v, want oldest-first [%s %s]", got, fakeID(0), fakeID(1))
	}
}

// TestConcurrentPushAndAck exercises the package's stated concurrency
// contract -- one producer goroutine, one sender goroutine -- under
// -race, pushing and acknowledging events interleaved. It also calls
// Depth and RejectedCount concurrently from a third goroutine, since the
// package doc allows that from e.g. a heartbeat builder.
func TestConcurrentPushAndAck(t *testing.T) {
	const n = 5000
	// Capacity >= n so no drop-oldest eviction competes with acking in
	// this test; cap behaviour has its own dedicated test above.
	q := NewMemQueue(Config{MaxEvents: n, MaxBytes: testMaxBytes})

	ids := make([]string, n)
	for i := range ids {
		ids[i] = fakeID(i)
	}

	var wg sync.WaitGroup
	wg.Add(3)

	var producerDone atomic.Bool
	go func() { // producer
		defer wg.Done()
		for _, id := range ids {
			q.Push(Event{ID: id, Payload: []byte("x")})
		}
		producerDone.Store(true)
	}()

	var acked atomic.Int64
	go func() { // sender
		defer wg.Done()
		for {
			batch := q.Peek(64)
			for _, e := range batch {
				q.Ack(e.ID)
				acked.Add(1)
			}
			if len(batch) == 0 && producerDone.Load() && q.Depth() == 0 {
				return
			}
		}
	}()

	go func() { // concurrent readers, as a heartbeat builder would call
		defer wg.Done()
		for !producerDone.Load() {
			_ = q.Depth()
			_ = q.RejectedCount()
			_ = q.Dropped()
		}
	}()

	wg.Wait()

	if got := acked.Load(); got != n {
		t.Fatalf("acked %d events, want %d", got, n)
	}
	if depth := q.Depth(); depth != 0 {
		t.Fatalf("final depth = %d, want 0", depth)
	}
}

// TestConcurrentPushAndReject is the same shape as
// TestConcurrentPushAndAck but exercises Reject, since #48 requires
// permanently-rejected events be dropped and counted rather than
// retried, and that bookkeeping must hold under concurrent access too.
func TestConcurrentPushAndReject(t *testing.T) {
	const n = 3000
	q := NewMemQueue(Config{MaxEvents: n, MaxBytes: testMaxBytes})

	var wg sync.WaitGroup
	wg.Add(2)

	var producerDone atomic.Bool
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			q.Push(Event{ID: fakeID(i)})
		}
		producerDone.Store(true)
	}()

	go func() {
		defer wg.Done()
		for {
			batch := q.Peek(32)
			for _, e := range batch {
				q.Reject(e.ID)
			}
			if len(batch) == 0 && producerDone.Load() && q.Depth() == 0 {
				return
			}
		}
	}()

	wg.Wait()

	if rejected := q.RejectedCount(); rejected != n {
		t.Fatalf("rejected = %d, want %d", rejected, n)
	}
	if depth := q.Depth(); depth != 0 {
		t.Fatalf("final depth = %d, want 0", depth)
	}
}

// TestPush_ByteCapEvictsOldest is gap 4's required case: a byte cap
// tight enough to bind before the (generous) count cap must still evict
// oldest-first and count the eviction, the same as the count cap does.
func TestPush_ByteCapEvictsOldest(t *testing.T) {
	q := NewMemQueue(Config{MaxEvents: 100, MaxBytes: 30})

	for i := 0; i < 4; i++ {
		q.Push(Event{ID: fakeID(i), Payload: make([]byte, 10)}) // 10 bytes each
	}

	// 4 * 10 = 40 bytes > the 30-byte cap, so the byte cap -- not the
	// count cap, which is nowhere near 100 -- must have evicted at least
	// the oldest event.
	if depth := q.Depth(); depth > 3 {
		t.Fatalf("depth = %d, want <= 3 (byte cap must evict before the count cap would ever bind)", depth)
	}
	if dropped := q.Dropped(); dropped == 0 {
		t.Fatal("dropped = 0, want at least 1 (byte-cap eviction must be counted)")
	}
	got := q.Peek(100)
	if len(got) == 0 || got[len(got)-1].ID != fakeID(3) {
		t.Fatalf("newest event missing after byte-cap eviction; peek = %v", got)
	}
	if got[0].ID == fakeID(0) {
		t.Fatal("oldest event (fakeID(0)) still present, want it evicted first")
	}
}

// TestPush_SingleEventLargerThanByteCapIsAdmittedAlone is gap 4's
// required sanity case for an event whose own Payload already exceeds
// MaxBytes: there is nothing left to evict once the queue is empty, so
// this package -- which never judges event content -- admits it alone
// rather than refusing it, panicking, or looping forever. The very next
// Push must still evict it like any other oldest entry, so it never
// grows the queue past one such event's worth of memory.
func TestPush_SingleEventLargerThanByteCapIsAdmittedAlone(t *testing.T) {
	q := NewMemQueue(Config{MaxEvents: 100, MaxBytes: 100})

	big := Event{ID: fakeID(0), Payload: make([]byte, 1000)}
	if added := q.Push(big); !added {
		t.Fatal("Push of an oversized single event returned false, want true (admitted alone)")
	}
	if depth := q.Depth(); depth != 1 {
		t.Fatalf("depth after oversized push = %d, want 1", depth)
	}

	// A normal-sized push afterward must evict the oversized one rather
	// than being refused or leaving the queue over the byte cap forever.
	if added := q.Push(Event{ID: fakeID(1), Payload: make([]byte, 10)}); !added {
		t.Fatal("Push after an oversized event returned false")
	}
	got := q.Peek(100)
	if len(got) != 1 || got[0].ID != fakeID(1) {
		t.Fatalf("queue after second push = %v, want only fakeID(1) (the oversized event evicted)", got)
	}
	if dropped := q.Dropped(); dropped != 1 {
		t.Fatalf("dropped = %d, want 1 (the evicted oversized event)", dropped)
	}
}

// TestPush_AckAndRejectRestoreByteBudget proves the byte accounting
// Ack/Reject maintain (via removeLocked) actually frees budget for later
// pushes, not just that Depth drops -- a leak here would silently shrink
// the effective byte cap over the agent's lifetime.
func TestPush_AckAndRejectRestoreByteBudget(t *testing.T) {
	q := NewMemQueue(Config{MaxEvents: 100, MaxBytes: 20})

	q.Push(Event{ID: fakeID(0), Payload: make([]byte, 20)})
	q.Ack(fakeID(0))

	// With the first event's bytes released, a second same-sized event
	// must fit without needing to evict anything (there is nothing left
	// to evict).
	if added := q.Push(Event{ID: fakeID(1), Payload: make([]byte, 20)}); !added {
		t.Fatal("Push after Ack returned false")
	}
	if depth := q.Depth(); depth != 1 {
		t.Fatalf("depth = %d, want 1", depth)
	}
	if dropped := q.Dropped(); dropped != 0 {
		t.Fatalf("dropped = %d, want 0 (Ack should have freed the byte budget already)", dropped)
	}
}
