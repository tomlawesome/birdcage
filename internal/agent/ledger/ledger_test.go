package ledger

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tomlawesome/birdcage/internal/agent/queue"
)

// fakeID returns a syntactically plausible 64-char lowercase hex event id
// for test fixtures, the same shape internal/agent/queue's tests use.
// This package never computes real ids (a peer package does); tests only
// need distinct, id-shaped strings.
func fakeID(n int) string {
	return fmt.Sprintf("%064x", n+1)
}

// pos builds a test Position at a distinct, easily-compared offset. The
// inode is fixed: these tests are about ledger bookkeeping, not rotation
// detection, which queue.Position's own tests already cover.
func pos(offset int64) queue.Position {
	return queue.Position{Inode: 1, Offset: offset}
}

func TestAdvance_InOrderResolutionAdvancesOneAtATime(t *testing.T) {
	l := New(DefaultCollisionWindow)
	ids := []string{fakeID(0), fakeID(1), fakeID(2)}
	for i, id := range ids {
		l.Append(id, pos(int64(i+1)))
	}

	for i, id := range ids {
		l.Resolve(id, Stored)
		p, ok := l.Advance()
		if !ok {
			t.Fatalf("entry %d: Advance ok = false, want true", i)
		}
		if want := pos(int64(i + 1)); p != want {
			t.Fatalf("entry %d: frontier = %+v, want %+v", i, p, want)
		}
	}
	if depth := l.Len(); depth != 0 {
		t.Fatalf("Len after resolving everything in order = %d, want 0", depth)
	}
}

// TestAdvance_OutOfOrderResolutionStallsBehindTheGap is #48 decision 3's
// central guarantee: "a resolved entry sitting behind an unresolved one
// must NOT advance the frontier." Birdcage may acknowledge a batch out
// of log order; resolving entry 3 while entry 2 is still open must never
// let the frontier skip past entry 1's position, and resolving 2
// afterward must bring both 2 and 3 in behind it in one jump.
func TestAdvance_OutOfOrderResolutionStallsBehindTheGap(t *testing.T) {
	l := New(DefaultCollisionWindow)
	id1, id2, id3 := fakeID(1), fakeID(2), fakeID(3)
	l.Append(id1, pos(1))
	l.Append(id2, pos(2))
	l.Append(id3, pos(3))

	// Resolve 1 and 3, leaving 2 open -- birdcage acknowledging out of
	// log order.
	l.Resolve(id1, Stored)
	l.Resolve(id3, Stored)

	p, ok := l.Advance()
	if !ok || p != pos(1) {
		t.Fatalf("frontier after resolving 1 and 3 (2 still open) = (%+v, %v), want (%+v, true)", p, ok, pos(1))
	}
	// Calling Advance again must not somehow find more to give: entry 2
	// is still the unresolved head.
	if _, ok := l.Advance(); ok {
		t.Fatal("second Advance with entry 2 still unresolved returned ok = true, want false")
	}
	if depth := l.Len(); depth != 2 {
		t.Fatalf("Len with 2 and 3 still held = %d, want 2", depth)
	}

	// Now resolve 2: both 2 and 3 become an unbroken resolved prefix and
	// must be consumed in one Advance, landing the frontier on 3.
	l.Resolve(id2, Stored)
	p, ok = l.Advance()
	if !ok || p != pos(3) {
		t.Fatalf("frontier after resolving 2 = (%+v, %v), want (%+v, true)", p, ok, pos(3))
	}
	if depth := l.Len(); depth != 0 {
		t.Fatalf("Len after the jump = %d, want 0", depth)
	}
}

func TestResolve_RejectedAdvancesLikeStored(t *testing.T) {
	l := New(DefaultCollisionWindow)
	id := fakeID(0)
	l.Append(id, pos(1))

	l.Resolve(id, Rejected)
	p, ok := l.Advance()
	if !ok || p != pos(1) {
		t.Fatalf("frontier after Rejected = (%+v, %v), want (%+v, true)", p, ok, pos(1))
	}
}

// TestResolve_UnknownIDIsIgnored covers both a verdict for an id that
// was never appended at all (the webhook-road ack case: webhook events
// have no ledger entry) and, separately, an id that is already fully
// resolved -- neither may be an error or change any observable state.
func TestResolve_UnknownIDIsIgnored(t *testing.T) {
	l := New(DefaultCollisionWindow)
	knownID := fakeID(0)
	l.Append(knownID, pos(1))

	// Never appended at all.
	l.Resolve(fakeID(999), Stored)
	if depth := l.Len(); depth != 1 {
		t.Fatalf("Len after resolving an unknown id = %d, want 1 (unchanged)", depth)
	}
	if _, ok := l.Advance(); ok {
		t.Fatal("Advance ok = true after resolving only an unknown id, want false")
	}

	// Already resolved: a duplicate verdict (e.g. a retried ack) must be
	// a harmless no-op, mirroring MemQueue.Ack's own idempotence.
	l.Resolve(knownID, Stored)
	l.Resolve(knownID, Stored)
	p, ok := l.Advance()
	if !ok || p != pos(1) {
		t.Fatalf("frontier after a duplicate resolve = (%+v, %v), want (%+v, true)", p, ok, pos(1))
	}
}

// TestAdvance_EvictedEntryStallsIndefinitely is #48 decision 2's other
// half: an event the queue evicted unsent never gets a verdict, so its
// ledger entry never resolves, and that must stall the frontier forever
// -- not just once -- no matter how much resolved work piles up behind
// it. That stall is what makes the next tailer catch-up re-read the
// evicted event instead of the agent silently moving on without it.
func TestAdvance_EvictedEntryStallsIndefinitely(t *testing.T) {
	l := New(DefaultCollisionWindow)
	evictedID := fakeID(0)
	l.Append(evictedID, pos(1))

	for i := 1; i <= 50; i++ {
		id := fakeID(i)
		l.Append(id, pos(int64(i+1)))
		l.Resolve(id, Stored)

		if _, ok := l.Advance(); ok {
			t.Fatalf("after resolving %d entries behind the evicted one, Advance ok = true, want false", i)
		}
	}
	if depth := l.Len(); depth != 51 {
		t.Fatalf("Len with 50 resolved entries piled up behind the evicted one = %d, want 51", depth)
	}
}

// TestAdvance_DiscardsResolvedPrefix proves memory does not grow without
// bound across many resolved entries -- Len must return to (near) zero
// after each one resolves and Advance runs, not accumulate across the
// run (#48 decision 3: "the resolved prefix is discarded").
func TestAdvance_DiscardsResolvedPrefix(t *testing.T) {
	l := New(DefaultCollisionWindow)
	const n = 10_000

	for i := 0; i < n; i++ {
		id := fakeID(i)
		l.Append(id, pos(int64(i+1)))
		l.Resolve(id, Stored)
		if _, ok := l.Advance(); !ok {
			t.Fatalf("entry %d: Advance ok = false, want true", i)
		}
		if depth := l.Len(); depth != 0 {
			t.Fatalf("entry %d: Len = %d, want 0 (resolved prefix must be discarded, not retained)", i, depth)
		}
	}
}

func TestCollisions_SameIDAtTwoPositionsIsCounted(t *testing.T) {
	l := New(DefaultCollisionWindow)
	id := fakeID(0)

	l.Append(id, pos(1))
	if got := l.Collisions(); got != 0 {
		t.Fatalf("collisions after a single occurrence = %d, want 0", got)
	}

	l.Append(id, pos(2)) // same id, a distinct position: the collapse case
	if got := l.Collisions(); got != 1 {
		t.Fatalf("collisions after a repeated id = %d, want 1", got)
	}

	// A third occurrence must count again, and a wholly different id
	// appended alongside must not.
	l.Append(id, pos(3))
	l.Append(fakeID(1), pos(4))
	if got := l.Collisions(); got != 2 {
		t.Fatalf("collisions after a third occurrence = %d, want 2", got)
	}
}

// TestCollisions_DetectedAcrossADiscardedEntry is why Append also checks
// the recently-discarded window and not just the live ledger: without
// it, a collision where the earlier twin has already resolved and been
// discarded past the frontier would go uncounted, exactly the silent
// failure #48's "0 dropped silently" rule (extended to "0 miscounted
// silently" here) forbids.
func TestCollisions_DetectedAcrossADiscardedEntry(t *testing.T) {
	l := New(DefaultCollisionWindow)
	id := fakeID(0)

	l.Append(id, pos(1))
	l.Resolve(id, Stored)
	if _, ok := l.Advance(); !ok {
		t.Fatal("Advance ok = false after resolving the only entry, want true")
	}
	if depth := l.Len(); depth != 0 {
		t.Fatalf("Len after discarding the only entry = %d, want 0", depth)
	}

	// id's entry is gone from the live ledger entirely, but still inside
	// the recently-discarded window -- the repeat must still be counted.
	l.Append(id, pos(2))
	if got := l.Collisions(); got != 1 {
		t.Fatalf("collisions after a repeat past the frontier = %d, want 1", got)
	}
}

// TestCollisions_WindowEviction proves the recently-discarded window is
// actually bounded: once more than collisionWindow ids have been
// discarded, the oldest ones age out and stop being checked, matching
// the doc comment's "bounded window" description rather than an
// unbounded history of every id ever seen.
func TestCollisions_WindowEviction(t *testing.T) {
	const window = 4
	l := New(window)

	first := fakeID(0)
	l.Append(first, pos(1))
	l.Resolve(first, Stored)
	if _, ok := l.Advance(); !ok {
		t.Fatal("Advance ok = false, want true")
	}

	// Push `first` out of the discarded window with `window` unrelated
	// ids, each resolved and discarded in turn.
	for i := 1; i <= window; i++ {
		id := fakeID(i)
		l.Append(id, pos(int64(i+1)))
		l.Resolve(id, Stored)
		if _, ok := l.Advance(); !ok {
			t.Fatalf("filler %d: Advance ok = false, want true", i)
		}
	}

	// first has now aged out of the window: re-appending it must not be
	// counted as a collision.
	l.Append(first, pos(999))
	if got := l.Collisions(); got != 0 {
		t.Fatalf("collisions after first aged out of a window of %d = %d, want 0", window, got)
	}
}

// TestResolve_InvalidVerdictPanics guards the contract that only Stored
// and Rejected are meaningful verdicts -- a Retry (or any other value)
// reaching Resolve is a caller bug, not routine input, and should fail
// loudly rather than silently doing nothing indistinguishable from an
// unknown id.
func TestResolve_InvalidVerdictPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Resolve with an invalid Verdict did not panic")
		}
	}()
	l := New(DefaultCollisionWindow)
	l.Resolve(fakeID(0), Verdict(0))
}

// TestConcurrentAppendAndResolve exercises the package's stated
// concurrency contract -- one intake goroutine (the tailer) calling
// Append, one sender goroutine calling Resolve and Advance -- under
// -race. It also calls Collisions and Len concurrently from a third
// goroutine, the same shape a heartbeat builder would use.
func TestConcurrentAppendAndResolve(t *testing.T) {
	const n = 5000
	l := New(DefaultCollisionWindow)

	ids := make([]string, n)
	for i := range ids {
		ids[i] = fakeID(i)
	}

	var wg sync.WaitGroup
	wg.Add(3)

	var appended atomic.Int64
	go func() { // intake / tailer goroutine
		defer wg.Done()
		for i, id := range ids {
			l.Append(id, pos(int64(i+1)))
			appended.Add(1)
		}
	}()

	var lastFrontier queue.Position
	go func() { // sender goroutine
		defer wg.Done()
		resolved := 0
		for resolved < n || appended.Load() < n {
			// Resolve whatever has been appended so far; Append runs
			// concurrently, so this goroutine only resolves ids it
			// knows exist.
			for resolved < int(appended.Load()) {
				l.Resolve(ids[resolved], Stored)
				resolved++
			}
			if p, ok := l.Advance(); ok {
				lastFrontier = p
			}
		}
		// Drain any final advance after the last resolve.
		if p, ok := l.Advance(); ok {
			lastFrontier = p
		}
	}()

	go func() { // concurrent reader, as a heartbeat builder would call
		defer wg.Done()
		for appended.Load() < n {
			_ = l.Collisions()
			_ = l.Len()
		}
	}()

	wg.Wait()

	if depth := l.Len(); depth != 0 {
		t.Fatalf("final Len = %d, want 0", depth)
	}
	if want := pos(int64(n)); lastFrontier != want {
		t.Fatalf("final frontier = %+v, want %+v", lastFrontier, want)
	}
	if collisions := l.Collisions(); collisions != 0 {
		t.Fatalf("collisions = %d, want 0 (every id was distinct)", collisions)
	}
}
