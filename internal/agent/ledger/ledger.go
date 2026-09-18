package ledger

import (
	"container/list"
	"sync"

	"github.com/tomlawesome/birdcage/internal/agent/queue"
)

// Verdict is the terminal outcome birdcage returns for a log-road event --
// the only two states this package ever resolves an entry against (#48
// decision 3: "Ledger entries resolve when the sender gets a terminal
// verdict for that id: stored or rejected ... A Retry verdict resolves
// nothing"). There is deliberately no Retry value: a retry never reaches
// Resolve, so there is nothing here for a caller to pass by mistake.
type Verdict int

const (
	// Stored is birdcage's acknowledgement that an event is durably
	// saved.
	Stored Verdict = iota + 1
	// Rejected is birdcage's permanent refusal of an event. It resolves
	// an entry exactly as Stored does -- both are terminal, and the
	// ledger's only job is knowing an id is settled, not what it settled
	// to (#48: "Both terminal").
	Rejected
)

// DefaultCollisionWindow is how many recently-discarded log-road ids
// Append still checks for a collision after their entry has already left
// the live ledger (frontier advanced past it, freeing its memory). #48
// decision 3 proposes this number and marks it [contested], not
// ratified: "Detect over the unresolved ledger plus a small window of
// recently resolved log-road ids (1,024 -- identical stamps mean
// near-adjacent lines, so a small window suffices)." Per
// docs/security-by-design.md's rule for contested numbers, it is written
// down here as a documented, tunable choice, not a settled fact -- a
// caller with a better number should pass it to New directly.
const DefaultCollisionWindow = 1024

// entry is one ledger record: an id, the position the log-road intake
// reached immediately after the line that produced it, and whether
// birdcage has returned a terminal verdict for it yet.
type entry struct {
	id       string
	pos      queue.Position
	resolved bool
}

// Ledger is the ordered record #48 decision 3 builds the acknowledged
// position from. It holds one entry per log-road line, in the log order
// Append is called in, and computes the frontier -- the position of the
// last entry in an unbroken resolved prefix -- which is the only value
// ever safe to persist as the acknowledged position.
//
// Concurrency: the tailer's goroutine calls Append; the sender's
// goroutine calls Resolve and Advance. One coarse mutex guards all of
// it, the same style as MemQueue in the sibling queue package and
// limiterRegistry in internal/ingest/ratelimit.go -- a ledger holds at
// most a few minutes' worth of in-flight entries (Advance discards a
// resolved prefix as soon as one exists), so lock contention here is not
// a design concern worth a finer-grained structure.
type Ledger struct {
	mu sync.Mutex

	collisionWindow int

	// order holds *entry values, oldest (earliest-appended, i.e. lowest
	// log position) at the front. This is the structure Advance walks
	// to find the resolved prefix.
	order *list.List

	// byID indexes order's live (not yet discarded) entries by id, each
	// slice oldest-first. A slice with more than one element is the
	// collision case: the same id recorded at two distinct log
	// positions. Resolve always settles the oldest unresolved element of
	// the slice, and Advance always discards from its front -- both
	// follow the same append-order invariant order itself keeps, so an
	// id's entries here are consumed in exactly the order they were
	// appended.
	byID map[string][]*list.Element

	// discardedOrder and discardedSet together are the bounded window of
	// ids whose entries Advance has already discarded, kept only so a
	// collision whose earlier twin has already left the live ledger is
	// still counted (see DefaultCollisionWindow). discardedOrder is the
	// eviction queue (oldest id at the front); discardedSet mirrors it
	// as id -> count of occurrences currently in the window, since the
	// same id can be discarded more than once while still inside a small
	// window.
	discardedOrder *list.List
	discardedSet   map[string]int

	// collisions counts every Append that found id already live or
	// within the discarded window -- the same event id at two distinct
	// log positions, expected to be zero forever (#48, "The event id":
	// OpenCanary appends and never rewrites, so a repeated line is a
	// repeated emission, not routine behaviour).
	collisions uint64
}

// New returns an empty Ledger. collisionWindow bounds how many
// already-discarded ids Append still checks against; pass
// DefaultCollisionWindow absent a better number for it. New panics if
// collisionWindow is negative -- zero is accepted, meaning no
// discarded-window check at all (a caller trading a smaller footprint
// for missing collisions that straddle a frontier advance), but a
// negative size is never meaningful and is a caller bug.
func New(collisionWindow int) *Ledger {
	if collisionWindow < 0 {
		panic("ledger: collisionWindow must not be negative")
	}
	return &Ledger{
		collisionWindow: collisionWindow,
		order:           list.New(),
		byID:            make(map[string][]*list.Element),
		discardedOrder:  list.New(),
		discardedSet:    make(map[string]int),
	}
}

// Append records a new entry for id at pos, trusting the caller's call
// order as the log order -- this package never re-derives ordering from
// pos itself (#48 decision 3: "one per line the tailer emits, appended
// by the log-road intake in log order"). Only the log-road tailer calls
// this; the webhook road never does, which is exactly what keeps a
// webhook-only event from ever advancing the frontier.
//
// If id already appears among the ledger's live entries (unresolved, or
// resolved but not yet discarded because something earlier still blocks
// the frontier) or in the recently-discarded window, this is the
// collision case #48's "The event id" section defines: the same id at
// two distinct log positions. Append counts it (see Collisions) and
// still records the new entry regardless -- turning a detected collision
// into a skipped entry would trade a visible bug for a silent one, which
// is the one direction this package must never fail toward.
func (l *Ledger) Append(id string, pos queue.Position) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, live := l.byID[id]; live || l.discardedSet[id] > 0 {
		l.collisions++
	}

	e := &entry{id: id, pos: pos}
	elem := l.order.PushBack(e)
	l.byID[id] = append(l.byID[id], elem)
}

// Resolve marks id's oldest unresolved live entry as settled by v. v
// must be Stored or Rejected; Resolve panics on any other value, since
// that is a caller bug -- a Retry verdict is never passed here at all
// (#48: "A Retry verdict resolves nothing"), so the only two valid
// values are the two this package defines.
//
// An id with no unresolved live entry -- never appended at all (a
// webhook-road ack, since webhook events have no ledger entry), already
// resolved, or already discarded past the frontier -- is ignored, not an
// error (#48: "Verdicts for ids not in the ledger are ignored"). When id
// collided (Append saw it more than once), Resolve settles exactly one
// entry, the oldest still-unresolved one, so two distinct log positions
// sharing an id resolve independently and in log order -- matching how
// MemQueue's own dedup means at most one instance of that id is ever
// in flight to birdcage at once.
func (l *Ledger) Resolve(id string, v Verdict) {
	if v != Stored && v != Rejected {
		panic("ledger: Resolve called with an invalid Verdict")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	for _, elem := range l.byID[id] {
		e := elem.Value.(*entry)
		if !e.resolved {
			e.resolved = true
			return
		}
	}
}

// Advance computes the frontier -- the position of the last entry in an
// unbroken resolved prefix of the ledger, walking from the oldest entry
// forward -- and discards that prefix from memory, which is what keeps
// the ledger from growing without bound across a long-running agent
// (#48 decision 3: "the resolved prefix is discarded"). ok is false when
// the prefix is empty (the ledger holds no entries, or its oldest entry
// is still unresolved), in which case pos is the zero Position and must
// not be used or saved.
//
// This is the property the whole package exists to protect: a resolved
// entry sitting behind an unresolved one must never advance the frontier
// past it. Advance stops at the first unresolved entry it meets no
// matter how many resolved entries sit after it, so an event birdcage
// acknowledges out of log order leaves the frontier exactly where the
// oldest still-unresolved event left it. An evicted event (the queue's
// drop-oldest eviction never resolves its ledger entry) therefore stalls
// the frontier indefinitely and deliberately, which is what makes the
// next tailer catch-up re-read it (#48 decision 2) rather than skip it.
//
// Call this once after resolving whatever verdicts a batch settled; it
// does not need to run per-event, since the answer is the same either
// way -- the position of the last entry before the first unresolved one,
// however many resolves happened since the last call.
func (l *Ledger) Advance() (pos queue.Position, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for {
		front := l.order.Front()
		if front == nil {
			break
		}
		e := front.Value.(*entry)
		if !e.resolved {
			break
		}

		l.order.Remove(front)
		// front is always byID[e.id]'s own front element too: order and
		// each byID slice share the same append order, so the earliest
		// remaining entry for e.id in one is the earliest remaining
		// entry for it in the other.
		if rest := l.byID[e.id][1:]; len(rest) == 0 {
			delete(l.byID, e.id)
		} else {
			l.byID[e.id] = rest
		}
		l.rememberDiscarded(e.id)

		pos, ok = e.pos, true
	}
	return pos, ok
}

// rememberDiscarded adds id to the bounded recently-discarded window,
// evicting the oldest entry once the window exceeds collisionWindow.
// Called with l.mu already held.
func (l *Ledger) rememberDiscarded(id string) {
	if l.collisionWindow == 0 {
		return
	}

	l.discardedOrder.PushBack(id)
	l.discardedSet[id]++

	for l.discardedOrder.Len() > l.collisionWindow {
		oldest := l.discardedOrder.Front()
		l.discardedOrder.Remove(oldest)
		oid := oldest.Value.(string)
		if l.discardedSet[oid]--; l.discardedSet[oid] == 0 {
			delete(l.discardedSet, oid)
		}
	}
}

// Collisions is the running count of ids Append has ever seen at two
// distinct log positions -- expected to be exactly zero for the life of
// a healthy agent (#48: "Expected zero, forever"). Exposed for the
// heartbeat self-report; building that report is out of this package's
// scope.
func (l *Ledger) Collisions() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.collisions
}

// Len reports the number of entries the ledger currently holds --
// unresolved, or resolved but not yet discarded because something
// earlier in log order still blocks the frontier. Exposed so a caller
// (or a test) can see that Advance is actually bounding memory rather
// than merely trusting that it does.
func (l *Ledger) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.order.Len()
}
