package queue

import (
	"container/list"
	"sync"
)

// Event is one OpenCanary hit awaiting delivery to birdcage. Payload is
// the verbatim bytes the agent hashed to produce ID (the emitted JSON,
// wrapped or unwrapped depending on which road it arrived by) -- carried
// opaque all the way to the HTTP client, per #48's "the agent never
// interprets an event beyond locating the first `{` and hashing verbatim".
type Event struct {
	// ID is the 64-char lowercase hex event id. A peer package computes
	// it (#48: "a peer is building the package that computes them -- do
	// NOT compute ids here, accept them"); this package only dedups and
	// stores by it.
	ID string
	// Payload is the event content, forwarded verbatim and never parsed
	// here.
	Payload []byte
}

// MemQueue is the agent's memory-only, capped send queue. It is not a
// disk spool (see the package doc): OpenCanary's log file is the durable
// store, so this queue exists purely to buffer accepted events between
// the point they're read -- webhook or log tail -- and the point the
// sender goroutine ships them, dropping the oldest under memory pressure
// rather than growing unbounded on the box built to attract floods (#48,
// "Constraints that are not negotiable"). Eviction enforces two caps
// together -- event count and total queued payload bytes -- rather than
// count alone (#48 gap 4; see Config's doc comment for why).
//
// Safe for exactly one producer goroutine (Push) and one sender goroutine
// (Peek, Ack, Reject) calling concurrently. Depth, Dropped and
// RejectedCount may additionally be called from other goroutines, e.g. a
// heartbeat builder.
type MemQueue struct {
	mu        sync.Mutex
	maxEvents int
	maxBytes  int64
	bytes     int64      // sum of Payload lengths currently queued
	order     *list.List // *Event elements, oldest at Front -- drop-oldest eviction order
	index     map[string]*list.Element
	dropped   uint64 // evicted for capacity (either cap), not birdcage's decision
	rejected  uint64 // birdcage permanently rejected these
}

// Config bounds a MemQueue's memory use. Both caps apply together: Push
// evicts oldest-first until the queue is under both MaxEvents and
// MaxBytes.
//
// A count cap alone left a hostile flood of near-event.MaxLogLineBytes
// (64 KiB) events as an out-of-memory path -- 10,000 events at that size
// is roughly 640 MiB, on the one box this design exists to keep from
// falling over (#48 gap 4). MaxBytes closes that: it bounds total queued
// bytes regardless of how large any one event's Payload is.
type Config struct {
	// MaxEvents caps the number of queued events.
	MaxEvents int
	// MaxBytes caps the sum of queued events' Payload lengths, in bytes.
	MaxBytes int64
}

// Default caps for a fresh agent process. Neither number is ratified;
// both are marked [contested] in #48's process-composition design note:
// "Cap sizing [contested]: ... Add a byte cap to MemQueue (sum of
// payload lengths; evict oldest until under both caps). Proposed: 10,000
// events / 32 MiB, whichever binds first -- roughly 15 minutes of
// full-rate ordinary events, a few seconds of worst-case hostile ones,
// on a box that must not be the OOM target." Written down here as
// documented, tunable implementation choices per
// docs/security-by-design.md, not as settled facts -- a caller with a
// better number should pass it to NewMemQueue directly.
const (
	DefaultMaxEvents     = 10_000
	DefaultMaxQueueBytes = 32 * 1024 * 1024
)

// NewMemQueue returns an empty queue bounded by cfg. It panics if either
// cfg.MaxEvents or cfg.MaxBytes is not positive: an unbounded or
// zero-sized queue is not a configuration this package supports, since
// #48 requires a cap -- of both kinds now -- to exist at all times.
func NewMemQueue(cfg Config) *MemQueue {
	if cfg.MaxEvents <= 0 || cfg.MaxBytes <= 0 {
		panic("queue: Config.MaxEvents and Config.MaxBytes must both be positive")
	}
	return &MemQueue{
		maxEvents: cfg.MaxEvents,
		maxBytes:  cfg.MaxBytes,
		order:     list.New(),
		index:     make(map[string]*list.Element, cfg.MaxEvents),
	}
}

// Push enqueues an event, deduplicating by ID so a hit that arrives by
// both the webhook and the log read -- or is replayed after a restart --
// resolves to one queued copy (#48, "Identifies each event by the id
// ... so the same hit arriving by both roads, or replayed after a
// restart, resolves to one stored alert"). It reports whether the event
// was newly queued; false means it was already present and Push was a
// no-op.
//
// When adding e would leave the queue at or over either cap -- MaxEvents
// or MaxBytes -- the oldest still-queued event is evicted, repeatedly,
// until the queue (not counting e yet) is under both, or empty. The log
// still holds every evicted event inside the recovery window, so this is
// memory-pressure relief, not data loss (#48: "The log holds what was
// dropped; the cap only stops the agent being the OOM-kill target on the
// one box built to attract floods").
//
// A single event whose own Payload already exceeds MaxBytes is still
// admitted, alone, once the queue has been evicted down to empty for it
// -- this package never judges event content (a peer package's job), so
// it does not refuse an oversize event outright. The very next Push
// evicts it in turn like anything else, so it never grows the queue past
// one such event's worth of memory.
func (q *MemQueue) Push(e Event) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if _, exists := q.index[e.ID]; exists {
		return false
	}

	for q.order.Len() > 0 && (q.order.Len() >= q.maxEvents || q.bytes+int64(len(e.Payload)) > q.maxBytes) {
		oldest := q.order.Front()
		q.order.Remove(oldest)
		oldestEvent := oldest.Value.(Event)
		delete(q.index, oldestEvent.ID)
		q.bytes -= int64(len(oldestEvent.Payload))
		q.dropped++
	}

	elem := q.order.PushBack(e)
	q.index[e.ID] = elem
	q.bytes += int64(len(e.Payload))
	return true
}

// Peek returns up to n queued events, oldest first, without removing
// them. The sender goroutine uses this to build a batch; events stay
// queued until Ack or Reject removes them by id, since the saved
// position must advance only on birdcage's acknowledgement, never on
// read (#48, "Durability: the saved position is the acknowledged
// position").
func (q *MemQueue) Peek(n int) []Event {
	q.mu.Lock()
	defer q.mu.Unlock()

	out := make([]Event, 0, n)
	for e := q.order.Front(); e != nil && len(out) < n; e = e.Next() {
		out = append(out, e.Value.(Event))
	}
	return out
}

// Ack removes an event birdcage has acknowledged as stored. Call it only
// once the acknowledgement is confirmed: removal here is what
// "acknowledged" means to this queue, and it is the caller's cue that it
// is now safe to advance the saved position (via PositionStore) past
// this event's place in the log. Acking an id not present (already
// removed, or never queued) is a harmless no-op.
func (q *MemQueue) Ack(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.removeLocked(id)
}

// Reject removes an event birdcage has permanently rejected and counts
// it, rather than leaving it to retry on the once-a-minute cadence out
// to the rotation horizon (#48: "An event birdcage permanently rejects
// is dropped from the queue and counted; it is not retried once a
// minute until the rotation horizon"). Like Ack, this is a terminal
// resolution the caller can use to advance the saved position.
func (q *MemQueue) Reject(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.removeLocked(id) {
		q.rejected++
	}
}

func (q *MemQueue) removeLocked(id string) bool {
	elem, exists := q.index[id]
	if !exists {
		return false
	}
	q.order.Remove(elem)
	delete(q.index, id)
	q.bytes -= int64(len(elem.Value.(Event).Payload))
	return true
}

// Depth is the number of events currently queued -- reported in the
// heartbeat's self-report (#48: "report queue depth (the heartbeat
// carries it)"). Building the heartbeat itself is out of this package's
// scope.
func (q *MemQueue) Depth() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.order.Len()
}

// Dropped is the number of events evicted for capacity (drop-oldest)
// since the queue was created -- whichever cap triggered the eviction,
// MaxEvents or MaxBytes (#48 gap 4): an eviction is an eviction, counted
// the same way regardless of which cap it relieved.
func (q *MemQueue) Dropped() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.dropped
}

// RejectedCount is the number of events birdcage has permanently
// rejected since the queue was created, exposed for the heartbeat
// self-report; building that report is out of this package's scope.
func (q *MemQueue) RejectedCount() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.rejected
}
