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
// "Constraints that are not negotiable").
//
// Safe for exactly one producer goroutine (Push) and one sender goroutine
// (Peek, Ack, Reject) calling concurrently. Depth, Dropped and
// RejectedCount may additionally be called from other goroutines, e.g. a
// heartbeat builder.
type MemQueue struct {
	mu       sync.Mutex
	capacity int
	order    *list.List // *Event elements, oldest at Front -- drop-oldest eviction order
	index    map[string]*list.Element
	dropped  uint64 // evicted for capacity, not birdcage's decision
	rejected uint64 // birdcage permanently rejected these
}

// NewMemQueue returns an empty queue that holds at most capacity events.
// NewMemQueue panics if capacity is not positive: an unbounded or
// zero-sized queue is not a configuration this package supports, since
// #48 requires a cap to exist at all times.
func NewMemQueue(capacity int) *MemQueue {
	if capacity <= 0 {
		panic("queue: capacity must be positive")
	}
	return &MemQueue{
		capacity: capacity,
		order:    list.New(),
		index:    make(map[string]*list.Element, capacity),
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
// When the queue is already at capacity, the oldest still-queued event
// is evicted to make room. The log still holds that event inside the
// recovery window, so this is memory-pressure relief, not data loss
// (#48: "The log holds what was dropped; the cap only stops the agent
// being the OOM-kill target on the one box built to attract floods").
func (q *MemQueue) Push(e Event) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if _, exists := q.index[e.ID]; exists {
		return false
	}

	if q.order.Len() >= q.capacity {
		oldest := q.order.Front()
		q.order.Remove(oldest)
		delete(q.index, oldest.Value.(Event).ID)
		q.dropped++
	}

	elem := q.order.PushBack(e)
	q.index[e.ID] = elem
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
// since the queue was created.
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
