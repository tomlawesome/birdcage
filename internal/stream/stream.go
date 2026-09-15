// Package stream is birdcage's in-process, no-dependency real-time
// fan-out for the dashboard (#44): a Hub that GET /api/stream (see
// internal/api/stream.go) subscribes to, and that a future write path
// (issue #32's token-authenticated ingest endpoint, once it lands) feeds
// by calling PublishAlert after store.InsertAlertIfNew reports it stored
// a genuinely new row.
//
// This package deliberately does not touch internal/store: adding a
// publish call inside store.InsertAlertIfNew itself would mean changing
// its signature, and its own tests (internal/store/token_test.go, #32's,
// not this issue's) call it directly today. Wiring stays one-directional
// -- this package imports store for the Alert type, store never imports
// this package -- so the write path stays exactly as #32 left it and
// gains streaming for free the moment it also calls PublishAlert.
package stream

import (
	"encoding/json"
	"log/slog"
	"sync"

	"github.com/tomlawesome/birdcage/internal/store"
)

const (
	// subscriberBuffer bounds how many not-yet-delivered events a single
	// /api/stream connection can accumulate before it is treated as too
	// slow to keep up. Issue #44's back-pressure requirement: bound each
	// subscriber's buffer and drop the slowest rather than growing
	// without limit. Sized well above the volume a real dashboard should
	// ever need to catch up on between reads (a handful of alerts), per
	// the bounded-queue guidance found researching this issue (see the
	// issue's Research section) -- large enough that a momentary stall
	// doesn't evict a healthy connection, small enough that a stuck one
	// costs a bounded, small amount of memory.
	subscriberBuffer = 16

	// maxSubscribers bounds total concurrent /api/stream connections.
	// Until #8 lands, nothing authenticates the dashboard (SECURITY.md),
	// so without this cap a single caller could open unbounded
	// connections and exhaust goroutines/memory/file descriptors --
	// the same uncontrolled-resource-consumption class (CWE-400) as
	// CVE-2007-6750 (Slowloris) and CVE-2023-44487 (HTTP/2 Rapid Reset),
	// found researching this issue. Past this many, Subscribe fails
	// closed (refuses rather than accepting unboundedly) and the caller
	// falls back to the 30s poll.
	maxSubscribers = 256
)

// subscriber is one open /api/stream connection's mailbox.
type subscriber struct {
	ch chan []byte
}

// Hub fans out each published alert to every currently-subscribed
// dashboard connection -- the "in-process hub" issue #44 specifies. No
// broker, no new dependency: just a map of channels guarded by a mutex.
type Hub struct {
	mu   sync.Mutex
	subs map[*subscriber]struct{}
}

// NewHub returns an empty Hub, ready to use.
func NewHub() *Hub {
	return &Hub{subs: make(map[*subscriber]struct{})}
}

// Subscribe registers a new listener and returns the channel it will
// receive published payloads on, plus a cancel func the caller must call
// exactly once (typically deferred) to unregister and release it.
//
// ok is false, and ch/cancel are nil, when the hub already holds
// maxSubscribers connections -- the caller (internal/api's handleStream)
// must fail the request closed (e.g. 503) rather than accept past the
// cap.
func (h *Hub) Subscribe() (ch <-chan []byte, cancel func(), ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.subs) >= maxSubscribers {
		return nil, nil, false
	}

	sub := &subscriber{ch: make(chan []byte, subscriberBuffer)}
	h.subs[sub] = struct{}{}

	var once sync.Once
	cancel = func() {
		once.Do(func() {
			h.mu.Lock()
			defer h.mu.Unlock()
			if _, present := h.subs[sub]; present {
				delete(h.subs, sub)
				close(sub.ch)
			}
		})
	}
	return sub.ch, cancel, true
}

// PublishAlert marshals a to JSON and fans it out to every current
// subscriber without blocking. A subscriber whose buffer is already full
// is evicted (its channel closed and removed from the hub) instead of
// being allowed to block this call or grow memory without bound -- issue
// #44's back-pressure requirement, and the exact failure mode a real
// prior-art SSE broadcaster bug (found researching this issue) shows is
// necessary to avoid: one slow client must never degrade every other
// connected dashboard.
//
// The evicted connection's handleStream sees its channel closed, ends
// the HTTP response, and the browser's own EventSource reconnects on its
// own; the dashboard's 30s poll (frontend/src/App.svelte's REFRESH_MS)
// keeps it correct in the meantime, so eviction is a safe response to a
// stuck reader, never a silent data loss the operator can't recover
// from.
//
// A JSON marshal failure is logged and dropped rather than returned:
// callers of PublishAlert reach it only after already committing a to
// the database, and a stream-encoding problem must never make an
// already-successful write look like it failed.
func (h *Hub) PublishAlert(a store.AlertInsert) {
	payload, err := json.Marshal(a)
	if err != nil {
		slog.Error("stream: marshal alert for publish", "err", err)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	for sub := range h.subs {
		select {
		case sub.ch <- payload:
		default:
			delete(h.subs, sub)
			close(sub.ch)
		}
	}
}

// Subscribers reports how many connections are currently registered.
// Exported for tests; production code has no need to inspect hub
// occupancy.
func (h *Hub) Subscribers() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}
