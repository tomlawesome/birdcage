package api

import (
	"fmt"
	"net/http"
	"time"
)

// handleStream serves GET /api/stream (#44): a server-sent-events
// connection birdcage holds open and writes to whenever an alert is
// stored, so an already-open dashboard sees a hit the moment it lands
// instead of waiting for its next 30s poll (frontend/src/App.svelte's
// REFRESH_MS). Registered behind the same requireAuth seam as every
// other dashboard route (see newHandlerWithHub) -- never on the ingest
// mux.
//
// Headers and behaviour here are the fail-closed choices issue #44's
// Research section records:
//   - Cache-Control/X-Accel-Buffering stop an intermediary (a reverse
//     proxy with buffering on by default) from silently holding events
//     until its buffer fills, which would make the feature quietly dead
//     without ever failing a request.
//   - A full subscriber cap in the hub returns 503 here rather than
//     accepting an unbounded number of held-open connections -- the
//     dashboard's poll keeps working regardless.
//   - The client disconnecting (request context canceled) unsubscribes
//     and ends the handler; nothing is left running.
//   - Every write carries a deadline. Without one, a client that stops
//     reading blocks the handler inside the write once the kernel
//     buffers fill: the hub evicts it and frees its cap slot, but the
//     goroutine and its connection stay held forever, so the cap stops
//     bounding anything an attacker can reach. The deadline turns that
//     into an error the loop returns on (#44 research, 2026-09-15).
//
// writeTimeout bounds a single write to one stream connection. A
// dashboard that is reading at all completes a write of a few dozen
// bytes far inside this; one that does not is stuck, and this is how
// long birdcage waits before saying so.
const writeTimeout = 10 * time.Second

func (h *handler) handleStream(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	flusher, ok := w.(http.Flusher)
	if !ok {
		// Every real net/http ResponseWriter implements Flusher; this
		// only fires for a hypothetical wrapper that doesn't. Fail
		// closed rather than silently buffering a stream that will
		// never actually flush to the client.
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	ch, cancel, ok := h.hub.Subscribe()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "stream at capacity")
		return
	}
	defer cancel()

	header := w.Header()
	header.Set("Content-Type", "text/event-stream")
	header.Set("Cache-Control", "no-cache")
	header.Set("Connection", "keep-alive")
	// Told buffering reverse proxies (nginx's default proxy_buffering
	// on) to pass each write straight through instead of holding it
	// until their buffer fills -- see docs/configuration.md.
	header.Set("X-Accel-Buffering", "no")
	if err := rc.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case payload, open := <-ch:
			if !open {
				// Evicted by the hub for being too slow to keep up
				// (back-pressure, issue #44). Ending the response here
				// makes the browser's EventSource reconnect on its own.
				return
			}
			// A stalled reader must cost this connection, not the
			// server: past the deadline the write fails and the
			// handler returns, releasing the goroutine and the
			// subscriber slot. The browser reconnects by itself and
			// the 30s poll covers the gap.
			if err := rc.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				return
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
