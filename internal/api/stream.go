package api

import (
	"fmt"
	"net/http"
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
func (h *handler) handleStream(w http.ResponseWriter, r *http.Request) {
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
			if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
