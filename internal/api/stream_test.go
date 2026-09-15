package api

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/store"
	"github.com/tomlawesome/birdcage/internal/stream"
)

// TestStreamDeliversAlertWithinASecond is issue #44's central "Done
// when": a hit written by the ingest path appears on an already-open
// dashboard within a second, proven by a test rather than by eye. It
// exercises the real HTTP handler over a real (loopback) connection,
// not an in-process fake, and the real store write path
// (store.InsertAlertIfNew) that issue #32 names as the store-level
// alert write path this issue publishes from.
func TestStreamDeliversAlertWithinASecond(t *testing.T) {
	database := openTempDB(t)
	hub := stream.NewHub()
	h := NewHandlerWithHub(database, nil, hub)

	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/stream", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/stream: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", cc)
	}
	if xb := resp.Header.Get("X-Accel-Buffering"); xb != "no" {
		t.Errorf("X-Accel-Buffering = %q, want no", xb)
	}

	// The dashboard is now "already open" (the stream is connected).
	// This channel decouples the blocking body read from the 1s
	// deadline below.
	lines := make(chan string, 8)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()

	// The ingest path: store.InsertAlertIfNew is what issue #32's
	// CONTEXT names as the store-level alert write path. A caller that
	// wants streaming publishes to the hub exactly when the store
	// reports it stored a genuinely new row, same as this test does.
	a := store.AlertInsert{
		InstanceID: "node-1",
		SourceIP:   "203.0.113.9",
		DestPort:   22,
		Service:    "ssh",
		Raw:        `{"src_host":"203.0.113.9"}`,
		ReceivedAt: time.Now().UTC(),
	}
	stored, err := store.InsertAlertIfNew(context.Background(), database, a)
	if err != nil {
		t.Fatalf("InsertAlertIfNew: %v", err)
	}
	if !stored {
		t.Fatalf("InsertAlertIfNew: stored = false, want true")
	}
	hub.PublishAlert(a)

	deadline := time.After(time.Second)
	for {
		select {
		case line := <-lines:
			if !strings.HasPrefix(line, "data: ") {
				continue // blank line separator, or a comment.
			}
			payload := strings.TrimPrefix(line, "data: ")
			if !strings.Contains(payload, "203.0.113.9") {
				t.Fatalf("data line = %q, want it to contain the alert's source IP", payload)
			}
			return // Delivered within the second: done when met.
		case <-deadline:
			t.Fatal("alert did not arrive on the open stream within a second")
		}
	}
}

// TestStreamRejectsWhenHubAtCapacity is the fail-closed connection-limit
// behaviour issue #44's Research section adds: past the hub's
// subscriber cap, GET /api/stream refuses rather than accepting an
// unbounded number of held-open connections.
func TestStreamRejectsWhenHubAtCapacity(t *testing.T) {
	database := openTempDB(t)
	hub := stream.NewHub()
	h := NewHandlerWithHub(database, nil, hub)

	// Fill the hub directly (cheaper and more deterministic than opening
	// 256 real HTTP connections) -- handleStream's only interaction with
	// the hub is Subscribe, which this exercises identically.
	var cancels []func()
	for {
		_, cancel, ok := hub.Subscribe()
		if !ok {
			break
		}
		cancels = append(cancels, cancel)
	}
	defer func() {
		for _, c := range cancels {
			c()
		}
	}()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/stream", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}

// TestStreamIsBehindTheSameOuterMuxAsOtherDashboardRoutes documents that
// /api/stream is registered exactly like every other dashboard route --
// through newHandlerWithHub's single "protected" wrapping, never
// standalone -- so it inherits requireAuth (#8) the same way GET
// /api/alerts etc. already do. A wrong method still reaches
// dashboardRoutes' mux and gets a 405, the same structural guarantee
// TestReadOnlyRoutesRejectMutatingMethods checks for the others.
func TestStreamIsBehindTheSameOuterMuxAsOtherDashboardRoutes(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, time.Now, nil)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/api/stream", nil)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/stream: status = %d, want 405", method, rec.Code)
		}
	}
}
