// http.go adds birdcage's side of issue #32's ingest transport to this
// package, alongside the pre-existing UDP syslog Server (server.go,
// retired in slice 7): a bearer-token-authenticated HTTPS endpoint a
// canary's agent (#48) posts batches of events to. It shares this
// package because both are "how an event gets into the alerts table
// from a canary", and slice 7 leaves exactly this half behind once the
// UDP path goes.
package ingest

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/stream"
)

// ingestHandler carries the dependencies POST /ingest/events needs: db
// for the token lookup and alert insert, hub (issue #44) so a newly
// stored alert reaches an open dashboard immediately, and now so tests
// can pin "current time" instead of depending on the wall clock.
type ingestHandler struct {
	db  *db.DB
	hub *stream.Hub
	now func() time.Time
}

// NewHandler returns the ingest submux: bearer-token auth in front of
// POST /ingest/events, and nothing else. It is never mounted alongside,
// or reachable from, internal/api's dashboard mux -- issue #32: "on its
// own submux, structurally unreachable from the dashboard routes and
// from the requireAuth seam (#8)" -- so cmd/birdcage/main.go serves it
// from its own *http.Server (see NewTLSServer), a separate listener
// entirely, not merely a separate path prefix on the dashboard's.
//
// hub may be nil (a caller that doesn't care about live dashboard
// updates, e.g. a test exercising only the auth behavior); a nil hub
// simply means handleBatch skips the publish step.
func NewHandler(database *db.DB, hub *stream.Hub) http.Handler {
	return newHandler(database, hub, time.Now)
}

// newHandler is NewHandler with now injectable, for tests that need a
// pinned clock -- mirroring internal/api's own newHandler/NewHandler
// split.
func newHandler(database *db.DB, hub *stream.Hub, now func() time.Time) http.Handler {
	h := &ingestHandler{db: database, hub: hub, now: now}

	// Exactly one route is ever registered on this mux. Mirrors
	// internal/api's dashboardRoutes doc comment: a request that doesn't
	// match "POST /ingest/events" -- including every dashboard path --
	// falls through to notFoundJSON, never to any dashboard handler,
	// because no dashboard handler is ever registered here. This mux
	// registered with a dashboard path never matches one either, for the
	// same reason in reverse: see TestIngestMuxCannotReachDashboardRoutes
	// and TestDashboardMuxCannotReachIngestRoute in http_test.go.
	mux := http.NewServeMux()
	mux.Handle("POST /ingest/events", requireBearerToken(database, now, h.handleBatch))
	mux.HandleFunc("/", notFoundJSON)
	return mux
}

func notFoundJSON(w http.ResponseWriter, _ *http.Request) {
	writeIngestError(w, http.StatusNotFound, "not found")
}

// writeJSON and writeIngestError mirror internal/api's own (unexported
// there, so not reusable directly): one place in this package that
// writes a response body, and one shape for every error response,
// {"error": "..."}.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("ingest: write response: %v", err)
	}
}

func writeIngestError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
