// Package api serves birdcage's dashboard HTTP API (#3): a read-only
// JSON view over the alerts table. It has no write path -- there is no
// handler anywhere in this package that can mutate the alerts table --
// which matches SECURITY.md's "no authentication yet" stance: reaching
// this handler unauthenticated only ever grants read access.
package api

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// handler carries the dependencies every route needs: db for queries,
// and now so handleStats' "current time" is pinnable in tests instead
// of always reading time.Now().
type handler struct {
	db  *db.DB
	now func() time.Time
}

// NewHandler wires the dashboard API behind the requireAuth seam #8
// will fill in (ADR-0003).
func NewHandler(database *db.DB) http.Handler {
	return newHandler(database, time.Now)
}

func newHandler(database *db.DB, now func() time.Time) http.Handler {
	protected := requireAuth(readOnlyRoutes(database, now))

	// Each known route is registered individually (rather than mounting
	// readOnlyRoutes at the "/api/" prefix) so anything readOnlyRoutes
	// does *not* register -- any other path under /api/ -- falls through
	// to notFoundJSON below instead of readOnlyRoutes' own mux producing
	// a plain-text 404. A wrong method on a known path is still handled
	// correctly: the request reaches readOnlyRoutes' mux either way, and
	// that mux's own method-specific patterns (net/http's Go 1.22+ "GET
	// /path" syntax) are what produce the 405, not this outer dispatch.
	mux := http.NewServeMux()
	mux.Handle("/api/alerts", protected)
	mux.Handle("/api/instances", protected)
	mux.Handle("/api/stats", protected)
	mux.HandleFunc("/", notFoundJSON)
	return mux
}

// readOnlyRoutes registers birdcage's entire dashboard API -- these
// three GET endpoints -- and nothing else. Mirrors mikroview's
// readOnlyRoutes (internal/api/auth.go there): a caller dispatched to
// this mux is structurally unable to reach anything but these routes,
// because nothing else is ever registered on it. That property is what
// requireAuth (issue #8, ADR-0003) will rely on once it exists: a
// lesser-privileged credential can be routed here and nowhere else.
func readOnlyRoutes(database *db.DB, now func() time.Time) *http.ServeMux {
	h := &handler{db: database, now: now}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/alerts", h.handleAlerts)
	mux.HandleFunc("GET /api/instances", h.handleInstances)
	mux.HandleFunc("GET /api/stats", h.handleStats)
	return mux
}

// requireAuth is a placeholder: issue #8 replaces it with session and
// API-token checks (ADR-0003). Until then every request is allowed.
func requireAuth(next http.Handler) http.Handler {
	return next
}

func notFoundJSON(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "not found")
}

// writeJSON is the only place a response body is written in this
// package, so Content-Type and encode-failure handling live in one
// place. The status line and headers are already on the wire by the
// time Encode could fail, so a failure here can't become a different
// status code -- it's logged (server-side only; the error text itself
// never reaches the client) rather than silently dropped.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("api: write response: %v", err)
	}
}

// writeError is every error response in this package: a JSON body of
// the shape {"error": "..."}. msg is shown to the client, so it must
// never carry a raw SQL error or other internal detail -- callers that
// hit an unexpected failure log it themselves and pass a generic
// message here (see handleAlerts et al.).
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
