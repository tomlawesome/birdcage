// Package api serves birdcage's dashboard HTTP API (#3): mostly a
// read-only JSON view over the alerts table (no handler here can mutate
// it), plus one write path added by issue #34 -- POST /api/heartbeat,
// which records a canary's phone-home into the separate
// canaries/heartbeats registry and never touches alerts. Until #8 lands,
// SECURITY.md's "no authentication yet" stance means reaching that
// handler unauthenticated lets a caller record heartbeats for any known
// canary id, not arbitrary writes -- the per-canary ingest token (#32)
// narrows that once it exists.
package api

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/stream"
)

// handler carries the dependencies every route needs: db for queries, now
// so handleStats' "current time" is pinnable in tests instead of always
// reading time.Now(), internalRanges (issue #35's
// BIRDCAGE_INTERNAL_RANGES, parsed once by cmd/birdcage/main.go) so
// handleVisitors/handleTrace can classify a source as "from inside" an
// operator's own address space beyond the always-internal defaults, and
// hub (issue #44) so handleStream can subscribe a dashboard connection
// to it.
type handler struct {
	db             *db.DB
	now            func() time.Time
	internalRanges []*net.IPNet
	hub            *stream.Hub
	// mailConfigured is whether cmd/birdcage found a complete outbound
	// mail configuration at boot (issue #55). It is the one thing GET
	// /api/mail cannot read out of the database: an outbox with nothing
	// in it looks identical whether mail is switched off or simply has
	// had nothing to say. The credential itself never reaches this
	// package -- only the fact that there is one.
	mailConfigured bool
}

// NewHandler wires the dashboard API behind the requireAuth seam #8
// will fill in (ADR-0003). internalRanges is BIRDCAGE_INTERNAL_RANGES,
// already parsed by the caller (store.ParseInternalRanges) -- nil is
// fine and means no ranges beyond the always-internal defaults. The
// returned handler owns its own stream.Hub, freshly created and not
// reachable from outside this package -- nothing yet publishes to it in
// production (issue #32's own ingest endpoint, once it lands, will).
// Use NewHandlerWithHub instead when a caller needs to publish to the
// same hub GET /api/stream serves from.
func NewHandler(database *db.DB, internalRanges []*net.IPNet) http.Handler {
	return NewHandlerWithHub(database, internalRanges, stream.NewHub(), false)
}

// NewHandlerWithHub is NewHandler with an explicit stream.Hub, for a
// caller (issue #32's future ingest endpoint, or a test) that needs to
// publish alerts to the exact hub GET /api/stream is subscribed to.
// mailConfigured is issue #55's boot-time answer to "is there anywhere
// for an alert to go" -- see handler.mailConfigured.
func NewHandlerWithHub(database *db.DB, internalRanges []*net.IPNet, hub *stream.Hub, mailConfigured bool) http.Handler {
	return newHandlerWithHub(database, time.Now, internalRanges, hub, mailConfigured)
}

// newHandler is newHandlerWithHub with a hub of its own and mail off --
// every existing test in this package builds a handler with this, and
// none of them care about streaming or mail, so they're untouched by
// issues #44 and #55.
func newHandler(database *db.DB, now func() time.Time, internalRanges []*net.IPNet) http.Handler {
	return newHandlerWithHub(database, now, internalRanges, stream.NewHub(), false)
}

// newHandlerWithMail is newHandler with issue #55's flag, for the tests
// that exercise GET /api/mail in both of its states.
func newHandlerWithMail(database *db.DB, now func() time.Time, mailConfigured bool) http.Handler {
	return newHandlerWithHub(database, now, nil, stream.NewHub(), mailConfigured)
}

func newHandlerWithHub(database *db.DB, now func() time.Time, internalRanges []*net.IPNet, hub *stream.Hub, mailConfigured bool) http.Handler {
	h := &handler{db: database, now: now, internalRanges: internalRanges, hub: hub, mailConfigured: mailConfigured}
	protected := requireAuth(dashboardRoutes(h))

	// Each known route is registered individually (rather than mounting
	// dashboardRoutes at the "/api/" prefix) so anything dashboardRoutes
	// does *not* register -- any other path under /api/ -- falls through
	// to notFoundJSON below instead of dashboardRoutes' own mux producing
	// a plain-text 404. A wrong method on a known path is still handled
	// correctly: the request reaches dashboardRoutes' mux either way, and
	// that mux's own method-specific patterns (net/http's Go 1.22+ "GET
	// /path" syntax) are what produce the 405, not this outer dispatch.
	mux := http.NewServeMux()
	mux.Handle("/api/alerts", protected)
	mux.Handle("/api/instances", protected)
	mux.Handle("/api/stats", protected)
	mux.Handle("/api/canaries", protected)
	mux.Handle("/api/scans", protected)
	mux.Handle("/api/heartbeat", protected)
	mux.Handle("/api/visitors", protected)
	mux.Handle("/api/trace", protected)
	mux.Handle("/api/stream", protected)
	mux.Handle("/api/history", protected)
	mux.Handle("/api/mail", protected)
	mux.HandleFunc("/", notFoundJSON)
	return mux
}

// dashboardRoutes registers birdcage's entire dashboard API -- ten GET
// routes (including /api/stream, issue #44, /api/history, issue #56,
// /api/mail, issue #55, and /api/scans, issue #108 slice 1) and one POST
// (/api/heartbeat) -- and nothing else. Mirrors mikroview's
// readOnlyRoutes (internal/api/auth.go there): a caller dispatched to
// this mux is structurally unable to reach anything but these routes,
// because nothing else is ever registered on it. That property is what
// requireAuth (issue #8, ADR-0003) will rely on once it exists: a
// lesser-privileged credential can be routed here and nowhere else.
func dashboardRoutes(h *handler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/alerts", h.handleAlerts)
	mux.HandleFunc("GET /api/instances", h.handleInstances)
	mux.HandleFunc("GET /api/stats", h.handleStats)
	mux.HandleFunc("GET /api/canaries", h.handleCanaries)
	mux.HandleFunc("GET /api/scans", h.handleScans)
	mux.HandleFunc("POST /api/heartbeat", h.handleHeartbeat)
	mux.HandleFunc("GET /api/visitors", h.handleVisitors)
	mux.HandleFunc("GET /api/trace", h.handleTrace)
	mux.HandleFunc("GET /api/stream", h.handleStream)
	mux.HandleFunc("GET /api/history", h.handleHistory)
	mux.HandleFunc("GET /api/mail", h.handleMail)
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
