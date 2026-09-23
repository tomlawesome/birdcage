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

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
	"github.com/tomlawesome/birdcage/internal/stream"
)

// ingestHandler carries the dependencies POST /ingest/events needs: db
// for the token lookup and alert insert, hub (issue #44) so a newly
// stored alert reaches an open dashboard immediately, now so tests can
// pin "current time" instead of depending on the wall clock, limiters
// for the per-canary rate caps (issue #32 item 8), and selfTestIndex
// (#46) -- the bounded, in-memory set of markers a self-test command
// planted, checked by handleBatch before an alert is stored (see
// store.MatchSelfTest's own doc comment for why the candidate set lives
// in memory rather than behind a query).
type ingestHandler struct {
	db            *db.DB
	hub           *stream.Hub
	now           func() time.Time
	limiters      *limiterRegistry
	coalescer     *auditCoalescer
	selfTestIndex *store.SelfTestIndex
	rotationHook  SelfTestRotationHook
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
// updates, e.g. a test exercising only the batch/auth behavior); a nil
// hub simply means handleBatch skips the publish step.
//
// idx is the self-test marker index (#46), constructed once by
// cmd/birdcage's main and shared with internal/selftestsched's
// scheduler -- the same reasoning MintSelfTestCommand's own doc comment
// gives (both sides of a run must agree on one in-memory index, so it
// is built once by whoever owns the ingest path's dependencies and
// passed in, never a package-level registry).
//
// hook is SelfTestRotationHook's own implementation (in practice,
// internal/selftestsched's scheduler), fired by handleRotate the
// instant a rotation succeeds; nil disables the rotation-coupled
// self-test schedule entirely (see hook's own doc comment for why this
// is a structural interface rather than a concrete import).
func NewHandler(database *db.DB, hub *stream.Hub, idx *store.SelfTestIndex, hook SelfTestRotationHook) http.Handler {
	return newHandler(database, hub, time.Now, defaultLimiterLimits, idx, hook)
}

// ingestRoute is the whole registration surface for this mux (issue
// #106, design note section 2): a pattern, the kinds allowed to post to
// it, and its handler. ingestRoutes below is the only place one of these
// is built, and newHandler's loop is the only place one is wired onto
// the mux -- there is no other way for a handler to reach it, and
// therefore no way to add a route that forgets requireBearerToken.
//
// kinds == nil (the zero value) refuses every request: a route added
// without thinking about which kinds may use it fails closed by
// construction, not by whoever wrote it remembering a line -- caught by
// TestEveryIngestRouteNamesARegisteredKind in http_test.go, in go test,
// not in the field.
type ingestRoute struct {
	pattern string
	kinds   []agentkind.Kind
	handler http.HandlerFunc
}

// ingestRoutes is the one table every route on this mux is registered
// from. Kind assignments (design note section 2):
//
//   - /ingest/events -- honeypot only, the alert route.
//   - /ingest/scans -- scanner only, its sole write path.
//   - /ingest/rotate and /ingest/heartbeat -- both kinds: rotation and
//     the heartbeat's common part are generic across every kind.
//   - /ingest/commands -- honeypot only, for now: the only command kind
//     that exists is the self-test, a honeypot concept, and nightjar
//     never polls this route. The set widens in the same commit that
//     ever mints a scanner command -- minimum grant, not maximum
//     convenience.
func ingestRoutes(h *ingestHandler) []ingestRoute {
	return []ingestRoute{
		{"POST /ingest/events", []agentkind.Kind{agentkind.Honeypot}, h.handleBatch},
		{"POST /ingest/rotate", []agentkind.Kind{agentkind.Honeypot, agentkind.Scanner}, h.handleRotate},
		{"POST /ingest/heartbeat", []agentkind.Kind{agentkind.Honeypot, agentkind.Scanner}, h.handleHeartbeat},
		{"POST /ingest/commands", []agentkind.Kind{agentkind.Honeypot}, h.handleCommands},
		{"POST /ingest/scans", []agentkind.Kind{agentkind.Scanner}, h.handleScan},
	}
}

// newHandler is NewHandler with now and limits injectable, for tests
// that need a pinned clock or (far more often) rate limits small enough
// to cross in a handful of calls rather than thousands -- mirroring
// internal/api's own newHandler/NewHandler split.
func newHandler(database *db.DB, hub *stream.Hub, now func() time.Time, limits limiterLimits, idx *store.SelfTestIndex, hook SelfTestRotationHook) http.Handler {
	h := &ingestHandler{db: database, hub: hub, now: now, limiters: newLimiterRegistry(limits), coalescer: newAuditCoalescer(), selfTestIndex: idx, rotationHook: hook}

	// Every route on this mux is behind requireBearerToken, extended
	// with the route's own allowed kinds (issue #106) -- ingestRoute's
	// own doc comment is why this loop is the only wiring. Mirrors
	// internal/api's dashboardRoutes doc comment: a request that doesn't
	// match one of them -- including every dashboard path -- falls
	// through to notFoundJSON, never to any dashboard handler, because
	// no dashboard handler is ever registered here. This mux registered
	// with a dashboard path never matches one either, for the same
	// reason in reverse: see TestIngestMuxCannotReachDashboardRoutes and
	// TestDashboardMuxCannotReachIngestRoute in http_test.go.
	mux := http.NewServeMux()
	for _, route := range ingestRoutes(h) {
		mux.Handle(route.pattern, requireBearerToken(database, now, h.limiters, h.coalescer, h.rotationHook, route))
	}
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
