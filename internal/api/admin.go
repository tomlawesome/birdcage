package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// The admin write routes (#227). They are not part of the dashboard
// handler: a read API token is answered by that handler, so a write route
// there would be reachable with a token. Standard pattern: a separate
// admin surface (OWASP API Security Top 10 2023, API5), mounted by
// internal/auth.Service.WrapWithAdmin on the session side only, behind
// the admin-role, X-Requested-With and Origin / Fetch Metadata checks.
// NewAdminHandler does none of those checks itself.

const (
	// AuditSelfTestRequested is the audit action for a run-now request.
	AuditSelfTestRequested = "canary.selftest.requested"

	// defaultMaintenance is how long PUT maintenance lasts without an
	// `until`; maxMaintenance is the furthest ahead `until` may be.
	// Maintenance always ends: open-ended downtime would let a dead
	// canary stay quiet forever.
	defaultMaintenance = 24 * time.Hour
	maxMaintenance     = 7 * 24 * time.Hour

	// maxAdminBody bounds the one small JSON body an admin route reads.
	maxAdminBody = 4 << 10
)

// SelfTestRunner queues a self-test now. internal/selftestsched.Scheduler
// implements it. created is false when a run was already open and
// commandID is that run's.
type SelfTestRunner interface {
	RunNow(ctx context.Context, canaryID string) (commandID string, created bool, err error)
}

type actorKey struct{}

// WithActor returns ctx carrying the signed-in username, which the admin
// handler records as the audit actor. The sign-in layer sets it from the
// verified session; nothing in a request can.
func WithActor(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, actorKey{}, username)
}

func actorFrom(ctx context.Context) string {
	a, _ := ctx.Value(actorKey{}).(string)
	return a
}

// adminRouteSpecs is the entire admin write API: three unsafe routes, in
// their own table so the dashboard table and its read-only test stay as
// they are.
func adminRouteSpecs(h *handler) []dashboardRouteSpec {
	return []dashboardRouteSpec{
		{http.MethodPost, "/api/admin/canaries/{id}/self-test", h.handleAdminSelfTest},
		{http.MethodPut, "/api/admin/canaries/{id}/maintenance", h.handleAdminMaintenanceSet},
		{http.MethodDelete, "/api/admin/canaries/{id}/maintenance", h.handleAdminMaintenanceClear},
	}
}

// NewAdminHandler serves the admin write routes. now nil means time.Now.
// A method a path's table does not list is 405, anything else 404, both
// as problem+json.
func NewAdminHandler(database *db.DB, now func() time.Time, runner SelfTestRunner) http.Handler {
	if now == nil {
		now = time.Now
	}
	h := &handler{db: database, now: now, runner: runner}
	mux := http.NewServeMux()
	allowed := map[string][]string{}
	for _, spec := range adminRouteSpecs(h) {
		mux.HandleFunc(spec.method+" "+spec.path, spec.handler)
		allowed[spec.path] = append(allowed[spec.path], spec.method)
	}
	for path, methods := range allowed {
		sort.Strings(methods)
		allow := strings.Join(methods, ", ")
		// Method-less, so less specific than the entries above: it
		// answers only the methods the table does not list.
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Allow", allow)
			WriteProblem(w, http.StatusMethodNotAllowed, "")
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		WriteProblem(w, http.StatusNotFound, "")
	})
	return mux
}

// WriteProblem writes an RFC 9457 problem+json response (#217): type
// about:blank, the status text as title, and detail when given. detail is
// shown to the client, so it never carries internal error text.
func WriteProblem(w http.ResponseWriter, status int, detail string) {
	body := map[string]any{"type": "about:blank", "title": http.StatusText(status), "status": status}
	if detail != "" {
		body["detail"] = detail
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("api: write problem: %v", err)
	}
}

// requireActor is the signed-in username for the audit row. A request that
// reaches here without one is refused rather than audited as nobody.
func requireActor(w http.ResponseWriter, r *http.Request) (string, bool) {
	actor := actorFrom(r.Context())
	if strings.TrimSpace(actor) == "" {
		WriteProblem(w, http.StatusUnauthorized, "no signed-in account")
		return "", false
	}
	return actor, true
}

func (h *handler) adminFailed(w http.ResponseWriter, what string, err error) {
	switch {
	case errors.Is(err, store.ErrCanaryNotFound):
		WriteProblem(w, http.StatusNotFound, "unknown canary")
	case errors.Is(err, store.ErrSelfTestNotReady):
		WriteProblem(w, http.StatusConflict, "this canary has not been heard from yet, so there is nothing to self-test")
	default:
		log.Printf("api: %s: %v", what, err)
		WriteProblem(w, http.StatusInternalServerError, "")
	}
}

func (h *handler) handleAdminSelfTest(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireActor(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if h.runner == nil {
		WriteProblem(w, http.StatusServiceUnavailable, "self-tests cannot be queued on this server")
		return
	}
	// Checked here as well as by the runner, so an unknown id is a 404
	// whatever runner is wired.
	if _, known, err := store.SelfTestCanaryByID(r.Context(), h.db, id); err != nil {
		h.adminFailed(w, "look up canary", err)
		return
	} else if !known {
		WriteProblem(w, http.StatusNotFound, "unknown canary")
		return
	}
	commandID, created, err := h.runner.RunNow(r.Context(), id)
	if err != nil {
		h.adminFailed(w, "run self-test now", err)
		return
	}
	reason := "self-test queued, command " + commandID
	if !created {
		reason = "self-test already queued, command " + commandID
	}
	if _, err := audit.Append(r.Context(), h.db, audit.Entry{
		Action: AuditSelfTestRequested, Target: id, Reason: reason, TriggeredBy: actor, CreatedAt: h.now(),
	}); err != nil {
		h.adminFailed(w, "audit self-test request", err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"command_id": commandID})
}

func (h *handler) handleAdminMaintenanceSet(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireActor(w, r)
	if !ok {
		return
	}
	now := h.now().UTC()
	until := now.Add(defaultMaintenance)

	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAdminBody))
	if err != nil {
		WriteProblem(w, http.StatusBadRequest, "the request body could not be read")
		return
	}
	if len(strings.TrimSpace(string(raw))) > 0 {
		var body struct {
			Until *string `json:"until"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			WriteProblem(w, http.StatusBadRequest, `the body must be JSON like {"until": "2026-01-02T15:04:05Z"}`)
			return
		}
		if body.Until != nil {
			t, err := time.Parse(time.RFC3339, *body.Until)
			if err != nil {
				WriteProblem(w, http.StatusBadRequest, "until must be an RFC3339 timestamp, e.g. 2026-01-02T15:04:05Z")
				return
			}
			until = t.UTC()
		}
	}
	if !until.After(now) {
		WriteProblem(w, http.StatusBadRequest, "until must be in the future")
		return
	}
	if until.After(now.Add(maxMaintenance)) {
		WriteProblem(w, http.StatusBadRequest, "until must be no more than 7 days ahead")
		return
	}

	if err := store.SetCanaryMaintenance(r.Context(), h.db, r.PathValue("id"), until, now, actor); err != nil {
		h.adminFailed(w, "set maintenance", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]time.Time{"maintenance_until": until})
}

func (h *handler) handleAdminMaintenanceClear(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireActor(w, r)
	if !ok {
		return
	}
	if err := store.ClearCanaryMaintenance(r.Context(), h.db, r.PathValue("id"), h.now().UTC(), actor); err != nil {
		h.adminFailed(w, "clear maintenance", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
