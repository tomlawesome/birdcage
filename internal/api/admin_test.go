package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

const adminActor = "erebus-admin"

// fakeRunner stands in for the self-test scheduler: the first request for
// a canary queues "cmd-<id>", later ones answer with that queued id.
type fakeRunner struct {
	calls  []string
	queued map[string]string
}

func (f *fakeRunner) RunNow(_ context.Context, canaryID string) (string, bool, error) {
	f.calls = append(f.calls, canaryID)
	if f.queued == nil {
		f.queued = map[string]string{}
	}
	if id, ok := f.queued[canaryID]; ok {
		return id, false, nil
	}
	f.queued[canaryID] = "cmd-" + canaryID
	return f.queued[canaryID], true, nil
}

type adminFixture struct {
	database *db.DB
	runner   *fakeRunner
	now      time.Time
	admin    http.Handler
	dash     http.Handler
}

// newAdminFixture has one canary, canary-a, last heard at the fixed clock
// time minus ten minutes (so, silent without maintenance).
func newAdminFixture(t *testing.T) *adminFixture {
	t.Helper()
	database := openTempDB(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	insertCanary(t, database, store.Canary{ID: "canary-a", Name: "canary-a", Lane: "lan", Ports: "22", HeartbeatIntervalS: 60, EnrolledAt: now.Add(-time.Hour)})
	if err := store.RecordHeartbeat(context.Background(), database, "canary-a", now.Add(-10*time.Minute)); err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}
	runner := &fakeRunner{}
	return &adminFixture{
		database: database, runner: runner, now: now,
		admin: NewAdminHandler(database, fixedNow(now), runner),
		dash:  newHandler(database, fixedNow(now), nil),
	}
}

// do sends one request to the admin handler as the signed-in adminActor
// (the sign-in layer's job, here played by WithActor).
func (f *adminFixture) do(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req = req.WithContext(WithActor(req.Context(), adminActor))
	rec := httptest.NewRecorder()
	f.admin.ServeHTTP(rec, req)
	return rec
}

func (f *adminFixture) canaryJSON(t *testing.T) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	f.dash.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/canaries", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/canaries: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Canaries []map[string]any `json:"canaries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp.Canaries) != 1 {
		t.Fatalf("decode canaries: %v; body=%s", err, rec.Body.String())
	}
	return resp.Canaries[0]
}

func assertProblem(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, status, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Errorf("Content-Type = %q, want application/problem+json (RFC 9457)", ct)
	}
	var p struct {
		Title  string `json:"title"`
		Status int    `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || p.Status != status || p.Title == "" {
		t.Errorf("problem body = %s (%v), want a title and status %d", rec.Body.String(), err, status)
	}
}

func (f *adminFixture) auditRows(t *testing.T, action string) (n int, target, by string) {
	t.Helper()
	if err := f.database.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = ?`, action).Scan(&n); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if n > 0 {
		if err := f.database.QueryRow(`SELECT target, triggered_by FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1`, action).Scan(&target, &by); err != nil {
			t.Fatalf("scan audit row: %v", err)
		}
	}
	return n, target, by
}

// TestAdminRoutesAllUnsafeAndOwnTable: the admin routes have their own
// table, adminRouteSpecs, apart from the read-only dashboard one. It holds
// exactly POST self-test, PUT maintenance and DELETE maintenance, all under
// /api/admin/, and every unsafe method it registers is one of these three.
// The dashboard table stays GET-only and holds nothing under /api/admin/.
func TestAdminRoutesAllUnsafeAndOwnTable(t *testing.T) {
	got := map[string]bool{}
	for _, spec := range adminRouteSpecs(&handler{}) {
		if !strings.HasPrefix(spec.path, "/api/admin/") {
			t.Errorf("admin route %s %s is outside /api/admin/", spec.method, spec.path)
		}
		switch spec.method {
		case http.MethodPost, http.MethodPut, http.MethodDelete:
		default:
			t.Errorf("admin route %s %s: only unsafe methods belong in this table", spec.method, spec.path)
		}
		got[spec.method+" "+spec.path] = true
	}
	for _, want := range []string{
		"POST /api/admin/canaries/{id}/self-test",
		"PUT /api/admin/canaries/{id}/maintenance",
		"DELETE /api/admin/canaries/{id}/maintenance",
	} {
		if !got[want] {
			t.Errorf("adminRouteSpecs has no %s", want)
		}
	}
	if len(got) != 3 {
		t.Errorf("adminRouteSpecs registers %d routes, want exactly 3: %v", len(got), got)
	}
	for _, spec := range dashboardRouteSpecs(&handler{}) {
		if strings.HasPrefix(spec.path, "/api/admin/") {
			t.Errorf("dashboard table registers %s %s: admin routes must not share the read-only table", spec.method, spec.path)
		}
	}
}

// TestDashboardHandlerDoesNotServeAdminRoutes: a read token is answered by
// the dashboard handler, so that handler must find nothing at an admin path
// under any method.
func TestDashboardHandlerDoesNotServeAdminRoutes(t *testing.T) {
	f := newAdminFixture(t)
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		for _, path := range []string{"/api/admin/canaries/canary-a/self-test", "/api/admin/canaries/canary-a/maintenance"} {
			rec := httptest.NewRecorder()
			f.dash.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
			if rec.Code != http.StatusNotFound {
				t.Errorf("dashboard handler %s %s = %d, want 404", method, path, rec.Code)
			}
		}
	}
	if len(f.runner.calls) != 0 {
		t.Errorf("run-now calls = %v, want none", f.runner.calls)
	}
}

// TestAdminHandlerRejectsOtherMethods: a method the table does not list is
// 405, not a write.
func TestAdminHandlerRejectsOtherMethods(t *testing.T) {
	f := newAdminFixture(t)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/admin/canaries/canary-a/self-test"},
		{http.MethodPut, "/api/admin/canaries/canary-a/self-test"},
		{http.MethodDelete, "/api/admin/canaries/canary-a/self-test"},
		{http.MethodGet, "/api/admin/canaries/canary-a/maintenance"},
		{http.MethodPost, "/api/admin/canaries/canary-a/maintenance"},
		{http.MethodPatch, "/api/admin/canaries/canary-a/maintenance"},
	} {
		if rec := f.do(t, c.method, c.path, ""); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d, want 405", c.method, c.path, rec.Code)
		}
	}
}

// TestSecurityDocListsEveryAdminRoute: SECURITY.md names each admin route
// and says how it is guarded.
func TestSecurityDocListsEveryAdminRoute(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "SECURITY.md"))
	if err != nil {
		t.Fatalf("read SECURITY.md: %v", err)
	}
	doc := string(raw)
	for _, spec := range adminRouteSpecs(&handler{}) {
		if !strings.Contains(doc, "| `"+spec.path+"`") {
			t.Errorf("SECURITY.md has no table row for %s %s", spec.method, spec.path)
		}
	}
	for _, guard := range []string{"X-Requested-With", "Origin", "Sec-Fetch-Site", "admin"} {
		if !strings.Contains(doc, guard) {
			t.Errorf("SECURITY.md does not mention %q among the admin routes' guards", guard)
		}
	}
}

// TestAdminMaintenancePutDefaultsTo24Hours: no `until` ends 24 h ahead,
// answers 200 with the end time, and the canary API then carries it.
func TestAdminMaintenancePutDefaultsTo24Hours(t *testing.T) {
	f := newAdminFixture(t)
	if got, ok := f.canaryJSON(t)["maintenance_until"]; !ok || got != nil {
		t.Fatalf("maintenance_until before = %v (present=%v), want present and null", got, ok)
	}
	rec := f.do(t, http.MethodPut, "/api/admin/canaries/canary-a/maintenance", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	want := f.now.Add(24 * time.Hour)
	var body struct {
		Until time.Time `json:"maintenance_until"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || !body.Until.Equal(want) {
		t.Fatalf("response %s (%v), want maintenance_until %v", rec.Body.String(), err, want)
	}
	got, _ := f.canaryJSON(t)["maintenance_until"].(string)
	if parsed, err := time.Parse(time.RFC3339, got); err != nil || !parsed.Equal(want) {
		t.Errorf("GET /api/canaries maintenance_until = %q, want %v", got, want)
	}
	if st := f.canaryJSON(t)["status"]; st == "silent" {
		t.Errorf("status = %v while in maintenance, want the silent warning quiet", st)
	}
}

// TestAdminMaintenancePutHonoursUntilUpToSevenDays: an `until` up to 7 days
// ahead is taken as given; 8 days, the past and nonsense are 400
// problem+json and change nothing.
func TestAdminMaintenancePutHonoursUntilUpToSevenDays(t *testing.T) {
	f := newAdminFixture(t)
	ok := f.now.Add(7 * 24 * time.Hour)
	rec := f.do(t, http.MethodPut, "/api/admin/canaries/canary-a/maintenance", `{"until":"`+ok.Format(time.RFC3339)+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT until +7d = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Until time.Time `json:"maintenance_until"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || !body.Until.Equal(ok) {
		t.Fatalf("response %s (%v), want maintenance_until %v", rec.Body.String(), err, ok)
	}

	for name, until := range map[string]string{
		"8 days ahead": f.now.Add(8 * 24 * time.Hour).Format(time.RFC3339),
		"in the past":  f.now.Add(-time.Hour).Format(time.RFC3339),
		"not a time":   "tomorrow",
		"just over 7d": f.now.Add(7*24*time.Hour + time.Minute).Format(time.RFC3339),
	} {
		f2 := newAdminFixture(t)
		rec := f2.do(t, http.MethodPut, "/api/admin/canaries/canary-a/maintenance", `{"until":"`+until+`"}`)
		assertProblem(t, rec, http.StatusBadRequest)
		if got := f2.canaryJSON(t)["maintenance_until"]; got != nil {
			t.Errorf("%s: maintenance_until = %v after a refused PUT, want null", name, got)
		}
		if n, _, _ := f2.auditRows(t, "canary.maintenance.set"); n != 0 {
			t.Errorf("%s: %d audit rows after a refused PUT, want 0", name, n)
		}
	}
}

// TestAdminMaintenanceDeleteClears: 204, maintenance_until back to null,
// and the silent warning returns.
func TestAdminMaintenanceDeleteClears(t *testing.T) {
	f := newAdminFixture(t)
	if rec := f.do(t, http.MethodPut, "/api/admin/canaries/canary-a/maintenance", ""); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d; body=%s", rec.Code, rec.Body.String())
	}
	rec := f.do(t, http.MethodDelete, "/api/admin/canaries/canary-a/maintenance", "")
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("DELETE = %d body=%q, want 204 and no body", rec.Code, rec.Body.String())
	}
	c := f.canaryJSON(t)
	if c["maintenance_until"] != nil || c["status"] != "silent" {
		t.Errorf("after DELETE: maintenance_until %v status %v, want null / silent", c["maintenance_until"], c["status"])
	}
}

// TestAdminRoutesUnknownCanary404: every route, problem+json, no side
// effects.
func TestAdminRoutesUnknownCanary404(t *testing.T) {
	f := newAdminFixture(t)
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/admin/canaries/nope/self-test"},
		{http.MethodPut, "/api/admin/canaries/nope/maintenance"},
		{http.MethodDelete, "/api/admin/canaries/nope/maintenance"},
	} {
		assertProblem(t, f.do(t, c.method, c.path, ""), http.StatusNotFound)
	}
	var n int
	if err := f.database.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action LIKE 'canary.%'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("canary audit rows after unknown-canary requests = %d, %v, want 0", n, err)
	}
}

// TestAdminSelfTestQueuesOnceWhileQueued: 202 each time; the second
// request answers with the queued run rather than adding one.
func TestAdminSelfTestQueuesOnceWhileQueued(t *testing.T) {
	f := newAdminFixture(t)
	var ids []string
	for i := 0; i < 2; i++ {
		rec := f.do(t, http.MethodPost, "/api/admin/canaries/canary-a/self-test", "")
		if rec.Code != http.StatusAccepted {
			t.Fatalf("POST #%d = %d, want 202; body=%s", i+1, rec.Code, rec.Body.String())
		}
		var body struct {
			CommandID string `json:"command_id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.CommandID == "" {
			t.Fatalf("POST #%d body %s (%v), want a command_id", i+1, rec.Body.String(), err)
		}
		ids = append(ids, body.CommandID)
	}
	if ids[0] != ids[1] {
		t.Errorf("second request answered %q, want the queued %q", ids[1], ids[0])
	}
	if len(f.runner.queued) != 1 || len(f.runner.calls) != 2 {
		t.Errorf("runner saw calls %v queued %v, want 2 calls for 1 queued run", f.runner.calls, f.runner.queued)
	}
}

// TestAdminWritesAuditWithActorAndTarget: each successful write leaves its
// row, target the canary id, triggered_by the signed-in username.
func TestAdminWritesAuditWithActorAndTarget(t *testing.T) {
	f := newAdminFixture(t)
	f.do(t, http.MethodPost, "/api/admin/canaries/canary-a/self-test", "")
	f.do(t, http.MethodPut, "/api/admin/canaries/canary-a/maintenance", "")
	f.do(t, http.MethodDelete, "/api/admin/canaries/canary-a/maintenance", "")
	for _, action := range []string{"canary.selftest.requested", "canary.maintenance.set", "canary.maintenance.cleared"} {
		n, target, by := f.auditRows(t, action)
		if n != 1 || target != "canary-a" || by != adminActor {
			t.Errorf("%s: %d rows, target %q, triggered_by %q, want 1 / canary-a / %s", action, n, target, by, adminActor)
		}
	}
}

// TestHitDuringMaintenanceIsStillReturnedByAlertsAPI: maintenance quiets
// health warnings, never what the canary reports. The hit is listed by
// GET /api/alerts and by the stream's source of truth, and once until
// passes (the handler's injected clock moves) the silent warning is back.
func TestHitDuringMaintenanceIsStillReturnedByAlertsAPI(t *testing.T) {
	f := newAdminFixture(t)
	until := f.now.Add(time.Hour)
	if rec := f.do(t, http.MethodPut, "/api/admin/canaries/canary-a/maintenance", `{"until":"`+until.Format(time.RFC3339)+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d; body=%s", rec.Code, rec.Body.String())
	}
	insertAlert(t, f.database, "canary-a", "203.0.113.9", 22, "ssh", f.now.Add(time.Minute).Format("2006-01-02T15:04:05Z"))

	alerts := func(h http.Handler) []store.Alert {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/alerts?instance=canary-a", nil))
		var resp alertsResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("GET /api/alerts = %d (%v); body=%s", rec.Code, err, rec.Body.String())
		}
		return resp.Alerts
	}
	if got := alerts(f.dash); len(got) != 1 || got[0].SourceIP != "203.0.113.9" {
		t.Fatalf("alerts during maintenance = %+v, want the hit", got)
	}
	if st := f.canaryJSON(t)["status"]; st == "silent" {
		t.Errorf("status during maintenance = %v, want quiet", st)
	}

	later := newHandler(f.database, fixedNow(until.Add(time.Minute)), nil)
	if got := alerts(later); len(got) != 1 {
		t.Errorf("alerts after until = %+v, want the hit still there", got)
	}
	rec := httptest.NewRecorder()
	later.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/canaries", nil))
	var resp struct {
		Canaries []map[string]any `json:"canaries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp.Canaries) != 1 {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if resp.Canaries[0]["status"] != "silent" || resp.Canaries[0]["maintenance_until"] != nil {
		t.Errorf("after until: status %v maintenance_until %v, want silent / null", resp.Canaries[0]["status"], resp.Canaries[0]["maintenance_until"])
	}
}

// TestCanaryPageCarriesMaintenanceUntil: GET /api/canary (the canary's own
// page) carries the field too: null, then the end time.
func TestCanaryPageCarriesMaintenanceUntil(t *testing.T) {
	f := newAdminFixture(t)
	get := func() map[string]any {
		rec := httptest.NewRecorder()
		f.dash.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/canary?id=canary-a", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/canary = %d; body=%s", rec.Code, rec.Body.String())
		}
		var m struct {
			Canary map[string]any `json:"canary"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return m.Canary
	}
	if m := get(); func() bool { v, ok := m["maintenance_until"]; return !ok || v != nil }() {
		t.Fatalf("maintenance_until before = %v, want present and null; body=%v", m["maintenance_until"], m)
	}
	f.do(t, http.MethodPut, "/api/admin/canaries/canary-a/maintenance", "")
	if got, _ := get()["maintenance_until"].(string); got != f.now.Add(24*time.Hour).Format(time.RFC3339) {
		t.Errorf("maintenance_until = %q, want %q", got, f.now.Add(24*time.Hour).Format(time.RFC3339))
	}
}
