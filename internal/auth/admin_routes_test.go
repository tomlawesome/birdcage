package auth_test

import (
	"net/http"
	"strings"
	"testing"
)

// adminRoute is one of the admin write routes (#227), against the canary
// seedCanary inserts.
type adminRoute struct {
	method, path string
	okStatus     int
}

var adminRoutes = []adminRoute{
	{http.MethodPost, "/api/admin/canaries/scanner-a/self-test", http.StatusAccepted},
	{http.MethodPut, "/api/admin/canaries/scanner-a/maintenance", http.StatusOK},
	{http.MethodDelete, "/api/admin/canaries/scanner-a/maintenance", http.StatusNoContent},
}

// adminCall sends one admin request with exactly the given headers.
func adminCall(t *testing.T, c *http.Client, base string, r adminRoute, header map[string]string) (int, string) {
	t.Helper()
	status, body := call(t, c, r.method, base+r.path, nil, header)
	return status, string(body)
}

func originOf(s *system) map[string]string {
	return map[string]string{csrfHeader: csrfValue, "Origin": s.server.URL}
}

// TestAdminRoutesRefuseATokenWith404: the admin routes live on the
// session side of Wrap only, so a read token (which Wrap answers from the
// dashboard handler) finds nothing there: 404 on every route and method,
// and nothing is queued.
func TestAdminRoutesRefuseATokenWith404(t *testing.T) {
	database := openDatabase(t)
	seedCanary(t, database)
	sys, runner := startAdminSystem(t, database, testKey('a'))
	admin := sys.signInFirstAdmin(t)
	token := sys.mintReadToken(t, admin)

	for _, r := range adminRoutes {
		header := originOf(sys)
		header["Authorization"] = "Bearer " + token
		status, body := adminCall(t, newClient(t), sys.server.URL, r, header)
		if status != http.StatusNotFound {
			t.Errorf("%s %s with a read token: status %d, want 404; body=%s", r.method, r.path, status, body)
		}
	}
	if len(runner.calls) != 0 {
		t.Errorf("self-test run-now calls after token requests = %v, want none", runner.calls)
	}
}

// TestAdminRoutesNeedASession: no credential at all is 401, as for the
// rest of /api/.
func TestAdminRoutesNeedASession(t *testing.T) {
	database := openDatabase(t)
	seedCanary(t, database)
	sys, _ := startAdminSystem(t, database, testKey('a'))
	sys.registerFirstAdmin(t, newClient(t))
	for _, r := range adminRoutes {
		if status, body := adminCall(t, newClient(t), sys.server.URL, r, originOf(sys)); status != http.StatusUnauthorized {
			t.Errorf("%s %s with no session: status %d, want 401; body=%s", r.method, r.path, status, body)
		}
	}
}

// TestAdminRoutesCSRFAndOriginChecks: a signed-in admin's cookie request
// is refused (403, problem+json) without X-Requested-With, with a foreign
// Origin, and with neither Origin nor Sec-Fetch-Site: same-origin; it is
// accepted with the right Origin, or with no Origin and same-origin
// Fetch Metadata. A refusal changes nothing.
func TestAdminRoutesCSRFAndOriginChecks(t *testing.T) {
	database := openDatabase(t)
	seedCanary(t, database)
	sys, runner := startAdminSystem(t, database, testKey('a'))
	admin := sys.signInFirstAdmin(t)

	refused := map[string]map[string]string{
		"no X-Requested-With":              {"Origin": sys.server.URL},
		"wrong X-Requested-With":           {csrfHeader: "mikroview", "Origin": sys.server.URL},
		"foreign Origin":                   {csrfHeader: csrfValue, "Origin": "https://evil.example.net"},
		"foreign Origin, same-origin hint": {csrfHeader: csrfValue, "Origin": "https://evil.example.net", "Sec-Fetch-Site": "same-origin"},
		"no Origin, cross-site":            {csrfHeader: csrfValue, "Sec-Fetch-Site": "cross-site"},
		"no Origin, same-site":             {csrfHeader: csrfValue, "Sec-Fetch-Site": "same-site"},
		"no Origin, no Fetch Metadata":     {csrfHeader: csrfValue},
	}
	for name, header := range refused {
		for _, r := range adminRoutes {
			status, body := adminCall(t, admin, sys.server.URL, r, header)
			if status != http.StatusForbidden {
				t.Errorf("%s %s (%s): status %d, want 403; body=%s", r.method, r.path, name, status, body)
			}
		}
	}
	if len(runner.calls) != 0 {
		t.Fatalf("run-now calls after refused requests = %v, want none", runner.calls)
	}

	accepted := map[string]map[string]string{
		"matching Origin":                        originOf(sys),
		"no Origin, Sec-Fetch-Site: same-origin": {csrfHeader: csrfValue, "Sec-Fetch-Site": "same-origin"},
	}
	for name, header := range accepted {
		for _, r := range adminRoutes {
			if status, body := adminCall(t, admin, sys.server.URL, r, header); status != r.okStatus {
				t.Errorf("%s %s (%s): status %d, want %d; body=%s", r.method, r.path, name, status, r.okStatus, body)
			}
		}
	}
}

// TestAdminRoutesRefuseANonAdminWith403: a signed-in account that is not
// an admin gets 403 on every admin route even with a perfect request.
func TestAdminRoutesRefuseANonAdminWith403(t *testing.T) {
	database := openDatabase(t)
	seedCanary(t, database)
	sys, runner := startAdminSystem(t, database, testKey('a'))
	admin := sys.signInFirstAdmin(t)
	plain := sys.signInPlainUser(t, admin)

	for _, r := range adminRoutes {
		status, body := adminCall(t, plain, sys.server.URL, r, originOf(sys))
		if status != http.StatusForbidden {
			t.Errorf("%s %s as a non-admin: status %d, want 403; body=%s", r.method, r.path, status, body)
		}
	}
	if len(runner.calls) != 0 {
		t.Errorf("run-now calls by a non-admin = %v, want none", runner.calls)
	}
}

// TestAdminRefusalsAreProblemJSON: errors are RFC 9457 problem+json.
func TestAdminRefusalsAreProblemJSON(t *testing.T) {
	database := openDatabase(t)
	seedCanary(t, database)
	sys, _ := startAdminSystem(t, database, testKey('a'))
	admin := sys.signInFirstAdmin(t)

	req, err := http.NewRequest(http.MethodPost, sys.server.URL+adminRoutes[0].path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "https://evil.example.net")
	req.Header.Set(csrfHeader, csrfValue)
	resp, err := admin.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
}

// TestAdminWritesAreAuditedWithTheSignedInUsername: each write through
// the whole stack leaves its row, target the canary id, triggered_by the
// signed-in username.
func TestAdminWritesAreAuditedWithTheSignedInUsername(t *testing.T) {
	database := openDatabase(t)
	seedCanary(t, database)
	sys, _ := startAdminSystem(t, database, testKey('a'))
	admin := sys.signInFirstAdmin(t)

	want := []string{"canary.selftest.requested", "canary.maintenance.set", "canary.maintenance.cleared"}
	for i, r := range adminRoutes {
		if status, body := adminCall(t, admin, sys.server.URL, r, originOf(sys)); status != r.okStatus {
			t.Fatalf("%s %s: status %d, want %d; body=%s", r.method, r.path, status, r.okStatus, body)
		}
		var target, by string
		row := database.QueryRow(`SELECT target, triggered_by FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1`, want[i])
		if err := row.Scan(&target, &by); err != nil {
			t.Fatalf("no %s audit row after %s %s: %v", want[i], r.method, r.path, err)
		}
		if target != "scanner-a" || by != testAdminName {
			t.Errorf("%s audit row: target %q triggered_by %q, want scanner-a / %s", want[i], target, by, testAdminName)
		}
	}
}
