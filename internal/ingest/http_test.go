package ingest

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/api"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/db/dbtest"
	"github.com/tomlawesome/birdcage/internal/store"
)

// forEachEngine mirrors internal/store's own helper (store_test.go):
// every ingest test that touches the database runs once per engine
// dbtest.Targets returns, so a Postgres-only failure is reported
// distinctly from SQLite's.
func forEachEngine(t *testing.T, fn func(t *testing.T, database *db.DB)) {
	t.Helper()
	for _, tgt := range dbtest.Targets(t) {
		tgt := tgt
		t.Run(tgt.Name, func(t *testing.T) {
			fn(t, tgt.DB)
		})
	}
}

// mintToken mints a bearer token for canaryID, registering canaryID as a
// Honeypot (the kind almost every test in this package wants -- a
// scanner-shaped test uses mintTokenForKind directly) unless a canaries
// row already exists for it. Issue #106's registry kind check means
// every route on this mux now refuses a token whose canary is
// unregistered, so a test minting a token has to have a row behind it to
// reach its handler at all -- ensureCanary makes that the default
// instead of a per-call chore, while staying a no-op for a test that
// already registered the canary itself (heartbeat_test.go's enrollCanary
// and scans_test.go's enrollCanaryKind, both called before mintToken in
// several tests).
func mintToken(t *testing.T, database *db.DB, canaryID string) string {
	t.Helper()
	return mintTokenForKind(t, database, canaryID, agentkind.Honeypot)
}

// mintTokenForKind is mintToken with the registered kind explicit, for a
// test that needs something other than Honeypot (scans_test.go's
// scanner-only route).
func mintTokenForKind(t *testing.T, database *db.DB, canaryID string, kind agentkind.Kind) string {
	t.Helper()
	ensureCanary(t, database, canaryID, kind)
	raw, _, err := store.MintCanaryToken(context.Background(), database, canaryID, time.Now().UTC())
	if err != nil {
		t.Fatalf("MintCanaryToken: %v", err)
	}
	return raw
}

// ensureCanary registers canaryID with kind if (and only if) no canaries
// row for it exists yet -- idempotent, so a test that already called
// enrollCanary/enrollCanaryKind for canaryID before minting a token
// doesn't collide with a second, conflicting insert here.
func ensureCanary(t *testing.T, database *db.DB, canaryID string, kind agentkind.Kind) {
	t.Helper()
	var exists int
	err := database.QueryRow(`SELECT 1 FROM canaries WHERE id = ?`, canaryID).Scan(&exists)
	if err == nil {
		return // already registered -- including with a different kind, which the caller asked for by registering it itself first.
	}
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("check canary %s exists: %v", canaryID, err)
	}
	if err := store.InsertCanary(context.Background(), database, store.Canary{
		ID: canaryID, Name: canaryID, Lane: "lan", Kind: kind, EnrolledAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("InsertCanary(%s): %v", canaryID, err)
	}
}

func revokeAllTokens(t *testing.T, database *db.DB, canaryID string) {
	t.Helper()
	rows, err := database.Query(`SELECT id FROM canary_tokens WHERE canary_id = ?`, canaryID)
	if err != nil {
		t.Fatalf("query token ids: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan token id: %v", err)
		}
		ids = append(ids, id)
	}
	for _, id := range ids {
		if err := store.RevokeCanaryToken(context.Background(), database, id, time.Now().UTC()); err != nil {
			t.Fatalf("RevokeCanaryToken: %v", err)
		}
	}
}

func batchRequest(token, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/ingest/events", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// TestIngestAuthDatabaseFailureIsRetryableNot401: #32's fail-closed
// rule says an infrastructure failure is never reported as a rejection.
// A 401 is permanent to the agent, so a database problem answered with
// one would look to every canary like a dead credential; it must be a
// 503 the agent retries instead.
func TestIngestAuthDatabaseFailureIsRetryableNot401(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		token := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		// Closing the handle is how this test reaches the lookup's
		// error path; dbtest's own cleanup closing it again is a no-op.
		if err := database.Close(); err != nil {
			t.Fatalf("close database: %v", err)
		}

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, batchRequest(token, `{"events":[]}`))

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want %d: a database failure is retryable, not a rejected credential",
				rec.Code, http.StatusServiceUnavailable)
		}
	})
}

// TestIngestAuthRejectsMissingUnknownAndRevokedTokens is #32 slice 2's
// first required test: "missing, unknown and revoked tokens all get
// 401".
func TestIngestAuthRejectsMissingUnknownAndRevokedTokens(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)
		validBody := `{"events":[]}`

		cases := []struct {
			name  string
			token string
		}{
			{"missing", ""},
			{"unknown", "not-a-real-token"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, batchRequest(tc.token, validBody))
				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusUnauthorized, rec.Body.String())
				}
			})
		}

		t.Run("revoked", func(t *testing.T) {
			raw := mintToken(t, database, "canary-revoked")
			revokeAllTokens(t, database, "canary-revoked")

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, batchRequest(raw, validBody))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusUnauthorized, rec.Body.String())
			}
		})
	})
}

// TestIngestMuxCannotReachDashboardRoutes is half of slice 2's structural
// test: "a dashboard session cannot reach the route" -- read here as
// "the ingest mux never serves a dashboard path", since the two are
// never the same mux or the same *http.Server (see NewHandler's doc
// comment) and there is, as yet, no dashboard session at all (#8 is
// still a placeholder no-op).
func TestIngestMuxCannotReachDashboardRoutes(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		for _, path := range []string{"/api/alerts", "/api/heartbeat", "/api/stream", "/"} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusNotFound {
				t.Errorf("ingest mux GET %s = %d, want %d (dashboard route reachable from ingest mux)", path, rec.Code, http.StatusNotFound)
			}
		}
	})
}

// TestDashboardMuxCannotReachIngestRoute is the other half: "the ingest
// token cannot reach a dashboard route" -- the dashboard mux never
// registers POST /ingest/events (nor, as of slices 5/5a/5b,
// /ingest/rotate, /ingest/heartbeat or /ingest/commands) at all, so no token, valid or otherwise, reaches
// ingest logic through it; presenting one changes nothing.
func TestDashboardMuxCannotReachIngestRoute(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		dashboard := api.NewHandler(database, nil)

		for _, path := range []string{"/ingest/events", "/ingest/rotate", "/ingest/heartbeat", "/ingest/commands"} {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
			req.Header.Set("Authorization", "Bearer "+raw)
			rec := httptest.NewRecorder()
			dashboard.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("dashboard mux POST %s (with a valid ingest token) = %d, want %d", path, rec.Code, http.StatusNotFound)
			}
		}
	})
}

// TestEveryIngestRouteNamesARegisteredKind is issue #106's own required
// package test (design note section 2): ingestRoute's zero value for
// kinds refuses every request, on purpose -- a route added without
// thinking about kinds fails closed rather than open. This test is what
// catches the *other* way that could go wrong unnoticed: a route that
// compiles with kinds set, but to something that doesn't actually name a
// registered kind (a typo, a kind that was renamed elsewhere). Every
// entry ingestRoutes returns must name at least one kind, and every kind
// it names must be one agentkind.Valid recognizes.
func TestEveryIngestRouteNamesARegisteredKind(t *testing.T) {
	h := &ingestHandler{}
	for _, route := range ingestRoutes(h) {
		if len(route.kinds) == 0 {
			t.Errorf("route %s names no kind -- it refuses every request by construction; give it at least one registered kind", route.pattern)
			continue
		}
		for _, k := range route.kinds {
			if !agentkind.Valid(k) {
				t.Errorf("route %s names unregistered kind %q", route.pattern, k)
			}
		}
	}
}
