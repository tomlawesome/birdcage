package ingest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

func mintToken(t *testing.T, database *db.DB, canaryID string) string {
	t.Helper()
	raw, _, err := store.MintCanaryToken(context.Background(), database, canaryID, time.Now().UTC())
	if err != nil {
		t.Fatalf("MintCanaryToken: %v", err)
	}
	return raw
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
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

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
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)
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
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

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
// registers POST /ingest/events (nor, as of slice 5, /ingest/rotate) at
// all, so no token, valid or otherwise, reaches ingest logic through it;
// presenting one changes nothing.
func TestDashboardMuxCannotReachIngestRoute(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		dashboard := api.NewHandler(database, nil)

		for _, path := range []string{"/ingest/events", "/ingest/rotate"} {
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
