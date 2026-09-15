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

// TestIngestAuthRejectsMissingUnknownAndRevokedTokens is #32 slice 2's
// first required test: "missing, unknown and revoked tokens all get
// 401".
func TestIngestAuthRejectsMissingUnknownAndRevokedTokens(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		h := newHandler(database, nil, time.Now)
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
		h := newHandler(database, nil, time.Now)

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
// registers POST /ingest/events at all, so no token, valid or otherwise,
// reaches ingest logic through it; presenting one changes nothing.
func TestDashboardMuxCannotReachIngestRoute(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		dashboard := api.NewHandler(database, nil)

		req := httptest.NewRequest(http.MethodPost, "/ingest/events", strings.NewReader(`{"events":[]}`))
		req.Header.Set("Authorization", "Bearer "+raw)
		rec := httptest.NewRecorder()
		dashboard.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("dashboard mux POST /ingest/events (with a valid ingest token) = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})
}
