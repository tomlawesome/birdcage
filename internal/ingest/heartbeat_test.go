package ingest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

func enrollCanary(t *testing.T, database *db.DB, id string) {
	t.Helper()
	if err := store.InsertCanary(context.Background(), database, store.Canary{
		ID: id, Name: id, Lane: "lan", EnrolledAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("InsertCanary(%s): %v", id, err)
	}
}

func findCanaryByID(t *testing.T, canaries []store.Canary, id string) store.Canary {
	t.Helper()
	for _, c := range canaries {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no canary %q in %+v", id, canaries)
	return store.Canary{}
}

// TestHandleHeartbeatRequiresCanaryToken is #32 slice 5a's first
// required test: "a heartbeat without a canary token is refused".
func TestHandleHeartbeatRequiresCanaryToken(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/heartbeat", "", `{"agent_version":"1.0.0"}`))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})
}

// TestHandleHeartbeatIdentityIsAlwaysTheTokens is slice 5a's second
// required test: "the canary is the token's, whatever the body says".
func TestHandleHeartbeatIdentityIsAlwaysTheTokens(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		enrollCanary(t, database, "canary-b")
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		body := `{"canary_id":"canary-b","agent_version":"1.0.0"}`
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/heartbeat", raw, body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		canaries, err := store.ListCanaries(context.Background(), database, time.Now().UTC(), 24*time.Hour)
		if err != nil {
			t.Fatalf("ListCanaries: %v", err)
		}
		a := findCanaryByID(t, canaries, "canary-a")
		if a.LastHeartbeatAt == nil {
			t.Fatal("canary-a (the token's canary) has no recorded heartbeat")
		}
		b := findCanaryByID(t, canaries, "canary-b")
		if b.LastHeartbeatAt != nil {
			t.Fatal("canary-b (the payload's claimed identity) recorded a heartbeat; identity must come from the token")
		}
	})
}

// TestHandleHeartbeatStoresSelfReportFields is slice 5a's third required
// test: "the self-report fields are stored for #45".
func TestHandleHeartbeatStoresSelfReportFields(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		body := `{"queue_depth":7,"log_read_ok":true,"last_event_id":"` + validEventID1 + `","agent_version":"1.2.3"}`
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/heartbeat", raw, body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		var (
			version    string
			queueDepth int
			logReadOK  int
			lastEvent  string
		)
		row := database.QueryRow(
			`SELECT agent_version, agent_queue_depth, agent_log_read_ok, agent_last_event_id FROM canaries WHERE id = ?`,
			"canary-a")
		if err := row.Scan(&version, &queueDepth, &logReadOK, &lastEvent); err != nil {
			t.Fatalf("scan self-report columns: %v", err)
		}
		if version != "1.2.3" || queueDepth != 7 || logReadOK != 1 || lastEvent != validEventID1 {
			t.Errorf("stored self-report = (%q, %d, %d, %q), want (\"1.2.3\", 7, 1, %q)",
				version, queueDepth, logReadOK, lastEvent, validEventID1)
		}
	})
}

// TestHandleHeartbeatInvalidBodyDoesNotAdvanceLastSeen is slice 5a's
// fourth statement, drawn directly from issue #32's fail-closed section:
// "invalid heartbeat body -> 4xx, and the canary's last-seen does NOT
// advance -- a broken agent must look broken, never healthy".
func TestHandleHeartbeatInvalidBodyDoesNotAdvanceLastSeen(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/heartbeat", raw, `{"queue_depth":"not-a-number"}`))
		if rec.Code < 400 || rec.Code >= 500 {
			t.Fatalf("status = %d, want a 4xx (body %q)", rec.Code, rec.Body.String())
		}

		var lastHeartbeat *string
		row := database.QueryRow(`SELECT last_heartbeat_at FROM canaries WHERE id = ?`, "canary-a")
		if err := row.Scan(&lastHeartbeat); err != nil {
			t.Fatalf("scan last_heartbeat_at: %v", err)
		}
		if lastHeartbeat != nil {
			t.Fatalf("last_heartbeat_at = %v after an invalid heartbeat body, want unchanged (nil, never beaten)", *lastHeartbeat)
		}
	})
}

// TestHandleHeartbeatUnknownFieldRejected mirrors the batch endpoint's
// own DisallowUnknownFields behavior (TestHandleBatchRejectsUnknownField)
// for consistency across this package's two JSON-bodied routes.
func TestHandleHeartbeatUnknownFieldRejected(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/heartbeat", raw, `{"unexpected_field":true}`))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	})
}

// TestHandleHeartbeatUnknownCanaryReturns404 mirrors internal/api's own
// handleHeartbeat: canary_tokens carries no foreign key into canaries
// (0004_canary_tokens.sql's own comment), so a live token for an
// unregistered canary id is a real, distinct case from birdcage's own
// storage trouble.
func TestHandleHeartbeatUnknownCanaryReturns404(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-never-enrolled")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/heartbeat", raw, `{"agent_version":"1.0.0"}`))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusNotFound, rec.Body.String())
		}
	})
}

// TestHandleHeartbeatOverLimitReturns429AndIsRecorded proves #32's fix
// for this route having no rate limit at all: previously only
// handleBatch charged the per-canary requests/min cap (item 8), so a
// compromised canary's token could flood POST /ingest/heartbeat freely.
// The charge now lives in the shared requireBearerToken wrapper, so this
// route is covered too.
func TestHandleHeartbeatOverLimitReturns429AndIsRecorded(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		raw := mintToken(t, database, "canary-a")
		tiny := limiterLimits{RequestsPerMinute: 2, EventsPerMinute: 60000}
		h := newHandler(database, nil, time.Now, tiny)
		body := `{"agent_version":"1.0.0"}`

		var last *httptest.ResponseRecorder
		for i := 0; i < 3; i++ {
			last = httptest.NewRecorder()
			h.ServeHTTP(last, ingestRequest(http.MethodPost, "/ingest/heartbeat", raw, body))
		}
		if last.Code != http.StatusTooManyRequests {
			t.Fatalf("3rd heartbeat status = %d, want %d (body %q)", last.Code, http.StatusTooManyRequests, last.Body.String())
		}

		if got := countAuditRows(t, database, "ingest.rate_limited", "canary-a"); got == 0 {
			t.Fatal("no audit_log row recorded for the rate limit crossing on heartbeat")
		}
	})
}
