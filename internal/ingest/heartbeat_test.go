package ingest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// enrollCanary registers id as a Honeypot -- the kind almost every test
// in this package wants; enrollCanaryKind is the same with the kind
// explicit, for scans_test.go's scanner-only route.
func enrollCanary(t *testing.T, database *db.DB, id string) {
	t.Helper()
	enrollCanaryKind(t, database, id, agentkind.Honeypot)
}

func enrollCanaryKind(t *testing.T, database *db.DB, id string, kind agentkind.Kind) {
	t.Helper()
	if err := store.InsertCanary(context.Background(), database, store.Canary{
		ID: id, Name: id, Lane: "lan", Kind: kind, EnrolledAt: time.Now().UTC(),
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

// TestHandleHeartbeatStoresExtendedSelfReportFields is #48's
// process-composition note, gap 3: the dropped/rejected/event-id-collision
// counters and the position-found flag round-trip into storage exactly
// like TestHandleHeartbeatStoresSelfReportFields's own original four.
func TestHandleHeartbeatStoresExtendedSelfReportFields(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		body := `{"queue_depth":7,"log_read_ok":true,"last_event_id":"` + validEventID1 + `","agent_version":"1.2.3",` +
			`"dropped":3,"rejected":2,"event_id_collisions":0,"position_found":true}`
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/heartbeat", raw, body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		var dropped, rejected, collisions, positionFound *int64
		row := database.QueryRow(
			`SELECT agent_dropped, agent_rejected, agent_event_id_collisions, agent_position_found FROM canaries WHERE id = ?`,
			"canary-a")
		if err := row.Scan(&dropped, &rejected, &collisions, &positionFound); err != nil {
			t.Fatalf("scan extended self-report columns: %v", err)
		}
		if dropped == nil || *dropped != 3 {
			t.Errorf("agent_dropped = %v, want 3", dropped)
		}
		if rejected == nil || *rejected != 2 {
			t.Errorf("agent_rejected = %v, want 2", rejected)
		}
		if collisions == nil || *collisions != 0 {
			t.Errorf("agent_event_id_collisions = %v, want 0 (explicitly reported, not absent)", collisions)
		}
		if positionFound == nil || *positionFound != 1 {
			t.Errorf("agent_position_found = %v, want 1 (true)", positionFound)
		}
	})
}

// TestHandleHeartbeatOldShapeAcceptedWithoutFabricatingZeroes is #48's
// central compatibility rule: an agent built before this change (or
// mid-rollout) sends only the original four fields. That body is a
// subset, not an unknown field, so DisallowUnknownFields still accepts
// it -- and the new columns must land as SQL NULL ("no news"), never as
// an explicit zero/false, which would misreport "this agent has dropped
// nothing" when the agent has in fact said nothing about drops at all.
func TestHandleHeartbeatOldShapeAcceptedWithoutFabricatingZeroes(t *testing.T) {
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

		var dropped, rejected, collisions, positionFound *int64
		row := database.QueryRow(
			`SELECT agent_dropped, agent_rejected, agent_event_id_collisions, agent_position_found FROM canaries WHERE id = ?`,
			"canary-a")
		if err := row.Scan(&dropped, &rejected, &collisions, &positionFound); err != nil {
			t.Fatalf("scan extended self-report columns: %v", err)
		}
		if dropped != nil || rejected != nil || collisions != nil || positionFound != nil {
			t.Errorf("extended self-report columns = (%v, %v, %v, %v), want all NULL for an old-shape heartbeat, not fabricated zeroes",
				dropped, rejected, collisions, positionFound)
		}

		canaries, err := store.ListCanaries(context.Background(), database, time.Now().UTC(), 24*time.Hour)
		if err != nil {
			t.Fatalf("ListCanaries: %v", err)
		}
		c := findCanaryByID(t, canaries, "canary-a")
		if c.AgentDropped != nil || c.AgentRejected != nil || c.AgentEventIDCollisions != nil || c.AgentPositionFound != nil {
			t.Errorf("Canary extended self-report fields = (%v, %v, %v, %v), want all nil for an old-shape heartbeat",
				c.AgentDropped, c.AgentRejected, c.AgentEventIDCollisions, c.AgentPositionFound)
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

// TestHandleHeartbeatScannerCommonShapeStored is issue #106's own
// required proof for the per-kind body split: a Scanner-kind token's
// heartbeat is decoded as the common-only shape and stored through
// store.RecordCanaryCommonHeartbeat, advancing last-seen and
// agent_version exactly like a Honeypot's own heartbeat does.
func TestHandleHeartbeatScannerCommonShapeStored(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-scanner", agentkind.Scanner)
		raw := mintTokenForKind(t, database, "canary-scanner", agentkind.Scanner)
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/heartbeat", raw, `{"agent_version":"9.9.9"}`))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		var (
			version         string
			lastHeartbeatAt *string
		)
		row := database.QueryRow(`SELECT agent_version, last_heartbeat_at FROM canaries WHERE id = ?`, "canary-scanner")
		if err := row.Scan(&version, &lastHeartbeatAt); err != nil {
			t.Fatalf("scan canaries row: %v", err)
		}
		if version != "9.9.9" {
			t.Errorf("agent_version = %q, want %q", version, "9.9.9")
		}
		if lastHeartbeatAt == nil {
			t.Error("last_heartbeat_at is nil, want it advanced")
		}
	})
}

// TestHandleHeartbeatScannerRejectsLogTailerFields proves
// ingestCommonHeartbeat's own DisallowUnknownFields: a Scanner-kind
// token sending queue_depth or log_read_ok would be lying about having a
// log tailer at all, and the decoder refuses it outright rather than the
// handler needing a bespoke field-by-field check.
func TestHandleHeartbeatScannerRejectsLogTailerFields(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-scanner", agentkind.Scanner)
		raw := mintTokenForKind(t, database, "canary-scanner", agentkind.Scanner)
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		for _, body := range []string{`{"queue_depth":5}`, `{"log_read_ok":true}`} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/heartbeat", raw, body))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("body %s: status = %d, want %d (body %q)", body, rec.Code, http.StatusBadRequest, rec.Body.String())
			}
		}
	})
}

// TestHandleHeartbeatUnknownCanaryReturns403AtTheSeam used to prove
// handleHeartbeat's own 404 for a live token whose canaries row is
// missing (canary_tokens carries no foreign key into canaries --
// 0004_canary_tokens.sql's own comment -- so that is a real, distinct
// case from birdcage's own storage trouble). Issue #106 moves that
// refusal earlier: LookupCanaryTokenByHash's LEFT JOIN resolves such a
// token with Kind == "", which the registry kind check refuses before
// the request ever reaches handleHeartbeat at all (design note section
// 7's own trap, called out deliberately in this package's commit
// history) -- 403 "forbidden" now, never handleHeartbeat's 404. The 404
// path in handleHeartbeat itself is dead code against a live token as of
// this commit; it stays, defended, for a token store bug that resolved
// one anyway.
//
// mintToken is not used here on purpose: it would register the canary
// (issue #106's own default), which is exactly the row this test needs
// absent.
func TestHandleHeartbeatUnknownCanaryReturns403AtTheSeam(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw, _, err := store.MintCanaryToken(context.Background(), database, "canary-never-enrolled", time.Now().UTC())
		if err != nil {
			t.Fatalf("MintCanaryToken: %v", err)
		}
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/heartbeat", raw, `{"agent_version":"1.0.0"}`))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusForbidden, rec.Body.String())
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
