package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

func validEventJSON(eventID string) string {
	return fmt.Sprintf(`{"event_id":%q,"source_ip":"203.0.113.9","dest_port":22,"service":"ssh","raw":"hit"}`, eventID)
}

const (
	validEventID1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	validEventID2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// TestHandleBatchRejectsOversizedBody is #32 slice 3's first required
// test: "oversized body rejected".
func TestHandleBatchRejectsOversizedBody(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		oversizedRaw := strings.Repeat("x", maxBodyBytes+1)
		body := fmt.Sprintf(`{"events":[{"event_id":%q,"source_ip":"203.0.113.9","dest_port":22,"service":"ssh","raw":%q}]}`,
			validEventID1, oversizedRaw)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, batchRequest(raw, body))
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusRequestEntityTooLarge, rec.Body.String())
		}
	})
}

// TestHandleBatchRejectsUnknownField is slice 3's second required test:
// "unknown field rejected".
func TestHandleBatchRejectsUnknownField(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		body := fmt.Sprintf(`{"events":[%s],"unexpected_field":true}`, validEventJSON(validEventID1))

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, batchRequest(raw, body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	})
}

// TestHandleBatchOverLimitReturns429AndIsRecorded is slice 3's third
// required test: "over-limit returns 429 and is recorded". It uses a
// tiny requests/min limit (via newHandler's injectable limiterLimits, not
// defaultLimiterLimits) so the cap is crossed in three calls instead of
// three thousand.
func TestHandleBatchOverLimitReturns429AndIsRecorded(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		tiny := limiterLimits{RequestsPerMinute: 2, EventsPerMinute: 60000}
		h := newHandler(database, nil, time.Now, tiny)
		body := fmt.Sprintf(`{"events":[%s]}`, validEventJSON(validEventID1))

		var last *httptest.ResponseRecorder
		for i := 0; i < 3; i++ {
			last = httptest.NewRecorder()
			h.ServeHTTP(last, batchRequest(raw, body))
		}
		if last.Code != http.StatusTooManyRequests {
			t.Fatalf("3rd request status = %d, want %d (body %q)", last.Code, http.StatusTooManyRequests, last.Body.String())
		}

		var count int
		row := database.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = ? AND target = ?`,
			"ingest.rate_limited", "canary-a")
		if err := row.Scan(&count); err != nil {
			t.Fatalf("count audit_log rows: %v", err)
		}
		if count == 0 {
			t.Fatal("no audit_log row recorded for the rate limit crossing")
		}
	})
}

// TestHandleBatchOneBadEventRejectedRestStored is slice 3's fourth
// required test: "one bad event in a batch is rejected by id and the
// rest stored".
func TestHandleBatchOneBadEventRejectedRestStored(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		badEventID := "not-a-valid-event-id"
		body := fmt.Sprintf(`{"events":[%s,{"event_id":%q,"source_ip":"203.0.113.9","dest_port":22,"service":"ssh","raw":"hit"}]}`,
			validEventJSON(validEventID1), badEventID)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, batchRequest(raw, body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		var resp ackResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if len(resp.Stored) != 1 || resp.Stored[0] != validEventID1 {
			t.Errorf("stored = %v, want [%s]", resp.Stored, validEventID1)
		}
		if reason, rejected := resp.Rejected[badEventID]; !rejected || reason == "" {
			t.Errorf("rejected = %v, want an entry for %s", resp.Rejected, badEventID)
		}

		var alertCount int
		row := database.QueryRow(`SELECT COUNT(*) FROM alerts WHERE instance_id = ?`, "canary-a")
		if err := row.Scan(&alertCount); err != nil {
			t.Fatalf("count alerts: %v", err)
		}
		if alertCount != 1 {
			t.Errorf("alerts stored for canary-a = %d, want 1 (only the good event)", alertCount)
		}
	})
}

// TestHandleBatchPayloadNodeIDMismatchStoresUnderTokenCanary is #32
// slice 4's first required test: "a payload naming another canary is
// stored against the token's canary".
func TestHandleBatchPayloadNodeIDMismatchStoresUnderTokenCanary(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		body := fmt.Sprintf(`{"node_id":"canary-b","events":[%s]}`, validEventJSON(validEventID1))

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, batchRequest(raw, body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		alerts, err := store.ListAlerts(context.Background(), database, store.AlertFilter{InstanceID: "canary-a"})
		if err != nil {
			t.Fatalf("ListAlerts(canary-a): %v", err)
		}
		if len(alerts) != 1 {
			t.Fatalf("canary-a (the token's canary) alerts = %d, want 1", len(alerts))
		}

		spoofed, err := store.ListAlerts(context.Background(), database, store.AlertFilter{InstanceID: "canary-b"})
		if err != nil {
			t.Fatalf("ListAlerts(canary-b): %v", err)
		}
		if len(spoofed) != 0 {
			t.Fatalf("canary-b (the payload's claimed, untrusted identity) alerts = %d, want 0", len(spoofed))
		}
	})
}

// TestHandleBatchAckListsExactlyStoredAndRejected is #32 slice 4's
// second required test: "the response lists exactly the ids stored and
// rejected" -- every event id sent appears in exactly one of the two
// lists, with nothing missing and nothing extra.
func TestHandleBatchAckListsExactlyStoredAndRejected(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		goodID := validEventID1
		badID := "not-a-valid-event-id"
		body := fmt.Sprintf(`{"events":[%s,{"event_id":%q,"source_ip":"203.0.113.9","dest_port":22,"service":"ssh","raw":"hit"}]}`,
			validEventJSON(goodID), badID)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, batchRequest(raw, body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}
		var resp ackResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}

		named := map[string]bool{}
		for _, id := range resp.Stored {
			if named[id] {
				t.Fatalf("event id %q named more than once in stored", id)
			}
			named[id] = true
		}
		for id := range resp.Rejected {
			if named[id] {
				t.Fatalf("event id %q present in both stored and rejected", id)
			}
			named[id] = true
		}
		want := map[string]bool{goodID: true, badID: true}
		if len(named) != len(want) {
			t.Fatalf("ack named %d distinct ids %v, want exactly %v", len(named), named, want)
		}
		for id := range want {
			if !named[id] {
				t.Errorf("ack response never named event id %q", id)
			}
		}
	})
}

// TestHandleBatchSameMultiEventBatchTwiceStoresOneCopyEach is #32 slice
// 4's third required test: "the same batch sent twice stores one copy" --
// exercised here with a multi-event batch, distinct from
// TestHandleBatchDuplicateEventIDAcksAsStored's single-event case.
func TestHandleBatchSameMultiEventBatchTwiceStoresOneCopyEach(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		body := fmt.Sprintf(`{"events":[%s,%s]}`, validEventJSON(validEventID1), validEventJSON(validEventID2))

		for i := 0; i < 2; i++ {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, batchRequest(raw, body))
			if rec.Code != http.StatusOK {
				t.Fatalf("attempt %d: status = %d, want %d (body %q)", i, rec.Code, http.StatusOK, rec.Body.String())
			}
		}

		alerts, err := store.ListAlerts(context.Background(), database, store.AlertFilter{InstanceID: "canary-a"})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		if len(alerts) != 2 {
			t.Fatalf("alerts stored = %d, want 2 (the same two-event batch sent twice must store one copy each)", len(alerts))
		}
	})
}

// TestHandleBatchDuplicateEventIDAcksAsStored exercises issue #32's ack
// semantics for a duplicate id -- not one of the eight required test
// statements, but directly stated in the issue's fail-closed section
// ("duplicate event_id -> acked as stored") and cheap to prove alongside
// the test above.
func TestHandleBatchDuplicateEventIDAcksAsStored(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)
		body := fmt.Sprintf(`{"events":[%s]}`, validEventJSON(validEventID2))

		for i := 0; i < 2; i++ {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, batchRequest(raw, body))
			if rec.Code != http.StatusOK {
				t.Fatalf("attempt %d: status = %d, want %d", i, rec.Code, http.StatusOK)
			}
			var resp ackResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal response: %v", err)
			}
			if len(resp.Stored) != 1 || resp.Stored[0] != validEventID2 {
				t.Fatalf("attempt %d: stored = %v, want [%s] (a duplicate id must ack as stored)", i, resp.Stored, validEventID2)
			}
		}

		var alertCount int
		row := database.QueryRow(`SELECT COUNT(*) FROM alerts WHERE instance_id = ? AND event_id = ?`, "canary-a", validEventID2)
		if err := row.Scan(&alertCount); err != nil {
			t.Fatalf("count alerts: %v", err)
		}
		if alertCount != 1 {
			t.Errorf("alerts stored for event_id %s = %d, want 1 (delivered twice, stored once)", validEventID2, alertCount)
		}
	})
}
