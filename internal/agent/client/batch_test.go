package client

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// validID1/2/3 are well-formed event ids (64 lowercase hex chars,
// internal/ingest/batch.go's eventIDPattern): distinct digits so a test
// asserting on more than one at once can tell them apart at a glance.
var (
	validID1 = strings.Repeat("1", 64)
	validID2 = strings.Repeat("2", 64)
)

const badID = "not-a-valid-event-id"

// mintToken mints a bearer token for canaryID, registering it as a
// Honeypot -- the kind almost every test in this package wants -- unless
// a canaries row already exists for it (issue #106: every ingest route
// now refuses a token whose canary is unregistered, so a token minted
// for a test has to have a row behind it to reach a handler at all).
// scans_test.go's enrollCanaryKind registers "canary-a" as a Scanner
// before calling this, for the one route here that needs it.
func mintToken(t *testing.T, database *db.DB, canaryID string) string {
	t.Helper()
	ensureCanary(t, database, canaryID, agentkind.Honeypot)
	raw, _, err := store.MintCanaryToken(ctx(), database, canaryID, time.Now().UTC())
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
		return
	}
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("check canary %s exists: %v", canaryID, err)
	}
	if err := store.InsertCanary(ctx(), database, store.Canary{
		ID: canaryID, Name: canaryID, Lane: "lan", Kind: kind, EnrolledAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("InsertCanary(%s): %v", canaryID, err)
	}
}

// TestPushBatchStoredAndRejected proves this package's ack/reject split
// against internal/ingest's real handler: a batch with one malformed
// event id alongside two valid ones must report exactly the same split
// the server enforces (internal/ingest/batch.go's validateEvent), not a
// shape this package invented.
func TestPushBatchStoredAndRejected(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		c, _ := newIngestServer(t, database, agentkind.Honeypot)
		token := mintToken(t, database, "canary-a")

		result, err := c.PushBatch(ctx(), token, []Event{
			{ID: validID1, SourceIP: "203.0.113.9", DestPort: 22, Service: "ssh", Raw: "hit-1"},
			{ID: badID, SourceIP: "203.0.113.9", DestPort: 22, Service: "ssh", Raw: "hit-bad"},
			{ID: validID2, SourceIP: "203.0.113.9", DestPort: 22, Service: "ssh", Raw: "hit-2"},
		})
		if err != nil {
			t.Fatalf("PushBatch: %v", err)
		}
		if len(result.Stored) != 2 || !containsAll(result.Stored, validID1, validID2) {
			t.Errorf("stored = %v, want [%s %s]", result.Stored, validID1, validID2)
		}
		if reason, ok := result.Rejected[badID]; !ok || reason == "" {
			t.Errorf("rejected = %v, want a non-empty entry for %s", result.Rejected, badID)
		}
		if len(result.Retry) != 0 {
			t.Errorf("retry = %v, want none", result.Retry)
		}
	})
}

// TestPushBatchDuplicateAcksAsStored proves the same batch sent twice
// stores once and both times reports the id as Stored (#32: "a
// duplicate id acks as stored -- idempotent success"), against the real
// handler and its actual dedup index.
func TestPushBatchDuplicateAcksAsStored(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		c, _ := newIngestServer(t, database, agentkind.Honeypot)
		token := mintToken(t, database, "canary-a")
		events := []Event{{ID: validID1, SourceIP: "203.0.113.9", DestPort: 22, Service: "ssh", Raw: "hit"}}

		for i := 0; i < 2; i++ {
			result, err := c.PushBatch(ctx(), token, events)
			if err != nil {
				t.Fatalf("attempt %d: PushBatch: %v", i, err)
			}
			if len(result.Stored) != 1 || result.Stored[0] != validID1 {
				t.Fatalf("attempt %d: stored = %v, want [%s]", i, result.Stored, validID1)
			}
		}

		alerts, err := store.ListAlerts(ctx(), database, store.AlertFilter{InstanceID: "canary-a"})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		if len(alerts) != 1 {
			t.Fatalf("alerts stored = %d, want 1 (delivered twice, stored once)", len(alerts))
		}
	})
}

// TestPushBatchUnauthorized proves a dead token surfaces as
// ErrUnauthorized, not a generic or retryable error -- #48's fail-closed
// rule depends on the caller being able to tell "no channel to
// birdcage" apart from "try again".
func TestPushBatchUnauthorized(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		c, _ := newIngestServer(t, database, agentkind.Honeypot)

		_, err := c.PushBatch(ctx(), "not-a-real-token", []Event{{ID: validID1, DestPort: -1, Raw: "{}"}})
		if !IsUnauthorized(err) {
			t.Fatalf("err = %v, want ErrUnauthorized", err)
		}
		if IsRetryable(err) {
			t.Fatal("401 must never be reported as retryable")
		}
	})
}

// TestPushBatchEnvelopeRejectionFallsBackToSingly is #48's ratified
// owner decision (2026-09-15): a batch birdcage rejects at the envelope
// level is resent as individual single-event requests, so one bad
// member never costs the rest. Triggered here against the real handler
// via a genuine 413 (internal/ingest/batch.go's maxBodyBytes, 300 KiB):
// one event's raw payload alone exceeds the cap and is permanently
// rejected even sent alone, the other is ordinary and stored.
func TestPushBatchEnvelopeRejectionFallsBackToSingly(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		c, _ := newIngestServer(t, database, agentkind.Honeypot)
		token := mintToken(t, database, "canary-a")

		oversizedRaw := strings.Repeat("x", 310*1024)
		result, err := c.PushBatch(ctx(), token, []Event{
			{ID: validID1, SourceIP: "203.0.113.9", DestPort: 22, Service: "ssh", Raw: oversizedRaw},
			{ID: validID2, SourceIP: "203.0.113.9", DestPort: 22, Service: "ssh", Raw: "small"},
		})
		if err != nil {
			t.Fatalf("PushBatch: %v", err)
		}
		if len(result.Stored) != 1 || result.Stored[0] != validID2 {
			t.Errorf("stored = %v, want [%s]", result.Stored, validID2)
		}
		if reason, ok := result.Rejected[validID1]; !ok || reason == "" {
			t.Errorf("rejected = %v, want a non-empty entry for the oversized event %s", result.Rejected, validID1)
		}
	})
}

// TestPushBatchEmptyEventsIsANoOp proves PushBatch never touches the
// network for an empty batch -- a caller with nothing to send should
// not pay for (or be able to trigger) a round trip.
func TestPushBatchEmptyEventsIsANoOp(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler reached for an empty batch")
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	result, err := c.PushBatch(ctx(), "tok", nil)
	if err != nil {
		t.Fatalf("PushBatch(nil): %v", err)
	}
	if len(result.Stored) != 0 || len(result.Rejected) != 0 || len(result.Retry) != 0 {
		t.Errorf("result = %+v, want the zero value", result)
	}
}

// TestPushBatchRetryableStatuses is the gate's required 429/503 cases:
// both must come back as *RetryableError, never a rejection and never
// ErrUnauthorized.
func TestPushBatchRetryableStatuses(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"error":"try again"}`))
			}))
			defer ts.Close()
			c := newTestClient(t, ts)

			result, err := c.PushBatch(ctx(), "tok", []Event{{ID: validID1, DestPort: -1, Raw: "{}"}})
			if !IsRetryable(err) {
				t.Fatalf("status %d: err = %v, want a *RetryableError", status, err)
			}
			if len(result.Stored) != 0 || len(result.Rejected) != 0 {
				t.Errorf("status %d: result = %+v, want the zero value on a whole-call failure", status, result)
			}
		})
	}
}

func containsAll(got []string, want ...string) bool {
	set := make(map[string]bool, len(got))
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}
