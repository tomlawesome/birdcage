package ingest

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// TestRateLimitFloodDoesNotWriteOneRowPerRejection is issue #57's first
// reproduction: recordRateLimitCrossed used to append one audit_log row
// per rejected request (ratelimit.go:102-113), so an attacker who found
// the requests/min cap could turn the limiter itself into an insert
// flood against an append-only table. With a 1-request cap, one request
// succeeds and every one after it is rejected; only the first rejection
// may write a row inside a single coalescing interval.
func TestRateLimitFloodDoesNotWriteOneRowPerRejection(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		tiny := limiterLimits{RequestsPerMinute: 1, EventsPerMinute: 60000}
		base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		now := base
		h := newHandler(database, nil, func() time.Time { return now }, tiny, store.NewSelfTestIndex(), nil)
		body := fmt.Sprintf(`{"events":[%s]}`, validEventJSON(validEventID1))

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, batchRequest(raw, body))
		if rec.Code != http.StatusOK {
			t.Fatalf("first request: status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		const rejections = 500
		for i := 0; i < rejections; i++ {
			rec = httptest.NewRecorder()
			h.ServeHTTP(rec, batchRequest(raw, body))
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("rejection %d: status = %d, want %d (body %q)", i, rec.Code, http.StatusTooManyRequests, rec.Body.String())
			}
		}

		got := countAuditRows(t, database, "ingest.rate_limited", "canary-a")
		if got != 1 {
			t.Fatalf("audit_log rows for %d rejected requests inside one coalescing interval = %d, want 1 (only the first rejection should write; the rest must be coalesced)", rejections, got)
		}
	})
}

// TestTokenConflictFloodDoesNotWriteOneRowPerPresentation is issue #57's
// second reproduction: recordTokenConflictIfSuccessorActive used to
// append one audit_log row for every presentation of a revoked token
// whose canary has an active successor (auth.go:165-173) -- and unlike
// the rate-limit path, the caller needs no working credential at all, so
// a revoked token alone is enough to flood the table.
func TestTokenConflictFloodDoesNotWriteOneRowPerPresentation(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw1 := mintToken(t, database, "canary-a")
		// base must be after mintToken's own real time.Now() call (raw1's
		// created_at) so the rotation below sees raw2 as the newer token
		// and actually supersedes raw1 -- otherwise completeRotation's
		// ordering never revokes raw1 and every "revoked token" premise
		// this test relies on is false.
		base := time.Now().UTC().Add(time.Minute)
		now := base
		h := newHandler(database, nil, func() time.Time { return now }, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		raw2 := mustRotate(t, h, raw1)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/events", raw2, batchBody(rotateEventIDA)))
		if rec.Code != http.StatusOK {
			t.Fatalf("raw2 first use: status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		const presentations = 500
		for i := 0; i < presentations; i++ {
			rec = httptest.NewRecorder()
			h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/events", raw1, batchBody(rotateEventIDD)))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("presentation %d: status = %d, want %d (body %q)", i, rec.Code, http.StatusUnauthorized, rec.Body.String())
			}
		}

		got := countAuditRows(t, database, "ingest.token_conflict", "canary-a")
		if got != 1 {
			t.Fatalf("audit_log rows for %d revoked-token presentations inside one coalescing interval = %d, want 1 (only the first presentation should write; the rest must be coalesced)", presentations, got)
		}
	})
}

// TestFloodedRateLimitStillReadsThrottled proves the design's central
// claim: coalescing at 1-minute granularity does not change the
// "throttled" health state (internal/store/health.go's throttledWindow,
// 5 minutes), because the newest audit_log row is never more than one
// coalescing interval old while the flood continues. The flood here
// spans several coalescing intervals of simulated time, so it proves the
// steady-state case, not just the always-fires-once first occurrence.
func TestFloodedRateLimitStillReadsThrottled(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

		if err := store.InsertCanary(ctx, database, store.Canary{
			ID: "canary-a", Name: "canary-a", Lane: "lan", Kind: agentkind.Honeypot,
			HeartbeatIntervalS: 3600, EnrolledAt: base,
		}); err != nil {
			t.Fatalf("InsertCanary: %v", err)
		}
		if err := store.RecordHeartbeat(ctx, database, "canary-a", base); err != nil {
			t.Fatalf("RecordHeartbeat: %v", err)
		}

		raw := mintToken(t, database, "canary-a")
		tiny := limiterLimits{RequestsPerMinute: 1, EventsPerMinute: 60000}
		now := base
		h := newHandler(database, nil, func() time.Time { return now }, tiny, store.NewSelfTestIndex(), nil)
		body := fmt.Sprintf(`{"events":[%s]}`, validEventJSON(validEventID1))

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, batchRequest(raw, body))
		if rec.Code != http.StatusOK {
			t.Fatalf("first request: status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		// A rejection every 10 simulated seconds for 6 simulated minutes:
		// well past auditCoalesceInterval (1 minute), so this crosses
		// several coalescing windows, but still a continuous flood right
		// up to the moment health is read.
		const rejections = 36
		for i := 0; i < rejections; i++ {
			now = now.Add(10 * time.Second)
			rec = httptest.NewRecorder()
			h.ServeHTTP(rec, batchRequest(raw, body))
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("rejection %d: status = %d, want %d (body %q)", i, rec.Code, http.StatusTooManyRequests, rec.Body.String())
			}
		}

		rows := countAuditRows(t, database, "ingest.rate_limited", "canary-a")
		if rows == 0 || rows >= rejections {
			t.Fatalf("audit_log rows over a %d-rejection, 6-minute flood = %d, want roughly one per coalescing interval (>0 and well under %d)", rejections, rows, rejections)
		}

		canaries, err := store.ListCanaries(ctx, database, now, 24*time.Hour)
		if err != nil {
			t.Fatalf("ListCanaries: %v", err)
		}
		var found *store.Canary
		for i := range canaries {
			if canaries[i].ID == "canary-a" {
				found = &canaries[i]
			}
		}
		if found == nil {
			t.Fatal("canary-a not found in ListCanaries result")
		}
		if found.Status != string(store.StateThrottled) {
			t.Fatalf("Status = %q, want %q -- a coalesced flood must still keep the canary reading throttled inside the 5-minute window", found.Status, store.StateThrottled)
		}
	})
}

// TestFloodedTokenConflictStillReadsTokenConflict is
// TestFloodedRateLimitStillReadsThrottled's counterpart for the
// tokenConflictQuietPeriod window (24 hours): a coalesced flood of
// revoked-token presentations must still keep the canary reading
// "token_conflict".
func TestFloodedTokenConflictStillReadsTokenConflict(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		enrolledAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

		if err := store.InsertCanary(ctx, database, store.Canary{
			ID: "canary-a", Name: "canary-a", Lane: "lan", Kind: agentkind.Honeypot,
			HeartbeatIntervalS: 3600, EnrolledAt: enrolledAt,
		}); err != nil {
			t.Fatalf("InsertCanary: %v", err)
		}
		if err := store.RecordHeartbeat(ctx, database, "canary-a", enrolledAt); err != nil {
			t.Fatalf("RecordHeartbeat: %v", err)
		}

		raw1 := mintToken(t, database, "canary-a")
		// base must be after mintToken's own real time.Now() call (raw1's
		// created_at) so the rotation below sees raw2 as the newer token
		// and actually supersedes raw1 -- see the same note in
		// TestTokenConflictFloodDoesNotWriteOneRowPerPresentation.
		base := time.Now().UTC().Add(time.Minute)
		now := base
		h := newHandler(database, nil, func() time.Time { return now }, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		raw2 := mustRotate(t, h, raw1)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/events", raw2, batchBody(rotateEventIDA)))
		if rec.Code != http.StatusOK {
			t.Fatalf("raw2 first use: status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		// A presentation every simulated minute for 30 simulated minutes.
		const presentations = 30
		for i := 0; i < presentations; i++ {
			now = now.Add(time.Minute)
			rec = httptest.NewRecorder()
			h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/events", raw1, batchBody(rotateEventIDD)))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("presentation %d: status = %d, want %d (body %q)", i, rec.Code, http.StatusUnauthorized, rec.Body.String())
			}
		}

		rows := countAuditRows(t, database, "ingest.token_conflict", "canary-a")
		if rows == 0 {
			t.Fatal("no ingest.token_conflict rows recorded for a 30-minute flood")
		}

		canaries, err := store.ListCanaries(ctx, database, now, 24*time.Hour)
		if err != nil {
			t.Fatalf("ListCanaries: %v", err)
		}
		var found *store.Canary
		for i := range canaries {
			if canaries[i].ID == "canary-a" {
				found = &canaries[i]
			}
		}
		if found == nil {
			t.Fatal("canary-a not found in ListCanaries result")
		}
		if found.Status != string(store.StateTokenConflict) {
			t.Fatalf("Status = %q, want %q -- a coalesced flood must still keep the canary reading token_conflict inside the 24h quiet period", found.Status, store.StateTokenConflict)
		}
	})
}
