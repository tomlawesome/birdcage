package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/selftest"
	"github.com/tomlawesome/birdcage/internal/store"
)

// mintSelfTestCommandForCanary mints one self-test command with a single
// ssh:22 target for canaryID against idx, and returns the marker
// planted for it -- the shared setup every test in this file needs to
// produce a marker MatchSelfTest will actually recognise.
func mintSelfTestCommandForCanary(t *testing.T, database *db.DB, idx *store.SelfTestIndex, canaryID string, issuedAt time.Time, ttl time.Duration) string {
	t.Helper()
	cmd, err := store.MintSelfTestCommand(context.Background(), database, idx, canaryID, "192.0.2.10",
		[]store.SelfTestTarget{{Service: "ssh", DestPort: 22}}, issuedAt, issuedAt.Add(ttl))
	if err != nil {
		t.Fatalf("MintSelfTestCommand: %v", err)
	}
	params, err := selftest.DecodeParams([]byte(cmd.Params))
	if err != nil {
		t.Fatalf("decode minted params: %v", err)
	}
	return params.Targets[0].Marker
}

// alertsForInstance queries the raw-alert admin listing (GET
// /api/alerts' own store.ListAlerts) for instanceID -- the one read
// path issue #46 item 2 deliberately leaves synthetic rows in, so a
// test can see both the ack and the Synthetic flag together.
func alertsForInstance(t *testing.T, database *db.DB, instanceID string) []store.Alert {
	t.Helper()
	alerts, err := store.ListAlerts(context.Background(), database, store.AlertFilter{InstanceID: instanceID})
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	return alerts
}

// TestHandleBatchMarkedEventStoredSyntheticAndExcludedFromDashboard is
// issue #46's required test: a marked alert arriving inside the self-
// test's window is stored synthetic and does not appear in the
// dashboard/read paths (here, store.GetStats -- every such path filters
// "synthetic = 0", see store/store.go's own comments).
func TestHandleBatchMarkedEventStoredSyntheticAndExcludedFromDashboard(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		idx := store.NewSelfTestIndex()
		now := time.Now().UTC()
		marker := mintSelfTestCommandForCanary(t, database, idx, "canary-a", now, 10*time.Minute)
		h := newHandler(database, nil, func() time.Time { return now }, defaultLimiterLimits, idx, nil)

		body := fmt.Sprintf(`{"events":[{"event_id":%q,"source_ip":"203.0.113.9","dest_port":22,"service":"ssh","raw":%q}]}`,
			validEventID1, `{"logdata":{"probe":"`+marker+`"}}`)
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
			t.Fatalf("stored = %v, rejected = %v, want [%s] stored", resp.Stored, resp.Rejected, validEventID1)
		}

		alerts := alertsForInstance(t, database, "canary-a")
		if len(alerts) != 1 || !alerts[0].Synthetic {
			t.Fatalf("alerts = %+v, want exactly one row with synthetic = true", alerts)
		}

		stats, err := store.GetStats(context.Background(), database, now)
		if err != nil {
			t.Fatalf("GetStats: %v", err)
		}
		if stats.Total != 0 {
			t.Fatalf("GetStats.Total = %d, want 0 (a synthetic alert must not count toward the dashboard's tiles)", stats.Total)
		}
	})
}

// TestHandleBatchTestShapedEventWithNoIssuedMarkerStoredRealAndVisible
// is #46's core security property re-proven at the ingest layer: a
// plausible-looking marker birdcage never actually minted must still
// raise a real alert -- stored non-synthetic and counted by GetStats.
func TestHandleBatchTestShapedEventWithNoIssuedMarkerStoredRealAndVisible(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		idx := store.NewSelfTestIndex()
		now := time.Now().UTC()
		// Mint an unrelated live self-test so idx is non-empty -- an
		// intruder guessing near a real run is the more realistic
		// adversary than an empty index.
		mintSelfTestCommandForCanary(t, database, idx, "canary-a", now, 10*time.Minute)
		h := newHandler(database, nil, func() time.Time { return now }, defaultLimiterLimits, idx, nil)

		guessed := "0123456789abcdef0123456789abcdef"[:selftest.MarkerBytes*2]
		body := fmt.Sprintf(`{"events":[{"event_id":%q,"source_ip":"203.0.113.9","dest_port":22,"service":"ssh","raw":%q}]}`,
			validEventID1, `{"logdata":{"probe":"`+guessed+`"}}`)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, batchRequest(raw, body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		alerts := alertsForInstance(t, database, "canary-a")
		if len(alerts) != 1 || alerts[0].Synthetic {
			t.Fatalf("alerts = %+v, want exactly one row with synthetic = false", alerts)
		}
		stats, err := store.GetStats(context.Background(), database, now)
		if err != nil {
			t.Fatalf("GetStats: %v", err)
		}
		if stats.Total != 1 {
			t.Fatalf("GetStats.Total = %d, want 1 (a real alert must count)", stats.Total)
		}
	})
}

// TestHandleBatchExpiredMarkerEventStoredReal: a marker from a
// self-test whose command has since expired must not suppress the
// alert forever -- stored real, once the window has passed.
func TestHandleBatchExpiredMarkerEventStoredReal(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		idx := store.NewSelfTestIndex()
		issuedAt := time.Now().UTC().Add(-time.Hour)
		marker := mintSelfTestCommandForCanary(t, database, idx, "canary-a", issuedAt, time.Minute) // expired 59 minutes ago
		afterExpiry := issuedAt.Add(time.Hour)
		h := newHandler(database, nil, func() time.Time { return afterExpiry }, defaultLimiterLimits, idx, nil)

		body := fmt.Sprintf(`{"events":[{"event_id":%q,"source_ip":"203.0.113.9","dest_port":22,"service":"ssh","raw":%q}]}`,
			validEventID1, `{"logdata":{"probe":"`+marker+`"}}`)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, batchRequest(raw, body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		alerts := alertsForInstance(t, database, "canary-a")
		if len(alerts) != 1 || alerts[0].Synthetic {
			t.Fatalf("alerts = %+v, want exactly one row with synthetic = false", alerts)
		}
	})
}

// TestHandleBatchMatchSelfTestErrorStoresReal is #46 slice 1's required
// error-path test: "on any error from MatchSelfTest: log, store the
// alert as real, continue. Never drop." The marker itself does match in
// memory (idx already has it), but self_test_targets -- where the match
// would be recorded -- is gone, so MatchSelfTest returns an error; the
// event must still be acked as stored, and stored non-synthetic.
func TestHandleBatchMatchSelfTestErrorStoresReal(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		idx := store.NewSelfTestIndex()
		now := time.Now().UTC()
		marker := mintSelfTestCommandForCanary(t, database, idx, "canary-a", now, 10*time.Minute)
		h := newHandler(database, nil, func() time.Time { return now }, defaultLimiterLimits, idx, nil)

		if _, err := database.Exec(`DROP TABLE self_test_targets`); err != nil {
			t.Fatalf("drop self_test_targets: %v", err)
		}

		body := fmt.Sprintf(`{"events":[{"event_id":%q,"source_ip":"203.0.113.9","dest_port":22,"service":"ssh","raw":%q}]}`,
			validEventID1, `{"logdata":{"probe":"`+marker+`"}}`)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, batchRequest(raw, body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q) -- a MatchSelfTest bookkeeping error must never turn into a dropped event", rec.Code, http.StatusOK, rec.Body.String())
		}
		var resp ackResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if len(resp.Stored) != 1 || resp.Stored[0] != validEventID1 {
			t.Fatalf("stored = %v, rejected = %v, want [%s] stored", resp.Stored, resp.Rejected, validEventID1)
		}

		alerts := alertsForInstance(t, database, "canary-a")
		if len(alerts) != 1 || alerts[0].Synthetic {
			t.Fatalf("alerts = %+v, want exactly one row with synthetic = false", alerts)
		}
	})
}
