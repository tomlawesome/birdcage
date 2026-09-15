package ingest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

const (
	rotateEventIDA = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	rotateEventIDB = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	rotateEventIDC = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	rotateEventIDD = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

// ingestRequest builds a request against path, authenticated with token
// unless token is "". Generalizes batchRequest (http_test.go), which is
// pinned to POST /ingest/events, for the two routes this file exercises.
func ingestRequest(method, path, token, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// batchBody wraps a single valid event into a full POST /ingest/events
// body, for tests in this file that only care about auth/rotation
// bookkeeping, not batch content.
func batchBody(eventID string) string {
	return fmt.Sprintf(`{"events":[%s]}`, validEventJSON(eventID))
}

func mustRotate(t *testing.T, h http.Handler, token string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/rotate", token, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp rotateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal rotate response: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("rotate returned an empty token")
	}
	return resp.Token
}

func countAuditRows(t *testing.T, database *db.DB, action, target string) int {
	t.Helper()
	var n int
	row := database.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = ? AND target = ?`, action, target)
	if err := row.Scan(&n); err != nil {
		t.Fatalf("count audit_log rows: %v", err)
	}
	return n
}

// TestRotateOldTokenStopsWorkingOnlyAfterNewTokenFirstUsed is #32 slice
// 5's first required test: "a rotated-from token stops working the
// moment the new one is used, and not before".
func TestRotateOldTokenStopsWorkingOnlyAfterNewTokenFirstUsed(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw1 := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		raw2 := mustRotate(t, h, raw1)
		if raw2 == raw1 {
			t.Fatal("rotate returned the same token that was presented")
		}

		// Not before: the old token must still authenticate.
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/events", raw1, batchBody(rotateEventIDA)))
		if rec.Code != http.StatusOK {
			t.Fatalf("old token before new one's first use: status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		// The moment the new one is used:
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/events", raw2, batchBody(rotateEventIDB)))
		if rec.Code != http.StatusOK {
			t.Fatalf("new token first use: status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		// ... it stops working.
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/events", raw1, batchBody(rotateEventIDC)))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("old token after new one's first use: status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})
}

// TestTokenUnusedForAWeekStillAuthenticates is slice 5's second required
// test: "a token unused for a week still authenticates" -- no token ever
// expires on a clock.
func TestTokenUnusedForAWeekStillAuthenticates(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		aWeekLater := func() time.Time { return time.Now().UTC().Add(7 * 24 * time.Hour) }
		h := newHandler(database, nil, aWeekLater, defaultLimiterLimits)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/events", raw, batchBody(rotateEventIDA)))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}
	})
}

// TestIssuedNeverUsedTokenDiesWhenLaterTokenFirstUsed is slice 5's third
// required test: "an issued-never-used token dies when a later token is
// first used". raw2 is issued (via rotate) and never used; raw3 is
// issued later from a still-live raw1; raw3's first use must revoke
// every older token for the canary, including the never-used orphan
// raw2 and raw1 itself -- not merely raw3's own immediate predecessor.
func TestIssuedNeverUsedTokenDiesWhenLaterTokenFirstUsed(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw1 := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		raw2 := mustRotate(t, h, raw1) // issued, left unused
		raw3 := mustRotate(t, h, raw1) // raw1 is still live, so this rotation succeeds too

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/events", raw3, batchBody(rotateEventIDA)))
		if rec.Code != http.StatusOK {
			t.Fatalf("raw3 first use: status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/events", raw2, batchBody(rotateEventIDB)))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("raw2 (issued, never used) after raw3's first use: status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}

		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/events", raw1, batchBody(rotateEventIDC)))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("raw1 after raw3's first use: status = %d, want %d (every older token, not just the immediate predecessor)", rec.Code, http.StatusUnauthorized)
		}
	})
}

// TestRevokedTokenAfterSuccessorActiveRecordsTokenConflict is slice 5's
// fourth required test: "a revoked token presented after a successor is
// active records a token conflict".
func TestRevokedTokenAfterSuccessorActiveRecordsTokenConflict(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw1 := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		raw2 := mustRotate(t, h, raw1)

		// raw2's first use revokes raw1 and makes raw2 the active successor.
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/events", raw2, batchBody(rotateEventIDA)))
		if rec.Code != http.StatusOK {
			t.Fatalf("raw2 first use: status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		if got := countAuditRows(t, database, "ingest.token_conflict", "canary-a"); got != 0 {
			t.Fatalf("token conflicts recorded before presenting the revoked token = %d, want 0", got)
		}

		// raw1 is now revoked, and raw2 is an active successor: presenting
		// raw1 again must be a uniform 401 externally, and a recorded
		// conflict internally.
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/events", raw1, batchBody(rotateEventIDD)))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("revoked token: status = %d, want %d (external response must not change)", rec.Code, http.StatusUnauthorized)
		}

		if got := countAuditRows(t, database, "ingest.token_conflict", "canary-a"); got == 0 {
			t.Fatal("no token conflict recorded for a revoked token presented while a successor is active")
		}
	})
}

// TestUnknownTokenNeverRecordsAConflict proves the negative: a hash that
// was never minted at all is ordinary noise, not a conflict -- the
// internal any-status lookup must tell the two apart.
func TestUnknownTokenNeverRecordsAConflict(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/events", "never-minted-token", batchBody(rotateEventIDA)))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}

		var n int
		row := database.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = ?`, "ingest.token_conflict")
		if err := row.Scan(&n); err != nil {
			t.Fatalf("count audit_log rows: %v", err)
		}
		if n != 0 {
			t.Fatalf("token conflicts recorded for a never-minted token = %d, want 0", n)
		}
	})
}

// TestRevokedTokenWithNoActiveSuccessorRecordsNoConflict: every token for
// the canary is revoked, so presenting one of them is noise (or a fully
// retired canary), never the stolen-token/cloned-box signal slice 5
// defines -- item 5's "the one observable difference" only applies when
// a successor is active.
func TestRevokedTokenWithNoActiveSuccessorRecordsNoConflict(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		revokeAllTokens(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/events", raw, batchBody(rotateEventIDA)))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}

		if got := countAuditRows(t, database, "ingest.token_conflict", "canary-a"); got != 0 {
			t.Fatalf("token conflicts recorded with no active successor = %d, want 0", got)
		}
	})
}

// TestRotateMintFailureReturns503NotARejection extends
// TestIngestAuthDatabaseFailureIsRetryableNot401's guarantee (http_test.go)
// to the new rotate route: a database outage must never look like a
// rejected credential here either. Closing the database fails
// requireBearerToken's own lookup before handleRotate's mint is ever
// reached, so this proves the shared auth wrapper's fail-closed 503
// behavior extends correctly to this route -- the mint step's own
// analogous failure (auth succeeds, MintCanaryToken itself fails) is the
// same code path as every other store write failure in this package
// (see handleRotate's doc comment) and isn't separately mocked here.
func TestRotateMintFailureReturns503NotARejection(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits)

		if err := database.Close(); err != nil {
			t.Fatalf("close database: %v", err)
		}

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/rotate", raw, ""))
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want %d: a mint failure is retryable, not a rejected credential", rec.Code, http.StatusServiceUnavailable)
		}
	})
}
