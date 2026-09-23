package ingest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// fakeFirstContactHook is a minimal SelfTestRotationHook: it records
// every FirstContact/RotationSucceeded call it receives, guarded by a
// mutex since requireBearerToken's caller is an ordinary http.Handler and
// nothing here assumes single-threaded delivery. Not internal/selftestsched
// itself -- this package must not import it (see rotate.go's own doc
// comment on why the hook is structural) -- so this is the test double
// every ingest-level test in this file drives against.
type fakeFirstContactHook struct {
	mu              sync.Mutex
	firstContactIDs []string
	rotationSuccIDs []string
}

func (h *fakeFirstContactHook) FirstContact(_ context.Context, canaryID string, _ time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.firstContactIDs = append(h.firstContactIDs, canaryID)
}

func (h *fakeFirstContactHook) RotationSucceeded(_ context.Context, canaryID string, _ time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rotationSuccIDs = append(h.rotationSuccIDs, canaryID)
}

func (h *fakeFirstContactHook) calls(which *[]string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), *which...)
}

// TestFirstContactHookFiresOnFirstEverTokenUseOnly is issue #47 step 8's
// required test: the hook fires exactly once, on the token's first-ever
// use (the same "first use of a canary's first token" branch
// TestFirstEverUseOfATokenIsAudited already proves is audited), and never
// again on a later request presenting the same, now-used token.
func TestFirstContactHookFiresOnFirstEverTokenUseOnly(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		hook := &fakeFirstContactHook{}
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), hook)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/events", raw, batchBody(rotateEventIDA)))
		if rec.Code != http.StatusOK {
			t.Fatalf("first request: status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}
		if got := hook.calls(&hook.firstContactIDs); len(got) != 1 || got[0] != "canary-a" {
			t.Fatalf("FirstContact calls after first-ever use = %v, want [canary-a]", got)
		}

		rec2 := httptest.NewRecorder()
		h.ServeHTTP(rec2, ingestRequest(http.MethodPost, "/ingest/events", raw, batchBody(rotateEventIDB)))
		if rec2.Code != http.StatusOK {
			t.Fatalf("second request: status = %d, want %d (body %q)", rec2.Code, http.StatusOK, rec2.Body.String())
		}
		if got := hook.calls(&hook.firstContactIDs); len(got) != 1 {
			t.Fatalf("FirstContact calls after a second request on the same token = %v, want still just one call", got)
		}
	})
}

// TestFirstContactHookNeverFiresOnARotationsFirstUse proves FirstContact
// and RotationSucceeded stay on their own branches: a token minted by an
// ordinary rotation (canary already has an older token) fires
// RotationSucceeded on its first use, per handleRotate's own hook call,
// never FirstContact -- FirstContact is "the canary's very first token",
// not "any token's first use".
func TestFirstContactHookNeverFiresOnARotationsFirstUse(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		hook := &fakeFirstContactHook{}
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), hook)

		// Burn the canary's first (and only) token's first-ever use on an
		// unrelated route, so the rotation below is not itself that event.
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/heartbeat", raw, `{"log_read_ok":true}`))
		if rec.Code != http.StatusOK {
			t.Fatalf("heartbeat: status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}
		if got := hook.calls(&hook.firstContactIDs); len(got) != 1 {
			t.Fatalf("FirstContact calls after the very first request = %v, want exactly one", got)
		}

		newRaw := mustRotate(t, h, raw)

		rec2 := httptest.NewRecorder()
		h.ServeHTTP(rec2, ingestRequest(http.MethodPost, "/ingest/events", newRaw, batchBody(rotateEventIDA)))
		if rec2.Code != http.StatusOK {
			t.Fatalf("first use of rotated token: status = %d, want %d (body %q)", rec2.Code, http.StatusOK, rec2.Body.String())
		}

		if got := hook.calls(&hook.firstContactIDs); len(got) != 1 {
			t.Fatalf("FirstContact calls after the rotated token's first use = %v, want still exactly one (unchanged)", got)
		}
		if got := hook.calls(&hook.rotationSuccIDs); len(got) != 1 || got[0] != "canary-a" {
			t.Fatalf("RotationSucceeded calls = %v, want [canary-a] (fired by handleRotate itself, not this path)", got)
		}
	})
}

// TestFirstContactRecordsLastSeenAddrBeforeAnyHeartbeat: the scheduler's
// mint (internal/selftestsched's mintForCanary) needs an address to probe
// and skips a canary with none -- proving completeRotation's own
// recordLastSeenAddr call runs, so a canary's very first request (of any
// route, not just a heartbeat) leaves last_seen_addr set even though no
// heartbeat has ever been sent.
func TestFirstContactRecordsLastSeenAddrBeforeAnyHeartbeat(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		hook := &fakeFirstContactHook{}
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), hook)

		rec := httptest.NewRecorder()
		req := ingestRequest(http.MethodPost, "/ingest/events", raw, batchBody(rotateEventIDA))
		req.RemoteAddr = "198.51.100.7:54321"
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}

		var addr *string
		if err := database.QueryRow(`SELECT last_seen_addr FROM canaries WHERE id = ?`, "canary-a").Scan(&addr); err != nil {
			t.Fatalf("query last_seen_addr: %v", err)
		}
		if addr == nil || *addr != "198.51.100.7" {
			t.Fatalf("last_seen_addr = %v, want 198.51.100.7 (from the request's own RemoteAddr, no heartbeat sent)", addr)
		}
	})
}

// TestFirstContactHookNilDoesNothing proves a nil hook (no scheduler
// wired in -- every other test in this package) leaves the request
// completely unaffected, matching RotationSucceeded's own stance in
// handleRotate.
func TestFirstContactHookNilDoesNothing(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/events", raw, batchBody(rotateEventIDA)))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}
	})
}
