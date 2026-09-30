package ingest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// pollCommands polls /ingest/commands with raw and returns the status and
// the decoded "command" field (nil when the queue is empty).
func pollCommands(t *testing.T, h http.Handler, raw, body string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/commands", raw, body))
	var out struct {
		Command map[string]any `json:"command"`
	}
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode command response %q: %v", rec.Body.String(), err)
		}
	}
	return rec.Code, out.Command
}

func mintSelfTest(t *testing.T, database *db.DB, canaryID string, createdAt time.Time, ttl time.Duration) store.CanaryCommand {
	t.Helper()
	cmd, err := store.MintCanaryCommand(context.Background(), database, canaryID,
		store.CommandSelfTest, `{"marker":"m1"}`, createdAt, createdAt.Add(ttl))
	if err != nil {
		t.Fatalf("MintCanaryCommand(%s): %v", canaryID, err)
	}
	return cmd
}

// TestHandleCommandsRequiresCanaryToken: the command endpoint sits behind
// the same bearer-token gate as every other ingest route.
func TestHandleCommandsRequiresCanaryToken(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/commands", "", ""))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})
}

// TestHandleCommandsEmptyQueueIsOK: "nothing for you" is the ordinary
// answer to a well-formed poll, so it is a 200 with a null command, not
// an error the agent has to distinguish from a real failure.
func TestHandleCommandsEmptyQueueIsOK(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		code, cmd := pollCommands(t, h, raw, "")
		if code != http.StatusOK {
			t.Fatalf("status = %d, want %d", code, http.StatusOK)
		}
		if cmd != nil {
			t.Fatalf("command = %v, want none", cmd)
		}
	})
}

// TestHandleCommandsDeliveredOnceNeverTwice is #32 slice 5b's first
// required test. The second poll must come back empty: a command handed
// over once is spent, whatever happened to it afterwards.
func TestHandleCommandsDeliveredOnceNeverTwice(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		raw := mintToken(t, database, "canary-a")
		now := time.Now().UTC()
		minted := mintSelfTest(t, database, "canary-a", now, commandTTL)
		h := newHandler(database, nil, func() time.Time { return now }, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		code, first := pollCommands(t, h, raw, "")
		if code != http.StatusOK || first == nil {
			t.Fatalf("first poll: status %d, command %v; want 200 and a command", code, first)
		}
		if first["id"] != minted.ID {
			t.Fatalf("delivered id = %v, want %s", first["id"], minted.ID)
		}
		if first["kind"] != string(store.CommandSelfTest) {
			t.Fatalf("delivered kind = %v, want %s", first["kind"], store.CommandSelfTest)
		}

		code, second := pollCommands(t, h, raw, "")
		if code != http.StatusOK {
			t.Fatalf("second poll status = %d, want %d", code, http.StatusOK)
		}
		if second != nil {
			t.Fatalf("second poll returned %v, want none -- a command was delivered twice", second)
		}
	})
}

// TestHandleCommandsMarksDeliveredBeforeTheWire: #32 requires the
// delivered mark to be committed before the response is written, so a
// crash in between loses the command rather than repeating it. Checked
// through the stored row, which is the only place that ordering is
// observable after the fact.
func TestHandleCommandsMarksDeliveredBeforeTheWire(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		raw := mintToken(t, database, "canary-a")
		now := time.Now().UTC()
		minted := mintSelfTest(t, database, "canary-a", now, commandTTL)
		h := newHandler(database, nil, func() time.Time { return now }, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		if code, cmd := pollCommands(t, h, raw, ""); code != http.StatusOK || cmd == nil {
			t.Fatalf("poll: status %d, command %v; want 200 and a command", code, cmd)
		}
		stored, err := store.LookupCanaryCommand(context.Background(), database, minted.ID)
		if err != nil {
			t.Fatalf("LookupCanaryCommand: %v", err)
		}
		if stored.DeliveredAt == nil {
			t.Fatal("delivered_at is still NULL after the command was handed over")
		}
	})
}

// TestHandleCommandsExpiredIsNotDelivered is slice 5b's second required
// test. Expiry is on birdcage's clock, ten minutes from mint.
func TestHandleCommandsExpiredIsNotDelivered(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		raw := mintToken(t, database, "canary-a")
		minted := time.Now().UTC().Add(-2 * commandTTL)
		mintSelfTest(t, database, "canary-a", minted, commandTTL)
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		code, cmd := pollCommands(t, h, raw, "")
		if code != http.StatusOK {
			t.Fatalf("status = %d, want %d", code, http.StatusOK)
		}
		if cmd != nil {
			t.Fatalf("expired command %v was delivered", cmd)
		}
	})
}

// TestHandleCommandsExpiryBoundaryIsNotSQL guards the trap that cost two
// rotation tests: RFC3339Nano trims trailing zeros, so a SQL string
// comparison sorts "…:00Z" after "…:00.5Z". A command minted on a whole
// second and one minted a fraction later must both expire correctly.
func TestHandleCommandsExpiryBoundaryIsNotSQL(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		raw := mintToken(t, database, "canary-a")
		whole := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
		mintSelfTest(t, database, "canary-a", whole, commandTTL)
		mintSelfTest(t, database, "canary-a", whole.Add(500*time.Millisecond), commandTTL)

		// One nanosecond after the first expires, the second is still live.
		at := whole.Add(commandTTL)
		h := newHandler(database, nil, func() time.Time { return at }, defaultLimiterLimits, store.NewSelfTestIndex(), nil)
		code, cmd := pollCommands(t, h, raw, "")
		if code != http.StatusOK || cmd == nil {
			t.Fatalf("status %d command %v: the later command should still be live", code, cmd)
		}
		if got := cmd["expires_at"]; got != whole.Add(500*time.Millisecond).Add(commandTTL).Format(time.RFC3339Nano) {
			t.Fatalf("delivered the wrong command: expires_at = %v", got)
		}
		// And nothing else is: the first one expired exactly on the boundary.
		if _, cmd := pollCommands(t, h, raw, ""); cmd != nil {
			t.Fatalf("command %v delivered after its expiry", cmd)
		}
	})
}

// TestHandleCommandsCannotBeReadWithAnotherCanarysToken is slice 5b's
// third required test.
func TestHandleCommandsCannotBeReadWithAnotherCanarysToken(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		enrollCanary(t, database, "canary-b")
		rawB := mintToken(t, database, "canary-b")
		now := time.Now().UTC()
		minted := mintSelfTest(t, database, "canary-a", now, commandTTL)
		h := newHandler(database, nil, func() time.Time { return now }, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		code, cmd := pollCommands(t, h, rawB, "")
		if code != http.StatusOK {
			t.Fatalf("status = %d, want %d", code, http.StatusOK)
		}
		if cmd != nil {
			t.Fatalf("canary-b was handed %v, which belongs to canary-a", cmd)
		}
		stored, err := store.LookupCanaryCommand(context.Background(), database, minted.ID)
		if err != nil {
			t.Fatalf("LookupCanaryCommand: %v", err)
		}
		if stored.DeliveredAt != nil {
			t.Fatal("canary-a's command was marked delivered by canary-b's poll")
		}
	})
}

// TestHandleCommandsConcurrentPollsDeliverOnce: two agents polling at
// once (a restart overlapping its predecessor, or a retry racing the
// original) must not both receive the same command.
func TestHandleCommandsConcurrentPollsDeliverOnce(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		raw := mintToken(t, database, "canary-a")
		now := time.Now().UTC()
		mintSelfTest(t, database, "canary-a", now, commandTTL)
		h := newHandler(database, nil, func() time.Time { return now }, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		const pollers = 4
		var (
			wg        sync.WaitGroup
			mu        sync.Mutex
			delivered int
		)
		for range pollers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/commands", raw, ""))
				var out struct {
					Command map[string]any `json:"command"`
				}
				if rec.Code == http.StatusOK && json.Unmarshal(rec.Body.Bytes(), &out) == nil && out.Command != nil {
					mu.Lock()
					delivered++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if delivered != 1 {
			t.Fatalf("%d of %d concurrent polls received the command, want exactly 1", delivered, pollers)
		}
	})
}

// TestHandleCommandsRejectsUnknownBody: an agent sending something
// birdcage does not understand is told so, rather than having it ignored.
func TestHandleCommandsRejectsUnknownBody(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		raw := mintToken(t, database, "canary-a")
		h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		for _, body := range []string{`{"canary_id":"canary-b"}`, `{}{}`, `not json`} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, ingestRequest(http.MethodPost, "/ingest/commands", raw, body))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("body %q: status = %d, want %d", body, rec.Code, http.StatusBadRequest)
			}
		}
		// An empty object is accepted, so an agent that always sends one
		// is not a special case.
		if code, _ := pollCommands(t, h, raw, `{}`); code != http.StatusOK {
			t.Fatalf("empty object body: status = %d, want %d", code, http.StatusOK)
		}
	})
}

// TestUpgradeCommandCannotBeMinted holds the owner's 2026-09-16 rule in
// place: no unattended upgrades. Until an admin's authority to order one
// can be established, no upgrade command can exist at all, so none can be
// delivered. If this test is ever changed, the gate must exist first.
func TestUpgradeCommandCannotBeMinted(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		now := time.Now().UTC()
		_, err := store.MintCanaryCommand(context.Background(), database, "canary-a",
			store.CommandKind("upgrade"), "", now, now.Add(commandTTL))
		if err == nil {
			t.Fatal("an upgrade command was minted; #32/#50: there is no way to order one yet")
		}
	})
}
