package client

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// TestPollCommandEmptyQueueReturnsNil proves "nothing for you" decodes
// as (nil, nil), never an error the caller has to special-case.
func TestPollCommandEmptyQueueReturnsNil(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		c, _ := newIngestServer(t, database)
		token := mintToken(t, database, "canary-a")

		cmd, err := c.PollCommand(ctx(), token)
		if err != nil {
			t.Fatalf("PollCommand: %v", err)
		}
		if cmd != nil {
			t.Fatalf("cmd = %+v, want nil", cmd)
		}
	})
}

// TestPollCommandDeliversOnce proves a minted command decodes correctly
// against the real handler (id, kind, expiry) and is never handed over
// twice.
func TestPollCommandDeliversOnce(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		c, _ := newIngestServer(t, database)
		token := mintToken(t, database, "canary-a")

		now := time.Now().UTC()
		minted, err := store.MintCanaryCommand(ctx(), database, "canary-a",
			store.CommandSelfTest, `{"marker":"m1"}`, now, now.Add(10*time.Minute))
		if err != nil {
			t.Fatalf("MintCanaryCommand: %v", err)
		}

		cmd, err := c.PollCommand(ctx(), token)
		if err != nil {
			t.Fatalf("first poll: %v", err)
		}
		if cmd == nil {
			t.Fatal("first poll: cmd = nil, want the minted command")
		}
		if cmd.ID != minted.ID {
			t.Errorf("id = %q, want %q", cmd.ID, minted.ID)
		}
		if cmd.Kind != string(store.CommandSelfTest) {
			t.Errorf("kind = %q, want %q", cmd.Kind, store.CommandSelfTest)
		}
		if cmd.ExpiresAt.IsZero() {
			t.Error("ExpiresAt is zero, want the parsed expiry")
		}
		if string(cmd.Params) != `{"marker":"m1"}` {
			t.Errorf("params = %s, want {\"marker\":\"m1\"}", cmd.Params)
		}

		second, err := c.PollCommand(ctx(), token)
		if err != nil {
			t.Fatalf("second poll: %v", err)
		}
		if second != nil {
			t.Fatalf("second poll returned %+v, want nil -- a command was delivered twice", second)
		}
	})
}

// TestPollCommandUnauthorized proves a dead token surfaces as
// ErrUnauthorized.
func TestPollCommandUnauthorized(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		c, _ := newIngestServer(t, database)

		_, err := c.PollCommand(ctx(), "not-a-real-token")
		if !IsUnauthorized(err) {
			t.Fatalf("err = %v, want ErrUnauthorized", err)
		}
	})
}

// TestPollCommandRetryableOn503 proves a whole-request storage failure
// on poll is reported as retryable.
func TestPollCommandRetryableOn503(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"service unavailable"}`))
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	_, err := c.PollCommand(ctx(), "tok")
	if !IsRetryable(err) {
		t.Fatalf("err = %v, want a *RetryableError", err)
	}
}
