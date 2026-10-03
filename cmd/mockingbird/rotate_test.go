package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/db"
)

var validID1 = strings.Repeat("1", 64)

func newTokenStoreFile(t *testing.T, token string) *TokenStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatalf("seed token file: %v", err)
	}
	ts, err := loadTokenStore(path)
	if err != nil {
		t.Fatalf("loadTokenStore: %v", err)
	}
	return ts
}

// TestRotateWritesTokenDurablyBeforeSwap is the rotation invariant test
// #48 requires: "a token is on disk before it is ever presented." After
// a successful rotate, the token file on disk already holds exactly
// what TokenStore.Current() now returns, at mode 0600, and the *old*
// token still works -- rotation's mint step alone revokes nothing (#32:
// revocation happens only at the new token's first use) -- proving the
// new token was written and swapped without disturbing the old one's
// validity a moment early.
func TestRotateWritesTokenDurablyBeforeSwap(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		c, _ := newIngestServer(t, database)
		oldToken := mintToken(t, database, "canary-a")
		ts := newTokenStoreFile(t, oldToken)

		wait := rotate(context.Background(), c, ts)
		if wait != rotationInterval {
			t.Errorf("wait = %v, want rotationInterval", wait)
		}

		newToken := ts.Current()
		if newToken == "" || newToken == oldToken {
			t.Fatalf("Current() = %q, want a fresh token distinct from %q", newToken, oldToken)
		}

		onDisk, err := os.ReadFile(ts.path)
		if err != nil {
			t.Fatalf("read token file: %v", err)
		}
		if string(onDisk) != newToken {
			t.Fatalf("token file = %q, want %q (must match TokenStore before any request presents it)", onDisk, newToken)
		}
		info, err := os.Stat(ts.path)
		if err != nil {
			t.Fatalf("stat token file: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("token file mode = %v, want 0600", info.Mode().Perm())
		}

		// The old token still works: minting the new one did not
		// revoke it early.
		if _, err := c.PushBatch(ctx(), oldToken, []client.Event{{ID: validID1, DestPort: -1, Raw: "{}"}}); err != nil {
			t.Fatalf("old token still expected to work right after rotation: %v", err)
		}
		// The new token's first use is what revokes the old one.
		if _, err := c.PushBatch(ctx(), newToken, []client.Event{{ID: validID1, DestPort: -1, Raw: "{}"}}); err != nil {
			t.Fatalf("new token first use: %v", err)
		}
		if _, err := c.PushBatch(ctx(), oldToken, []client.Event{{ID: validID1, DestPort: -1, Raw: "{}"}}); !client.IsUnauthorized(err) {
			t.Fatalf("old token after new one's first use: err = %v, want ErrUnauthorized", err)
		}
	})
}

// TestRotateWriteFailureKeepsOldTokenUsable proves #48's fail-closed
// rule: "a write failure discards the new token unused and keeps the
// old." Forced by pointing the token store at a path whose directory
// does not exist, so writeFileAtomic fails deterministically before
// touching anything.
func TestRotateWriteFailureKeepsOldTokenUsable(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, "canary-a")
		c, _ := newIngestServer(t, database)
		oldToken := mintToken(t, database, "canary-a")

		badPath := filepath.Join(t.TempDir(), "no-such-dir", "token")
		ts := &TokenStore{current: oldToken, path: badPath}

		wait := rotate(context.Background(), c, ts)
		if wait != rotationRetryInterval {
			t.Errorf("wait = %v, want rotationRetryInterval", wait)
		}
		if got := ts.Current(); got != oldToken {
			t.Fatalf("Current() = %q, want the old token %q unchanged", got, oldToken)
		}
		if _, err := os.Stat(badPath); !os.IsNotExist(err) {
			t.Fatalf("badPath exists after a failed write: %v", err)
		}

		// The old token is still fully usable: the failed rotation
		// never got far enough to jeopardize it.
		if _, err := c.PushBatch(ctx(), oldToken, []client.Event{{ID: validID1, DestPort: -1, Raw: "{}"}}); err != nil {
			t.Fatalf("old token after a failed rotation write: %v", err)
		}
	})
}

// TestRotateUnauthorizedLogsAndKeepsWaiting proves rotation's own 401
// handling: a dead current token is reported, TokenStore is left
// unchanged (there is nothing to swap to), and rotate schedules the
// ordinary interval rather than spinning.
func TestRotateUnauthorizedLogsAndKeepsWaiting(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		c, _ := newIngestServer(t, database)
		ts := &TokenStore{current: "not-a-real-token", path: filepath.Join(t.TempDir(), "token")}

		wait := rotate(context.Background(), c, ts)
		if wait != rotationInterval {
			t.Errorf("wait = %v, want rotationInterval", wait)
		}
		if got := ts.Current(); got != "not-a-real-token" {
			t.Fatalf("Current() = %q, want unchanged", got)
		}
	})
}

// TestRotateRetryableKeepsWaiting proves a whole-request transport
// failure (503 here) is retried on the shorter interval, current token
// left untouched.
func TestRotateRetryableKeepsWaiting(t *testing.T) {
	ts2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"service unavailable"}`))
	}))
	defer ts2.Close()
	c := newTestClient(t, ts2)
	ts := &TokenStore{current: "tok", path: filepath.Join(t.TempDir(), "token")}

	wait := rotate(context.Background(), c, ts)
	if wait != rotationRetryInterval {
		t.Errorf("wait = %v, want rotationRetryInterval", wait)
	}
	if got := ts.Current(); got != "tok" {
		t.Fatalf("Current() = %q, want unchanged", got)
	}
}
