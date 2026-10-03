package client

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
)

// TestRotateTokenReturnsFreshToken proves RotateToken decodes birdcage's
// real rotate response and that the old token keeps working until the
// new one's first use (internal/ingest/rotate.go's own contract) --
// exercised here through this package's own PushBatch, not a peek at
// internal/store.
func TestRotateTokenReturnsFreshToken(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		c, _ := newIngestServer(t, database, agentkind.Honeypot)
		oldToken := mintToken(t, database, "canary-a")

		newToken, err := c.RotateToken(ctx(), oldToken)
		if err != nil {
			t.Fatalf("RotateToken: %v", err)
		}
		if newToken == "" || newToken == oldToken {
			t.Fatalf("newToken = %q, want a non-empty token distinct from %q", newToken, oldToken)
		}

		// Not before the new token's first use: the old one still works.
		if _, err := c.PushBatch(ctx(), oldToken, []Event{{ID: validID1, DestPort: -1, Raw: "{}"}}); err != nil {
			t.Fatalf("old token before new one's first use: %v", err)
		}
		// The new token's first use revokes the old one (#32 item 5).
		if _, err := c.PushBatch(ctx(), newToken, []Event{{ID: validID2, DestPort: -1, Raw: "{}"}}); err != nil {
			t.Fatalf("new token first use: %v", err)
		}
		if _, err := c.PushBatch(ctx(), oldToken, []Event{{ID: validID1, DestPort: -1, Raw: "{}"}}); !IsUnauthorized(err) {
			t.Fatalf("old token after new one's first use: err = %v, want ErrUnauthorized", err)
		}
	})
}

// TestRotateTokenUnauthorized proves a dead token presented to rotate
// surfaces as ErrUnauthorized.
func TestRotateTokenUnauthorized(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		c, _ := newIngestServer(t, database, agentkind.Honeypot)

		_, err := c.RotateToken(ctx(), "not-a-real-token")
		if !IsUnauthorized(err) {
			t.Fatalf("err = %v, want ErrUnauthorized", err)
		}
	})
}

// TestRotateTokenRetryableOn503 proves a whole-request storage failure
// on rotate is reported as retryable, matching
// internal/ingest/rotate.go's own fail-closed rule: "the old token
// stays in use and rotation is retried".
func TestRotateTokenRetryableOn503(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"service unavailable"}`))
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	_, err := c.RotateToken(ctx(), "tok")
	if !IsRetryable(err) {
		t.Fatalf("err = %v, want a *RetryableError", err)
	}
}
