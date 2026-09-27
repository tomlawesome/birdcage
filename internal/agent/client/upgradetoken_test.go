package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// TestPresentUpgradeTokenAgainstRealIngest drives internal/ingest's own
// handler: accepted once, then refused as already used, and an unknown
// bearer token is ErrUnauthorized -- so this package's wire types cannot
// drift from the route's.
func TestPresentUpgradeTokenAgainstRealIngest(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		c, _ := newIngestServer(t, database, agentkind.Honeypot)
		bearer := mintToken(t, database, testCanaryID)
		if _, err := c.SendHeartbeat(ctx(), bearer, SelfReport{LogReadOK: true, AgentVersion: "1.0.0"}); err != nil {
			t.Fatalf("SendHeartbeat: %v", err)
		}
		raw, _, err := store.MintUpgradeToken(ctx(), database, testCanaryID, "1.1.0", time.Now().UTC())
		if err != nil {
			t.Fatalf("MintUpgradeToken: %v", err)
		}

		answer, err := c.PresentUpgradeToken(ctx(), bearer, raw)
		if err != nil || !answer.Accepted || answer.WindowUntil.IsZero() {
			t.Fatalf("first presentation = %+v, %v; want accepted with a window end", answer, err)
		}
		answer, err = c.PresentUpgradeToken(ctx(), bearer, raw)
		if err != nil || answer.Accepted || answer.Reason != "already used" {
			t.Errorf("second presentation = %+v, %v; want refused, already used", answer, err)
		}
		if _, err := c.PresentUpgradeToken(ctx(), "not-a-real-token", raw); !IsUnauthorized(err) {
			t.Errorf("unknown bearer: err = %v, want ErrUnauthorized", err)
		}
	})
}

// TestPresentUpgradeTokenStatuses: what each answer birdcage can give
// becomes -- retryable for anything that settled nothing, final for a
// 400.
func TestPresentUpgradeTokenStatuses(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		body      string
		retryable bool
		malformed bool
	}{
		{"503", http.StatusServiceUnavailable, `{"error":"service unavailable"}`, true, false},
		{"429", http.StatusTooManyRequests, `{"error":"rate limit exceeded"}`, true, false},
		{"200 unreadable", http.StatusOK, `not json`, true, false},
		{"200 unknown outcome", http.StatusOK, `{"outcome":"maybe"}`, true, false},
		{"400", http.StatusBadRequest, `{"error":"malformed upgrade token body"}`, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotBody string
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				gotBody = string(b)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(ts.Close)
			c := newTestClient(t, ts)
			tok := strings.Repeat("ab", 32)
			_, err := c.PresentUpgradeToken(ctx(), "bearer", tok)
			if IsRetryable(err) != tc.retryable {
				t.Errorf("err = %v, retryable = %v, want %v", err, IsRetryable(err), tc.retryable)
			}
			if (err == ErrUpgradeTokenMalformed) != tc.malformed {
				t.Errorf("err = %v, want malformed = %v", err, tc.malformed)
			}
			if gotBody != `{"upgrade_token":"`+tok+`"}` {
				t.Errorf("request body = %s", gotBody)
			}
		})
	}
}
