package ingest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// Issue #233: a stolen agent token must not grow the database without
// limit. /ingest/events cuts raw at 8192 bytes (UTF-8 safe, with a
// suffix), refuses service over 64 bytes and self_test_marker over the
// minted length (32 hex chars); /ingest/scans gets a per-canary cap of
// 60 requests/min.

const (
	boundsRawMax     = 8192
	boundsRawSuffix  = " [truncated by birdcage]"
	boundsServiceMax = 64
	boundsMarkerMax  = 32 // selftest.MarkerBytes (16) hex-encoded
	boundsScanPerMin = 60
)

// boundsEventBody is one event with the given service, raw and marker.
func boundsEventBody(t *testing.T, service, rawField, marker string) string {
	t.Helper()
	ev := map[string]any{
		"event_id": validEventID1, "source_ip": "203.0.113.9", "dest_port": 22,
		"service": service, "raw": rawField,
	}
	if marker != "" {
		ev["self_test_marker"] = marker
	}
	b, err := json.Marshal(map[string]any{"events": []any{ev}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func boundsPostEvent(t *testing.T, database *db.DB, body string) ackResponse {
	t.Helper()
	raw := mintToken(t, database, "canary-a")
	h := newHandler(database, nil, time.Now, defaultLimiterLimits, store.NewSelfTestIndex(), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, batchRequest(raw, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %.200q)", rec.Code, rec.Body.String())
	}
	var resp ackResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return resp
}

func boundsStoredRaw(t *testing.T, database *db.DB) string {
	t.Helper()
	var got string
	if err := database.QueryRow(`SELECT raw FROM alerts WHERE instance_id = ?`, "canary-a").Scan(&got); err != nil {
		t.Fatalf("read stored raw: %v", err)
	}
	return got
}

// TestHandleBatchTruncatesOverlongRawAtRuneBoundary: raw of 20 KiB made
// of multi-byte runes, with the 8192-byte cut falling at each offset of
// a 1-4 byte rune, is stored valid, within the cap, with the suffix.
func TestHandleBatchTruncatesOverlongRawAtRuneBoundary(t *testing.T) {
	for _, unit := range []string{"é", "€", "\U0001F600"} { // 2, 3, 4 bytes
		for pad := 0; pad < 4; pad++ {
			unit, pad := unit, pad
			t.Run(fmt.Sprintf("%dbyte_pad%d", len(unit), pad), func(t *testing.T) {
				forEachEngine(t, func(t *testing.T, database *db.DB) {
					in := strings.Repeat("a", pad) + strings.Repeat(unit, 20*1024/len(unit))
					resp := boundsPostEvent(t, database, boundsEventBody(t, "ssh", in, ""))
					if len(resp.Stored) != 1 {
						t.Fatalf("event not kept: stored=%v rejected=%v", resp.Stored, resp.Rejected)
					}
					got := boundsStoredRaw(t, database)
					if len(got) > boundsRawMax {
						t.Errorf("stored raw is %d bytes, want <= %d", len(got), boundsRawMax)
					}
					if !utf8.ValidString(got) {
						t.Error("stored raw is not valid UTF-8")
					}
					if !strings.HasSuffix(got, boundsRawSuffix) {
						t.Errorf("stored raw does not end with %q (tail %q)", boundsRawSuffix, got[len(got)-30:])
					}
					body := strings.TrimSuffix(got, boundsRawSuffix)
					if !strings.HasPrefix(in, body) {
						t.Error("stored raw is not a prefix of the input plus suffix")
					}
				})
			})
		}
	}
}

// TestHandleBatchKeepsRawOfExactlyCapWhole: 8192 bytes exactly is not
// truncated and gets no suffix.
func TestHandleBatchKeepsRawOfExactlyCapWhole(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		in := strings.Repeat("x", boundsRawMax)
		resp := boundsPostEvent(t, database, boundsEventBody(t, "ssh", in, ""))
		if len(resp.Stored) != 1 {
			t.Fatalf("event not stored: %+v", resp)
		}
		if got := boundsStoredRaw(t, database); got != in {
			t.Errorf("raw of exactly %d bytes changed: stored %d bytes, suffix=%v",
				boundsRawMax, len(got), strings.HasSuffix(got, boundsRawSuffix))
		}
	})
}

func TestHandleBatchRefusesServiceOverCap(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		resp := boundsPostEvent(t, database, boundsEventBody(t, strings.Repeat("s", boundsServiceMax+1), "hit", ""))
		if len(resp.Stored) != 0 {
			t.Errorf("65-byte service was stored: %v", resp.Stored)
		}
		if reason := resp.Rejected[validEventID1]; reason == "" {
			t.Errorf("65-byte service not rejected: %+v", resp)
		}
	})
}

func TestHandleBatchAcceptsServiceAtCap(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		resp := boundsPostEvent(t, database, boundsEventBody(t, strings.Repeat("s", boundsServiceMax), "hit", ""))
		if len(resp.Stored) != 1 {
			t.Errorf("64-byte service not stored: %+v", resp)
		}
	})
}

func TestHandleBatchRefusesMarkerOverMintedLength(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		resp := boundsPostEvent(t, database, boundsEventBody(t, "ssh", "hit", strings.Repeat("a", boundsMarkerMax+1)))
		if len(resp.Stored) != 0 {
			t.Errorf("33-char marker event was stored: %v", resp.Stored)
		}
		if reason := resp.Rejected[validEventID1]; reason == "" {
			t.Errorf("33-char marker not rejected: %+v", resp)
		}
	})
}

// TestHandleBatchAcceptsMarkerOfMintedLength: a marker of the minted
// length (32 hex chars) is not refused for length; it is an unmatched
// claim, so it is stored as an ordinary real alert.
func TestHandleBatchAcceptsMarkerOfMintedLength(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		resp := boundsPostEvent(t, database, boundsEventBody(t, "ssh", "hit", strings.Repeat("a", boundsMarkerMax)))
		if len(resp.Stored) != 1 {
			t.Errorf("32-char marker event not stored: %+v", resp)
		}
	})
}

// TestHandleScanPerCanaryCapIs60PerMinute: the 61st scan post from one
// canary inside a minute is a 429 with Retry-After; another canary is
// unaffected. Runs against defaultLimiterLimits (shared cap 3000/min),
// so only the new per-canary scan cap can refuse here.
func TestHandleScanPerCanaryCapIs60PerMinute(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanaryKind(t, database, "canary-a", agentkind.Scanner)
		enrollCanaryKind(t, database, "canary-b", agentkind.Scanner)
		rawA := mintToken(t, database, "canary-a")
		rawB := mintToken(t, database, "canary-b")
		// Fixed clock: the limiter refills a token a second, so a real clock
		// lets a slow runner refill one before the 61st post (#251).
		now := time.Now().UTC()
		h := newHandler(database, nil, func() time.Time { return now }, defaultLimiterLimits, store.NewSelfTestIndex(), nil)

		for i := 1; i <= boundsScanPerMin; i++ {
			rec := boundsPost(h, rawA, validScanOKBody)
			if rec.Code != http.StatusOK {
				t.Fatalf("scan %d: status = %d, want 200 (body %.200q)", i, rec.Code, rec.Body.String())
			}
		}
		rec := boundsPost(h, rawA, validScanOKBody)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("61st scan: status = %d, want 429 (body %.200q)", rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Retry-After") == "" {
			t.Error("61st scan: 429 has no Retry-After header")
		}
		if rec := boundsPost(h, rawB, validScanOKBody); rec.Code != http.StatusOK {
			t.Errorf("other canary's first scan: status = %d, want 200 (body %.200q)", rec.Code, rec.Body.String())
		}
	})
}
