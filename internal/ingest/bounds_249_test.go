package ingest

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tomlawesome/birdcage/internal/db"
)

// Issue #249 (audit SEC-1): netip.ParseAddr accepts an IPv6 zone of any
// length, so an event's source_ip was bounded only by the body cap. The
// fix caps source_ip at 64 bytes (maxSourceIPBytes) and refuses a longer
// one on the same path as #233's bounds: 200, the event id in rejected,
// the rest of the batch stored.

const sourceIPMax = 64 // maxSourceIPBytes

// zonedSourceIP returns a valid zoned IPv6 address of exactly n bytes.
func zonedSourceIP(n int) string {
	const prefix = "2001:db8::1%"
	return prefix + strings.Repeat("x", n-len(prefix))
}

func sourceIPBatch(t *testing.T, ips ...string) string {
	t.Helper()
	var evs []any
	ids := []string{validEventID1, validEventID2}
	for i, ip := range ips {
		evs = append(evs, map[string]any{
			"event_id": ids[i], "source_ip": ip, "dest_port": 22,
			"service": "ssh", "raw": "hit",
		})
	}
	b, err := json.Marshal(map[string]any{"events": evs})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func alertCount(t *testing.T, database *db.DB) int {
	t.Helper()
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM alerts WHERE instance_id = ?`, "canary-a").Scan(&n); err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	return n
}

func testSourceIPRefused(t *testing.T, bad string) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		resp := boundsPostEvent(t, database, sourceIPBatch(t, bad, "203.0.113.9"))
		if reason := resp.Rejected[validEventID1]; reason != "source_ip too long" {
			t.Errorf("rejected[%s] = %q, want %q (stored=%v)", validEventID1, reason, "source_ip too long", resp.Stored)
		}
		if len(resp.Stored) != 1 || resp.Stored[0] != validEventID2 {
			t.Errorf("stored = %v, want only [%s]", resp.Stored, validEventID2)
		}
		if n := alertCount(t, database); n != 1 {
			t.Errorf("alert rows = %d, want 1 (the over-long source_ip must not be stored)", n)
		}
	})
}

// TestHandleBatchRefusesSourceIPOverCap: a 65-byte zoned address is
// refused and not stored; the other event in the batch is stored.
func TestHandleBatchRefusesSourceIPOverCap(t *testing.T) {
	testSourceIPRefused(t, zonedSourceIP(sourceIPMax+1))
}

// TestHandleBatchRefusesSourceIPOfBodySize: the finding's own case, a
// zone of about 250 KiB (inside maxBodyBytes), is refused and not stored.
func TestHandleBatchRefusesSourceIPOfBodySize(t *testing.T) {
	testSourceIPRefused(t, zonedSourceIP(250*1024))
}

// TestHandleBatchAcceptsSourceIPAtCap: exactly 64 bytes is stored as sent.
func TestHandleBatchAcceptsSourceIPAtCap(t *testing.T) {
	ip := "::ffff:192.0.2.1%" + strings.Repeat("z", 47)
	if len(ip) != sourceIPMax {
		t.Fatalf("test address is %d bytes, want %d", len(ip), sourceIPMax)
	}
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		resp := boundsPostEvent(t, database, sourceIPBatch(t, ip))
		if len(resp.Stored) != 1 || resp.Stored[0] != validEventID1 {
			t.Fatalf("stored = %v, rejected = %v, want [%s] stored", resp.Stored, resp.Rejected, validEventID1)
		}
		var got string
		if err := database.QueryRow(`SELECT source_ip FROM alerts WHERE instance_id = ?`, "canary-a").Scan(&got); err != nil {
			t.Fatalf("read source_ip: %v", err)
		}
		if got != ip {
			t.Errorf("stored source_ip = %q, want %q", got, ip)
		}
	})
}

// TestValidateEventSourceIPBound: the 64-byte cap on validateEvent.
func TestValidateEventSourceIPBound(t *testing.T) {
	cases := []struct {
		name    string
		ip      string
		wantOK  bool
		wantSub string
	}{
		{"65-byte zoned refused", zonedSourceIP(sourceIPMax + 1), false, "source_ip"},
		{"64-byte zoned accepted", zonedSourceIP(sourceIPMax), true, ""},
		{"41-byte IPv4-mapped accepted", "0000:0000:0000:0000:0000:ffff:192.0.2.255", true, ""},
		{"empty accepted", "", true, ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			reason, ok := validateEvent(ingestEvent{EventID: validEventID1, SourceIP: tc.ip, DestPort: 22, Service: "ssh"})
			if ok != tc.wantOK {
				t.Fatalf("ok = %v (reason %q), want %v", ok, reason, tc.wantOK)
			}
			if !tc.wantOK && !strings.Contains(reason, tc.wantSub) {
				t.Errorf("reason = %q, want it to name %q", reason, tc.wantSub)
			}
		})
	}
}
