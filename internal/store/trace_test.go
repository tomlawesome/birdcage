package store

import (
	"context"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

func TestListTraceBeatsWithinLast15MinutesOnly(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrolledAt := mustParse(t, "2026-09-01T00:00:00Z")
		insertCanary(t, database, Canary{ID: "canary-lan", Name: "canary-lan", Lane: "lan", HeartbeatIntervalS: 60, EnrolledAt: enrolledAt})

		now := mustParse(t, "2026-09-12T22:04:31Z")
		// One beat a minute for the last 20 minutes -- only those within
		// traceBeatWindow (15m) of now must come back.
		for i := 0; i < 20; i++ {
			at := now.Add(-time.Duration(i) * time.Minute)
			if err := RecordHeartbeat(context.Background(), database, "canary-lan", at); err != nil {
				t.Fatalf("RecordHeartbeat: %v", err)
			}
		}

		trace, err := ListTrace(context.Background(), database, now, "14d", rangeDurations["14d"], nil)
		if err != nil {
			t.Fatalf("ListTrace: %v", err)
		}
		if len(trace.Canaries) != 1 {
			t.Fatalf("got %d canaries, want 1", len(trace.Canaries))
		}
		beats := trace.Canaries[0].Beats
		if len(beats) != 16 {
			t.Fatalf("got %d beats, want 16 (minutes 0..15 inclusive of now)", len(beats))
		}
		if !beats[0].Equal(now) {
			t.Errorf("beats[0] = %v, want now (%v), newest first", beats[0], now)
		}
		oldestAllowed := now.Add(-traceBeatWindow)
		if beats[len(beats)-1].Before(oldestAllowed) {
			t.Errorf("beats[last] = %v, older than the 15-minute window (%v)", beats[len(beats)-1], oldestAllowed)
		}
	})
}

func TestListTrace221HitsFromOneSourceArriveWhole(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrolledAt := mustParse(t, "2026-09-01T00:00:00Z")
		insertCanary(t, database, Canary{ID: "canary-iot", Name: "canary-iot", Lane: "iot", HeartbeatIntervalS: 60, EnrolledAt: enrolledAt})

		now := mustParse(t, "2026-09-12T22:04:31Z")
		// Matches the round-6 data story: knocks every 20 minutes,
		// oldest first, well under the 2000 cap.
		for i := 220; i >= 0; i-- {
			at := now.Add(-time.Duration(i) * 20 * time.Minute)
			insertAlertRaw(t, database, "canary-iot", "198.51.100.7", 445, "smb", `{}`, at.Format(time.RFC3339))
		}

		trace, err := ListTrace(context.Background(), database, now, "90d", rangeDurations["90d"], nil)
		if err != nil {
			t.Fatalf("ListTrace: %v", err)
		}
		iot := findTraceCanary(t, trace, "canary-iot")
		if len(iot.Hits) != 221 {
			t.Fatalf("got %d hits, want all 221 to arrive whole", len(iot.Hits))
		}
		for _, h := range iot.Hits {
			if h.Visitor != "198.51.100.7" {
				t.Errorf("hit visitor = %q, want 198.51.100.7", h.Visitor)
			}
		}
	})
}

func TestListTraceCapsAt2000NewestHitsPerCanary(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrolledAt := mustParse(t, "2026-09-01T00:00:00Z")
		insertCanary(t, database, Canary{ID: "canary-guest", Name: "canary-guest", Lane: "guest", HeartbeatIntervalS: 60, EnrolledAt: enrolledAt})

		now := mustParse(t, "2026-09-12T22:04:31Z")
		const total = 2005
		for i := total - 1; i >= 0; i-- {
			at := now.Add(-time.Duration(i) * time.Second)
			insertAlertRaw(t, database, "canary-guest", "203.0.113.42", 23, "telnet", `{}`, at.Format(time.RFC3339))
		}

		trace, err := ListTrace(context.Background(), database, now, "90d", rangeDurations["90d"], nil)
		if err != nil {
			t.Fatalf("ListTrace: %v", err)
		}
		guest := findTraceCanary(t, trace, "canary-guest")
		if len(guest.Hits) != maxHitsPerCanary {
			t.Fatalf("got %d hits, want the cap of %d", len(guest.Hits), maxHitsPerCanary)
		}
		// Newest kept: the very last inserted hit (at == now) must be
		// present, and the oldest 5 (total - cap) must be gone.
		if !guest.Hits[0].At.Equal(now) {
			t.Errorf("Hits[0].At = %v, want %v (newest first)", guest.Hits[0].At, now)
		}
		oldestKept := guest.Hits[len(guest.Hits)-1].At
		wantOldestKept := now.Add(-time.Duration(maxHitsPerCanary-1) * time.Second)
		if !oldestKept.Equal(wantOldestKept) {
			t.Errorf("oldest kept hit = %v, want %v (the cap-th newest)", oldestKept, wantOldestKept)
		}
	})
}

func TestListTraceStatusAndLastHeartbeatFromListCanaries(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrolledAt := mustParse(t, "2026-09-01T00:00:00Z")
		insertCanary(t, database, Canary{ID: "canary-lan", Name: "canary-lan", Lane: "lan", HeartbeatIntervalS: 60, EnrolledAt: enrolledAt})

		beatAt := mustParse(t, "2026-09-12T22:04:22Z")
		if err := RecordHeartbeat(context.Background(), database, "canary-lan", beatAt); err != nil {
			t.Fatalf("RecordHeartbeat: %v", err)
		}

		now := beatAt.Add(9 * time.Second)
		trace, err := ListTrace(context.Background(), database, now, "14d", rangeDurations["14d"], nil)
		if err != nil {
			t.Fatalf("ListTrace: %v", err)
		}
		lan := findTraceCanary(t, trace, "canary-lan")
		if lan.Status != "ok" {
			t.Errorf("Status = %q, want ok", lan.Status)
		}
		if lan.LastHeartbeatAt == nil || !lan.LastHeartbeatAt.Equal(beatAt) {
			t.Errorf("LastHeartbeatAt = %v, want %v", lan.LastHeartbeatAt, beatAt)
		}
		if lan.Lane != "lan" {
			t.Errorf("Lane = %q, want lan", lan.Lane)
		}
	})
}

func TestListTraceHitKindMatchesVisitorClassification(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrolledAt := mustParse(t, "2026-09-01T00:00:00Z")
		insertCanary(t, database, Canary{ID: "canary-lan", Name: "canary-lan", Lane: "lan", HeartbeatIntervalS: 60, EnrolledAt: enrolledAt})
		insertCanary(t, database, Canary{ID: "canary-srv", Name: "canary-srv", Lane: "srv", HeartbeatIntervalS: 60, EnrolledAt: enrolledAt})

		insertAlertRaw(t, database, "canary-lan", "203.0.113.42", 22, "ssh",
			`{"logdata": {"USERNAME": "root", "PASSWORD": "root"}}`, "2026-09-12T21:55:40Z")
		insertAlertRaw(t, database, "canary-srv", "203.0.113.42", 3306, "mysql",
			`{"logdata": {"USERNAME": "root"}}`, "2026-09-12T21:57:22Z")

		now := mustParse(t, "2026-09-12T22:04:31Z")
		trace, err := ListTrace(context.Background(), database, now, "14d", rangeDurations["14d"], nil)
		if err != nil {
			t.Fatalf("ListTrace: %v", err)
		}
		lan := findTraceCanary(t, trace, "canary-lan")
		if len(lan.Hits) != 1 || lan.Hits[0].Kind != KindSweep {
			t.Fatalf("canary-lan hits = %+v, want one sweep hit", lan.Hits)
		}
		if lan.Hits[0].Tried != "root / root" {
			t.Errorf("Tried = %q, want %q", lan.Hits[0].Tried, "root / root")
		}
		if lan.Hits[0].Service != "ssh" {
			t.Errorf("Service = %q, want ssh", lan.Hits[0].Service)
		}
	})
}

func TestListTraceLastHitNilWhenNoAlerts(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		now := mustParse(t, "2026-09-12T22:04:31Z")
		trace, err := ListTrace(context.Background(), database, now, "14d", rangeDurations["14d"], nil)
		if err != nil {
			t.Fatalf("ListTrace: %v", err)
		}
		if trace.LastHit != nil {
			t.Errorf("LastHit = %+v, want nil", trace.LastHit)
		}
	})
}

func TestListTraceLastHitIgnoresRange(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrolledAt := mustParse(t, "2026-08-01T00:00:00Z")
		insertCanary(t, database, Canary{ID: "canary-guest", Name: "canary-guest", Lane: "guest", HeartbeatIntervalS: 60, EnrolledAt: enrolledAt})

		// The one real touch, 23 days before "now" -- the quiet-fortnight
		// scene's own story.
		insertAlertRaw(t, database, "canary-guest", "198.51.100.200", 23, "telnet",
			`{"logdata": {"USERNAME": "root", "PASSWORD": "123456"}}`, "2026-08-13T09:00:00Z")

		now := mustParse(t, "2026-09-05T22:04:31Z")
		// range=15m contains none of the alert above -- last_hit must
		// still find it, proving it is not scoped to the range.
		trace, err := ListTrace(context.Background(), database, now, "15m", rangeDurations["15m"], nil)
		if err != nil {
			t.Fatalf("ListTrace: %v", err)
		}
		lan := findTraceCanary(t, trace, "canary-guest")
		if len(lan.Hits) != 0 {
			t.Fatalf("canary-guest hits within the 15m range = %+v, want none", lan.Hits)
		}

		if trace.LastHit == nil {
			t.Fatal("LastHit = nil, want the 13 Aug touch")
		}
		lh := *trace.LastHit
		if lh.Visitor != "198.51.100.200" || lh.Canary != "canary-guest" || lh.Port != 23 || lh.Service != "telnet" {
			t.Errorf("LastHit = %+v, want the 13 Aug touch's fields", lh)
		}
		if lh.Kind != KindTouch {
			t.Errorf("LastHit.Kind = %q, want touch", lh.Kind)
		}
		if !lh.At.Equal(mustParse(t, "2026-08-13T09:00:00Z")) {
			t.Errorf("LastHit.At = %v, want 2026-08-13T09:00:00Z", lh.At)
		}
	})
}

func TestListTraceLastHitClassifiesAgainstFullHistoryNotJustRange(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrolledAt := mustParse(t, "2026-07-01T00:00:00Z")
		insertCanary(t, database, Canary{ID: "canary-iot", Name: "canary-iot", Lane: "iot", HeartbeatIntervalS: 60, EnrolledAt: enrolledAt})

		// Same source and canary on 3 distinct days, spread far enough
		// apart that no range shorter than ~31 days spans all three.
		insertAlertRaw(t, database, "canary-iot", "198.51.100.7", 445, "smb", `{}`, "2026-08-01T10:00:00Z")
		insertAlertRaw(t, database, "canary-iot", "198.51.100.7", 445, "smb", `{}`, "2026-08-15T10:00:00Z")
		insertAlertRaw(t, database, "canary-iot", "198.51.100.7", 445, "smb", `{}`, "2026-09-01T10:00:05Z")

		now := mustParse(t, "2026-09-01T10:05:00Z")
		// range=15m sees only the newest hit by itself -- classified
		// alone that would be touch, not repeat.
		trace, err := ListTrace(context.Background(), database, now, "15m", rangeDurations["15m"], nil)
		if err != nil {
			t.Fatalf("ListTrace: %v", err)
		}
		if trace.LastHit == nil || trace.LastHit.Kind != KindRepeat {
			t.Fatalf("LastHit = %+v, want kind repeat (classified over the full history, not the 15m range)", trace.LastHit)
		}
	})
}

func findTraceCanary(t *testing.T, trace Trace, id string) TraceCanary {
	t.Helper()
	for _, c := range trace.Canaries {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no canary %q in trace: %+v", id, trace.Canaries)
	return TraceCanary{}
}
