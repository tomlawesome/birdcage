package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/event"
	"github.com/tomlawesome/birdcage/internal/agent/queue"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/selftest"
	"github.com/tomlawesome/birdcage/internal/store"
)

// portscanFixtureEvent builds an OpenCanary-shaped portscan detection
// (internal/agent/portscan/event.go's own wire shape, logtype 5001 ->
// service "portscan"), from srcAddr -- the address a self-test's own
// probe would have used, dialing the canary's own LAN address (#46
// settled decision 2).
func portscanFixtureEvent(srcAddr string, srcPort int) string {
	return fmt.Sprintf(`{"dst_host": "203.0.113.9", "dst_port": 54321, "logdata": {"COUNT": "5", "PORTS": "54321,54322", "PROTO": "tcp"}, "logtype": 5001, "node_id": "canary-a", "src_host": %q, "src_port": %d, "local_time": "2026-01-01 00:00:00.000000", "utc_time": "2026-01-01 00:00:00.000000"}`, srcAddr, srcPort)
}

// mintAttributedTargetAgainstRealDB mints one portscan (attributed
// grade) self-test target for testCanaryID at addr, against the real
// database newIngestServer's handler reads from -- its own SelfTestIndex
// is private to that handler, so this uses a throwaway index of its own;
// MatchSelfTestClaim's ensureLoaded picks the freshly minted command up
// from canary_commands on the handler's first use, the same lazy-load
// path a restarted birdcage process relies on.
func mintAttributedTargetAgainstRealDB(t *testing.T, database *db.DB, addr string, now time.Time, ttl time.Duration) string {
	t.Helper()
	if err := store.SetCanaryLastSeenAddr(context.Background(), database, testCanaryID, addr); err != nil {
		t.Fatalf("SetCanaryLastSeenAddr: %v", err)
	}
	throwawayIdx := store.NewSelfTestIndex()
	cmd, err := store.MintSelfTestCommand(context.Background(), database, throwawayIdx, testCanaryID, addr,
		[]store.SelfTestTarget{{Service: "portscan", DestPort: 0}}, now, now.Add(ttl))
	if err != nil {
		t.Fatalf("MintSelfTestCommand: %v", err)
	}
	params, err := selftest.DecodeParams([]byte(cmd.Params))
	if err != nil {
		t.Fatalf("decode minted params: %v", err)
	}
	return params.Targets[0].Marker
}

// TestClaimReachesBirdcageSynthetic is #46 slice 3's end-to-end proof:
// an attributed-grade event the claim window decided to claim carries
// self_test_marker onto the real wire (client.PushBatch), and birdcage's
// real ingest handler corroborates and stores it synthetic -- the same
// path a real portscan self-test round trip takes, short of the actual
// probe and detector.
func TestClaimReachesBirdcageSynthetic(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, testCanaryID)
		c, _ := newIngestServer(t, database)
		token := mintToken(t, database, testCanaryID)

		addr := "198.51.100.5"
		now := time.Now().UTC()
		marker := mintAttributedTargetAgainstRealDB(t, database, addr, now, time.Hour)

		in, _ := newTestIntake(t, queue.Config{})
		w := in.claims.startWindow("portscan", addr, marker)

		message := portscanFixtureEvent(addr, 54321)
		id, err := event.IDFromEmittedMessage([]byte(message))
		if err != nil {
			t.Fatalf("IDFromEmittedMessage: %v", err)
		}
		if err := in.SubmitPortscanEvent([]byte(message)); err != nil {
			t.Fatalf("SubmitPortscanEvent: %v", err)
		}
		if !in.claims.pending(id) {
			t.Fatal("the portscan event was not recorded as a claim candidate")
		}

		in.claims.resolveWindow(w) // exactly one candidate: claimed
		if gotMarker, ok := in.claims.marker(id); !ok || gotMarker != marker {
			t.Fatalf("marker(%s) = (%q, %v), want (%q, true)", id, gotMarker, ok, marker)
		}

		runCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go runSenderLoop(runCtx, c, newTokenStoreForTest(token), in, newPacer())

		alerts := waitForAlertCount(t, database, testCanaryID, 1, 5*time.Second)
		if !alerts[0].Synthetic {
			t.Fatalf("alert = %+v, want synthetic = true (a claimed event birdcage corroborated)", alerts[0])
		}
	})
}

// TestUnclaimedAttributedEventReachesBirdcageReal is the negative
// control: a portscan-shaped event that arrived outside any claim window
// carries no self_test_marker at all, and birdcage stores it as an
// ordinary real alert -- exactly the "zero candidates" and "late event"
// outcomes' consequence once the event actually reaches the wire.
func TestUnclaimedAttributedEventReachesBirdcageReal(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, testCanaryID)
		c, _ := newIngestServer(t, database)
		token := mintToken(t, database, testCanaryID)

		in, _ := newTestIntake(t, queue.Config{})
		message := portscanFixtureEvent("198.51.100.5", 54321)
		if err := in.SubmitPortscanEvent([]byte(message)); err != nil {
			t.Fatalf("SubmitPortscanEvent: %v", err)
		}

		runCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go runSenderLoop(runCtx, c, newTokenStoreForTest(token), in, newPacer())

		alerts := waitForAlertCount(t, database, testCanaryID, 1, 5*time.Second)
		if alerts[0].Synthetic {
			t.Fatalf("alert = %+v, want synthetic = false (no claim was ever made)", alerts[0])
		}
	})
}
