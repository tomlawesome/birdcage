package store

import (
	"context"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/selftest"
)

func mintSelfTestCommand(t *testing.T, database *db.DB, canaryID string, createdAt time.Time, ttl time.Duration) CanaryCommand {
	t.Helper()
	cmd, err := MintSelfTestCommand(context.Background(), database, canaryID, "192.0.2.10",
		[]SelfTestTarget{{Service: "ssh", DestPort: 22}}, createdAt, createdAt.Add(ttl))
	if err != nil {
		t.Fatalf("MintSelfTestCommand(%s): %v", canaryID, err)
	}
	return cmd
}

func mustDecodeParams(t *testing.T, cmd CanaryCommand) selftest.Params {
	t.Helper()
	p, err := selftest.DecodeParams([]byte(cmd.Params))
	if err != nil {
		t.Fatalf("decode minted params: %v", err)
	}
	return p
}

// TestMintSelfTestCommandGeneratesUnguessableMarkers is #46 settled
// decision 4 in test form: markers come from crypto/rand, one per
// target, never repeated -- an attacker who could predict one could get
// their own traffic classified as a test and kept off the dashboard.
func TestMintSelfTestCommandGeneratesUnguessableMarkers(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{ID: "canary-a", Name: "a", Lane: "l", Ports: "ssh 22", EnrolledAt: time.Now()})
		now := time.Now()
		cmd, err := MintSelfTestCommand(context.Background(), database, "canary-a", "192.0.2.10",
			[]SelfTestTarget{{Service: "ssh", DestPort: 22}, {Service: "ftp", DestPort: 21}},
			now, now.Add(time.Hour))
		if err != nil {
			t.Fatalf("MintSelfTestCommand: %v", err)
		}
		params := mustDecodeParams(t, cmd)
		if len(params.Targets) != 2 {
			t.Fatalf("targets = %d, want 2", len(params.Targets))
		}
		if params.Targets[0].Marker == "" || params.Targets[1].Marker == "" {
			t.Fatal("marker was left empty")
		}
		if params.Targets[0].Marker == params.Targets[1].Marker {
			t.Fatal("two targets in the same run share a marker")
		}
		if len(params.Targets[0].Marker) != selftest.MarkerBytes*2 { // hex-encoded
			t.Fatalf("marker length = %d, want %d hex chars", len(params.Targets[0].Marker), selftest.MarkerBytes*2)
		}

		// A second mint must never reuse a marker from the first.
		cmd2, err := MintSelfTestCommand(context.Background(), database, "canary-a", "192.0.2.10",
			[]SelfTestTarget{{Service: "ssh", DestPort: 22}}, now, now.Add(time.Hour))
		if err != nil {
			t.Fatalf("MintSelfTestCommand (second): %v", err)
		}
		params2 := mustDecodeParams(t, cmd2)
		if params2.Targets[0].Marker == params.Targets[0].Marker {
			t.Fatal("marker reused across separate mints")
		}
	})
}

// TestMatchSelfTestRecognisesAnIssuedMarker: an alert carrying a marker
// birdcage actually planted, for the canary it was planted on, before
// expiry, is a self-test hit.
func TestMatchSelfTestRecognisesAnIssuedMarker(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{ID: "canary-a", Name: "a", Lane: "l", Ports: "ssh 22", EnrolledAt: time.Now()})
		now := time.Now()
		cmd := mintSelfTestCommand(t, database, "canary-a", now, time.Hour)
		marker := mustDecodeParams(t, cmd).Targets[0].Marker

		alert := AlertInsert{
			InstanceID: "canary-a",
			DestPort:   22,
			Service:    "ssh",
			Raw:        `{"logdata":{"probe":"` + marker + `"}}`,
		}
		matched, err := MatchSelfTest(context.Background(), database, alert, now)
		if err != nil {
			t.Fatalf("MatchSelfTest: %v", err)
		}
		if !matched {
			t.Fatal("issued marker on the right canary before expiry did not match")
		}
	})
}

// TestMatchSelfTestExpiredCommandDoesNotMatch: expiry is judged in Go on
// parsed RFC3339Nano, never in SQL (ClaimNextCanaryCommand's own rule) --
// a marker from a command that has since expired must not suppress a
// real alert forever.
func TestMatchSelfTestExpiredCommandDoesNotMatch(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{ID: "canary-a", Name: "a", Lane: "l", Ports: "ssh 22", EnrolledAt: time.Now()})
		createdAt := time.Now().Add(-time.Hour)
		cmd := mintSelfTestCommand(t, database, "canary-a", createdAt, time.Minute) // expires 59 minutes ago
		marker := mustDecodeParams(t, cmd).Targets[0].Marker

		alert := AlertInsert{InstanceID: "canary-a", Raw: `{"probe":"` + marker + `"}`}
		matched, err := MatchSelfTest(context.Background(), database, alert, time.Now())
		if err != nil {
			t.Fatalf("MatchSelfTest: %v", err)
		}
		if matched {
			t.Fatal("a marker from an expired command was treated as a live self-test")
		}
	})
}

// TestMatchSelfTestNeverIssuedMarkerIsReal is #46's core security
// property: an intruder producing something test-shaped -- here, a
// plausible-looking marker that birdcage never actually minted -- must
// still raise a real alert, not be waved through as a self-test.
func TestMatchSelfTestNeverIssuedMarkerIsReal(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{ID: "canary-a", Name: "a", Lane: "l", Ports: "ssh 22", EnrolledAt: time.Now()})
		now := time.Now()
		mintSelfTestCommand(t, database, "canary-a", now, time.Hour) // issues its own, unrelated marker

		// Same shape and length as a real hex marker, but never minted.
		guessed := "0123456789abcdef0123456789abcdef"[:selftest.MarkerBytes*2]
		alert := AlertInsert{InstanceID: "canary-a", Raw: `{"probe":"` + guessed + `"}`}
		matched, err := MatchSelfTest(context.Background(), database, alert, now)
		if err != nil {
			t.Fatalf("MatchSelfTest: %v", err)
		}
		if matched {
			t.Fatal("an unissued, merely plausible-looking marker was treated as a self-test")
		}
	})
}

// TestMatchSelfTestDifferentCanaryDoesNotMatch: a marker issued for one
// canary must not suppress an alert arriving on another, even though
// nothing about the marker itself reveals which canary it belongs to.
func TestMatchSelfTestDifferentCanaryDoesNotMatch(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{ID: "canary-a", Name: "a", Lane: "l", Ports: "ssh 22", EnrolledAt: time.Now()})
		insertCanary(t, database, Canary{ID: "canary-b", Name: "b", Lane: "l", Ports: "ssh 22", EnrolledAt: time.Now()})
		now := time.Now()
		cmd := mintSelfTestCommand(t, database, "canary-a", now, time.Hour)
		marker := mustDecodeParams(t, cmd).Targets[0].Marker

		alert := AlertInsert{InstanceID: "canary-b", Raw: `{"probe":"` + marker + `"}`}
		matched, err := MatchSelfTest(context.Background(), database, alert, now)
		if err != nil {
			t.Fatalf("MatchSelfTest: %v", err)
		}
		if matched {
			t.Fatal("a marker issued for canary-a matched an alert from canary-b")
		}
	})
}

// TestMatchSelfTestUnknownCanaryIsReal: an alert naming a canary with no
// commands at all (unknown, or simply never issued a self-test) has
// nothing to match against, so it stays real -- the same fail-closed
// answer as an expired or never-issued marker.
func TestMatchSelfTestUnknownCanaryIsReal(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		alert := AlertInsert{InstanceID: "no-such-canary", Raw: `{"probe":"anything"}`}
		matched, err := MatchSelfTest(context.Background(), database, alert, time.Now())
		if err != nil {
			t.Fatalf("MatchSelfTest: %v", err)
		}
		if matched {
			t.Fatal("an unknown canary with no issued commands matched")
		}
	})
}
