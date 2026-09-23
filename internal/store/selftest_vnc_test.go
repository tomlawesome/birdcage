package store

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// vncRaw builds the raw JSON OpenCanary's vnc module logs (vnc.py's
// _recv_auth: `{"logdata": {"VNC Server Challenge": ..., "VNC Client
// Response": ...}}`, both hex).
func vncRaw(challenge, response []byte) string {
	return fmt.Sprintf(`{"logdata":{"VNC Server Challenge":"%s","VNC Client Response":"%s"}}`,
		hex.EncodeToString(challenge), hex.EncodeToString(response))
}

func vncChallengeAndCorrectResponse(t *testing.T, markerHex string) (challenge, response []byte) {
	t.Helper()
	challenge = make([]byte, vncChallengeLen)
	if _, err := rand.Read(challenge); err != nil {
		t.Fatalf("generate challenge: %v", err)
	}
	markerBytes, err := hex.DecodeString(markerHex)
	if err != nil {
		t.Fatalf("decode marker: %v", err)
	}
	mac := hmac.New(sha256.New, markerBytes)
	mac.Write(challenge)
	response = mac.Sum(nil)[:vncChallengeLen]
	return challenge, response
}

// mintVNCSelfTestCommand mints a single vnc:5900 target and returns its
// marker, the same helper shape mintSelfTestCommand (selftest_test.go)
// uses for ssh.
func mintVNCSelfTestCommand(t *testing.T, database *db.DB, idx *SelfTestIndex, canaryID string, createdAt time.Time, ttl time.Duration) string {
	t.Helper()
	cmd, err := MintSelfTestCommand(context.Background(), database, idx, canaryID, "192.0.2.10",
		[]SelfTestTarget{{Service: "vnc", DestPort: 5900}}, createdAt, createdAt.Add(ttl))
	if err != nil {
		t.Fatalf("MintSelfTestCommand(vnc): %v", err)
	}
	return mustDecodeParams(t, cmd).Targets[0].Marker
}

// TestMatchSelfTestVNCCorrectHMACMatches is #46 slice 2's challenge-marked
// grade, the match half: an event carrying the challenge OpenCanary's vnc
// module logged and the correct HMAC-SHA256(marker, challenge) response
// is recognised as this run's own probe.
func TestMatchSelfTestVNCCorrectHMACMatches(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{ID: "canary-a", Name: "a", Lane: "l", Ports: "vnc 5900", EnrolledAt: time.Now()})
		idx := NewSelfTestIndex()
		now := time.Now()
		marker := mintVNCSelfTestCommand(t, database, idx, "canary-a", now, time.Hour)
		challenge, response := vncChallengeAndCorrectResponse(t, marker)

		alert := AlertInsert{InstanceID: "canary-a", Service: "vnc", DestPort: 5900, Raw: vncRaw(challenge, response)}
		matched, err := MatchSelfTest(context.Background(), database, idx, alert, now)
		if err != nil {
			t.Fatalf("MatchSelfTest: %v", err)
		}
		if !matched {
			t.Fatal("a correct HMAC response to the logged challenge did not match")
		}
	})
}

// TestMatchSelfTestVNCWrongHMACStaysReal is the non-match half the slice
// 2 brief requires explicitly: a response that does not verify against
// any live marker -- here, one that simply is not the HMAC of the
// marker birdcage minted -- is not waved through. An intruder who merely
// observed the challenge (or guessed a response) cannot forge a hit.
func TestMatchSelfTestVNCWrongHMACStaysReal(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{ID: "canary-a", Name: "a", Lane: "l", Ports: "vnc 5900", EnrolledAt: time.Now()})
		idx := NewSelfTestIndex()
		now := time.Now()
		marker := mintVNCSelfTestCommand(t, database, idx, "canary-a", now, time.Hour)
		challenge, correctResponse := vncChallengeAndCorrectResponse(t, marker)

		wrongResponse := make([]byte, vncChallengeLen)
		copy(wrongResponse, correctResponse)
		wrongResponse[0] ^= 0xFF // flip a bit: no longer the marker's HMAC over this challenge

		alert := AlertInsert{InstanceID: "canary-a", Service: "vnc", DestPort: 5900, Raw: vncRaw(challenge, wrongResponse)}
		matched, err := MatchSelfTest(context.Background(), database, idx, alert, now)
		if err != nil {
			t.Fatalf("MatchSelfTest: %v", err)
		}
		if matched {
			t.Fatal("a response that is not the marker's HMAC over the logged challenge was treated as a match")
		}
	})
}

// TestMatchSelfTestVNCUnparseableRawStaysReal: a vnc-service alert whose
// raw payload has no parseable challenge/response pair (a real intrusion
// attempt, not shaped like a self-test at all) must not panic and must
// not match -- fail closed, the same as an unrecognised marked-grade
// payload.
func TestMatchSelfTestVNCUnparseableRawStaysReal(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{ID: "canary-a", Name: "a", Lane: "l", Ports: "vnc 5900", EnrolledAt: time.Now()})
		idx := NewSelfTestIndex()
		now := time.Now()
		mintVNCSelfTestCommand(t, database, idx, "canary-a", now, time.Hour)

		alert := AlertInsert{InstanceID: "canary-a", Service: "vnc", DestPort: 5900, Raw: `{"logdata":{"VNC Password":"password"}}`}
		matched, err := MatchSelfTest(context.Background(), database, idx, alert, now)
		if err != nil {
			t.Fatalf("MatchSelfTest: %v", err)
		}
		if matched {
			t.Fatal("a vnc alert with no challenge/response pair at all was treated as a match")
		}
	})
}
