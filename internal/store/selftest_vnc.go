// Package store: this file is #46 slice 2's "challenge-marked" grade,
// vnc alone. Classic RFB authentication is a DES challenge keyed on the
// real VNC password, so there is no attacker-chosen plaintext field a
// marker could ride in the way it does for every other carrier -- but
// OpenCanary's own vnc.py logs both halves verbatim, unvalidated: the
// 16-byte challenge it sent, and whatever 16 bytes the client answered
// (notes 19854, 19855, 19897). internal/agent/probe/vnc.go answers with
// HMAC-SHA256(marker, challenge) truncated to 16 bytes; this file
// recomputes that HMAC for every one of the canary's still-live markers
// and compares it to the logged response.
//
// This is a separate check from SelfTestIndex.match, not a variant of
// it: match asks "does raw contain marker m", a plain substring test
// that works because a marked-grade carrier puts m directly on the wire.
// A vnc response is never m itself -- it is a value only computable by
// someone who holds m, over a challenge that changes every connection --
// so there is nothing in raw for a substring test to find, and the
// verification has to walk the same live-marker set match walks, running
// the HMAC instead of strings.Contains.
package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// vncChallengeLen is RFC 6143 section 7.2.2's own constant: VNC
// Authentication's challenge and response are each exactly 16 bytes.
// Coincidentally equal to selftest.MarkerBytes, but the two are
// unrelated facts -- one is a wire protocol's fixed size, the other
// birdcage's own choice of marker entropy -- so this is its own name
// rather than an alias of that one.
const vncChallengeLen = 16

// vncLogEvent is the shape of the two fields OpenCanary's vnc module
// logs verbatim (vnc.py's _recv_auth: `logdata = {"VNC Server
// Challenge": ..., "VNC Client Response": ...}`), hex-encoded. Every
// other field that module logs (VNC Password) is cosmetic for this
// purpose and left unparsed.
type vncLogEvent struct {
	LogData struct {
		Challenge string `json:"VNC Server Challenge"`
		Response  string `json:"VNC Client Response"`
	} `json:"logdata"`
}

// parseVNCChallenge extracts and hex-decodes raw's challenge/response
// pair. ok is false for anything that does not parse as JSON, is
// missing either field, or decodes to something other than exactly
// vncChallengeLen bytes -- never a panic-worthy condition on a payload
// an attacker controls, just "not a match".
func parseVNCChallenge(raw string) (challenge, response []byte, ok bool) {
	var ev vncLogEvent
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		return nil, nil, false
	}
	c, err := hex.DecodeString(ev.LogData.Challenge)
	if err != nil || len(c) != vncChallengeLen {
		return nil, nil, false
	}
	r, err := hex.DecodeString(ev.LogData.Response)
	if err != nil || len(r) != vncChallengeLen {
		return nil, nil, false
	}
	return c, r, true
}

// verifyVNCChallenge reports whether response is
// HMAC-SHA256(markerHex, challenge), truncated to vncChallengeLen bytes
// -- the same computation internal/agent/probe/vnc.go's carrier makes.
// markerHex that fails to decode as hex (should never happen for a
// marker this package itself minted) reports no match rather than
// erroring: a malformed marker is exactly as unable to explain an event
// as one that never existed. hmac.Equal is constant-time, appropriate
// for comparing a value an on-the-wire attacker can see the outcome of.
func verifyVNCChallenge(markerHex string, challenge, response []byte) bool {
	markerBytes, err := hex.DecodeString(markerHex)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, markerBytes)
	mac.Write(challenge)
	want := mac.Sum(nil)[:vncChallengeLen]
	return hmac.Equal(want, response)
}

// matchVNCChallenge is MatchSelfTest's vnc-only fallback when
// SelfTestIndex.match's plain substring test misses: it walks
// canaryID's still-live markers exactly the way match does -- including
// match's own expiry pruning, so a call here costs a live self-test the
// same bounded work a normal match does -- and reports the first marker
// whose HMAC explains raw's logged challenge/response pair. A raw
// payload with no parseable pair, or one that matches no live marker,
// is not a hit: fail closed, the same answer match gives.
func (idx *SelfTestIndex) matchVNCChallenge(canaryID, raw string, now time.Time) (found bool, marker string) {
	challenge, response, ok := parseVNCChallenge(raw)
	if !ok {
		return false, ""
	}

	idx.mu.Lock()
	defer idx.mu.Unlock()
	markers := idx.byCanary[canaryID]
	for m, expiresAt := range markers {
		if !expiresAt.After(now) {
			delete(markers, m)
			continue
		}
		if verifyVNCChallenge(m, challenge, response) {
			found = true
			marker = m
		}
	}
	if len(markers) == 0 {
		delete(idx.byCanary, canaryID)
	}
	return found, marker
}
