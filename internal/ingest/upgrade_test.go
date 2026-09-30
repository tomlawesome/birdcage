package ingest

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// Issue #54's upgrade token over the real ingest mux, mTLS and all
// (credFixture): POST /ingest/upgrade-token, the window it opens, and
// what B4 does and does not stop flagging inside it.

const (
	oldBuild = "1.1.0+old"
	newBuild = "1.2.0+new"
)

func (f *credFixture) beat(t *testing.T, n node, version, localIP string) {
	t.Helper()
	if status, body := f.post(t, "/ingest/heartbeat", n.token, n.cert, map[string]any{"agent_version": version}, localIP); status != http.StatusOK {
		t.Fatalf("heartbeat %s: status = %d, body %s", version, status, body)
	}
}

func (f *credFixture) mint(t *testing.T, n node) string {
	t.Helper()
	raw, _, err := store.MintUpgradeToken(context.Background(), f.database, n.id, newBuild, f.clock.now())
	if err != nil {
		t.Fatalf("MintUpgradeToken: %v", err)
	}
	return raw
}

func (f *credFixture) presentUpgrade(t *testing.T, n node, raw string) ingestUpgradeTokenResponse {
	t.Helper()
	status, body := f.post(t, "/ingest/upgrade-token", n.token, n.cert, map[string]string{"upgrade_token": raw}, "")
	if status != http.StatusOK {
		t.Fatalf("POST /ingest/upgrade-token: status = %d, body %s", status, body)
	}
	var out ingestUpgradeTokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return out
}

// behindNode enrols a honeypot whose agent has reported oldBuild, so a
// token can be minted for it against newBuild.
func behindNode(t *testing.T, f *credFixture, id string) node {
	t.Helper()
	n := f.enrolNode(t, id, agentkind.Honeypot)
	f.beat(t, n, oldBuild, "")
	return n
}

// TestUpgradeTokenOpensTheWindow is the whole design in one run: the
// old build's last heartbeat, the token, the new build's first heartbeat
// seconds later -- no credential_conflict, upgrade_in_progress instead,
// and the old build heartbeating again inside the window is not flagged
// either.
func TestUpgradeTokenOpensTheWindow(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		n := behindNode(t, f, "node-a")
		raw := f.mint(t, n)

		f.clock.advance(5 * time.Second)
		out := f.presentUpgrade(t, n, raw)
		if out.Outcome != "accepted" || out.WindowUntil == "" || out.Reason != "" {
			t.Fatalf("answer = %+v, want accepted with window_until", out)
		}
		if got := auditCount(t, database, "ingest.upgrade_token_accepted", "node-a"); got != 1 {
			t.Errorf("ingest.upgrade_token_accepted rows = %d, want 1", got)
		}

		f.clock.advance(2 * time.Second)
		f.beat(t, n, newBuild, "")
		f.clock.advance(10 * time.Second)
		f.beat(t, n, oldBuild, "") // the old build, not gone yet
		f.clock.advance(10 * time.Second)
		f.beat(t, n, newBuild, "")

		if got := auditCount(t, database, "ingest.credential_dual_use", "node-a"); got != 0 {
			t.Errorf("credential_dual_use rows = %d inside the window, want 0", got)
		}
		if got := auditCount(t, database, "ingest.credential_dual_use_upgrade", "node-a"); got != 1 {
			t.Errorf("credential_dual_use_upgrade rows = %d, want 1 (coalesced)", got)
		}
		c := canaryState(t, database, "node-a", f.clock.now())
		if hasState(c, store.StateCredentialConflict) {
			t.Errorf("credential_conflict inside the window: %v", c.ActiveStates)
		}
		if !hasState(c, store.StateUpgradeInProgress) || c.UpgradeWindowUntil == nil {
			t.Errorf("states %v, window %v; want upgrade_in_progress with its end", c.ActiveStates, c.UpgradeWindowUntil)
		}
	})
}

// TestUpgradeWindowEndsDetection: after the five minutes, the old build
// still heartbeating flags exactly as before.
func TestUpgradeWindowEndsDetection(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		n := behindNode(t, f, "node-a")
		f.presentUpgrade(t, n, f.mint(t, n))
		f.beat(t, n, newBuild, "")

		// The new build heartbeating each minute through the window, and
		// the old one still there when it ends.
		for i := 0; i < 5; i++ {
			f.clock.advance(time.Minute)
			f.beat(t, n, newBuild, "")
		}
		f.clock.advance(10 * time.Second)
		f.beat(t, n, oldBuild, "")
		if got := auditCount(t, database, "ingest.credential_dual_use", "node-a"); got != 1 {
			t.Fatalf("credential_dual_use rows = %d after the window, want 1", got)
		}
		c := canaryState(t, database, "node-a", f.clock.now())
		if !hasState(c, store.StateCredentialConflict) || hasState(c, store.StateUpgradeInProgress) {
			t.Errorf("states = %v, want credential_conflict and no upgrade_in_progress", c.ActiveStates)
		}
	})
}

// TestUpgradeWindowCoversOnlyItsPair: a third build inside the window is
// flagged -- the window covers the old build and birdcage's, nothing
// else.
func TestUpgradeWindowCoversOnlyItsPair(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		n := behindNode(t, f, "node-a")
		f.presentUpgrade(t, n, f.mint(t, n))
		f.beat(t, n, newBuild, "")
		f.clock.advance(5 * time.Second)
		f.beat(t, n, "6.6.6-copy", "")

		c := canaryState(t, database, "node-a", f.clock.now())
		if !hasState(c, store.StateCredentialConflict) || c.CredentialConflict == nil ||
			strings.Join(c.CredentialConflict.Versions, ",") != newBuild+",6.6.6-copy" {
			t.Errorf("states %v, detail %+v; want credential_conflict naming %s and 6.6.6-copy", c.ActiveStates, c.CredentialConflict, newBuild)
		}
	})
}

// TestUpgradeWindowNeverCoversAddresses: the window is for the version
// change only; one credential from two addresses inside it is flagged as
// always.
func TestUpgradeWindowNeverCoversAddresses(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		n := behindNode(t, f, "node-a")
		f.presentUpgrade(t, n, f.mint(t, n))
		f.beat(t, n, newBuild, "127.0.0.1")
		f.clock.advance(5 * time.Second)
		f.beat(t, n, newBuild, "127.0.0.2")

		c := canaryState(t, database, "node-a", f.clock.now())
		if !hasState(c, store.StateCredentialConflict) || c.CredentialConflict == nil ||
			strings.Join(c.CredentialConflict.Addresses, ",") != "127.0.0.1,127.0.0.2" {
			t.Errorf("states %v, detail %+v; want credential_conflict naming both addresses", c.ActiveStates, c.CredentialConflict)
		}
	})
}

// TestUpgradeTokenRefusals: another agent's token, a used one, an
// expired one and one birdcage never minted -- the last being all a
// copied credential could ever present, since minting is a birdcage-host
// CLI -- each gets a 200 "refused" with its reason, is audited, opens no
// window, and leaves the version change flagged. The refusal never names
// the other agent to the presenter.
func TestUpgradeTokenRefusals(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		a := behindNode(t, f, "node-a")
		b := behindNode(t, f, "node-b")

		bToken := f.mint(t, b)
		out := f.presentUpgrade(t, a, bToken)
		if out.Outcome != "refused" || out.Reason != "minted for another agent" || out.WindowUntil != "" {
			t.Errorf("another agent's token: %+v", out)
		}
		spent := f.mint(t, a)
		if out := f.presentUpgrade(t, a, spent); out.Outcome != "accepted" {
			t.Fatalf("a's own token: %+v", out)
		}
		if out := f.presentUpgrade(t, a, spent); out.Outcome != "refused" || out.Reason != "already used" {
			t.Errorf("reused token: %+v", out)
		}
		expired := f.mint(t, b)
		f.clock.advance(store.UpgradeTokenTTL)
		if out := f.presentUpgrade(t, b, expired); out.Outcome != "refused" || out.Reason != "expired" {
			t.Errorf("expired token: %+v", out)
		}
		if out := f.presentUpgrade(t, b, strings.Repeat("ab", 32)); out.Outcome != "refused" || out.Reason != "unknown token" {
			t.Errorf("unknown token: %+v", out)
		}

		var reasons []string
		rows, err := database.Query(`SELECT target, reason FROM audit_log WHERE action = 'ingest.upgrade_token_refused' ORDER BY id`)
		if err != nil {
			t.Fatalf("query refusals: %v", err)
		}
		for rows.Next() {
			var target, reason string
			if err := rows.Scan(&target, &reason); err != nil {
				t.Fatalf("scan: %v", err)
			}
			reasons = append(reasons, target+": "+reason)
		}
		_ = rows.Close()
		want := []string{
			"node-a: upgrade token refused: minted for another agent (node-b); no upgrade window opened",
			"node-a: upgrade token refused: already used; no upgrade window opened",
			"node-b: upgrade token refused: expired; no upgrade window opened",
			"node-b: upgrade token refused: unknown token; no upgrade window opened",
		}
		if strings.Join(reasons, "\n") != strings.Join(want, "\n") {
			t.Errorf("refusal audit rows:\n%s\nwant:\n%s", strings.Join(reasons, "\n"), strings.Join(want, "\n"))
		}

		// b opened nothing: its version change flags.
		f.beat(t, b, newBuild, "")
		f.clock.advance(time.Second)
		f.beat(t, b, oldBuild, "")
		c := canaryState(t, database, "node-b", f.clock.now())
		if !hasState(c, store.StateCredentialConflict) || hasState(c, store.StateUpgradeInProgress) {
			t.Errorf("node-b states = %v, want credential_conflict and no upgrade window", c.ActiveStates)
		}
	})
}

// TestUpgradeTokenMalformedBody: anything but the one-field object is a
// 400, and settles nothing.
func TestUpgradeTokenMalformedBody(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		n := behindNode(t, f, "node-a")
		raw := f.mint(t, n)
		for _, body := range []any{
			map[string]string{"upgrade_token": raw, "canary_id": "node-b"},
			[]string{raw},
		} {
			if status, _ := f.post(t, "/ingest/upgrade-token", n.token, n.cert, body, ""); status != http.StatusBadRequest {
				t.Errorf("body %v: status = %d, want 400", body, status)
			}
		}
		if out := f.presentUpgrade(t, n, raw); out.Outcome != "accepted" {
			t.Errorf("the token after two malformed requests: %+v, want accepted", out)
		}
	})
}

// TestUpgradeTokenNeedsTheCredential: without a valid bearer token the
// route is a 401 like every other, and nothing is settled.
func TestUpgradeTokenNeedsTheCredential(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		n := behindNode(t, f, "node-a")
		raw := f.mint(t, n)
		if status, _ := f.post(t, "/ingest/upgrade-token", strings.Repeat("0", 64), n.cert, map[string]string{"upgrade_token": raw}, ""); status != http.StatusUnauthorized {
			t.Errorf("wrong bearer token: status = %d, want 401", status)
		}
		if out := f.presentUpgrade(t, n, raw); out.Outcome != "accepted" {
			t.Errorf("the token after a 401: %+v, want accepted", out)
		}
	})
}
