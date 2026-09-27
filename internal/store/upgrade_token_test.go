package store

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
)

var upgradeT0 = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

// upgradeAgent inserts agent id reporting agentVersion on a heartbeat at
// upgradeT0.
func upgradeAgent(t *testing.T, database *db.DB, id, agentVersion string) {
	t.Helper()
	ctx := context.Background()
	if err := InsertCanary(ctx, database, Canary{
		ID: id, Name: id, Lane: "lan", Kind: agentkind.Honeypot, Ports: "22", HeartbeatIntervalS: 60, EnrolledAt: upgradeT0.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("InsertCanary: %v", err)
	}
	if err := RecordCanaryAgentHeartbeat(ctx, database, id, upgradeT0, AgentHeartbeat{LogReadOK: true, AgentVersion: agentVersion}); err != nil {
		t.Fatalf("RecordCanaryAgentHeartbeat: %v", err)
	}
}

func mintUpgrade(t *testing.T, database *db.DB, id string, at time.Time) (string, UpgradeToken) {
	t.Helper()
	raw, tok, err := MintUpgradeToken(context.Background(), database, id, "1.2.0+new", at)
	if err != nil {
		t.Fatalf("MintUpgradeToken: %v", err)
	}
	return raw, tok
}

func present(t *testing.T, database *db.DB, id, raw string, at time.Time) UpgradeTokenResult {
	t.Helper()
	res, err := PresentUpgradeToken(context.Background(), database, id, raw, at)
	if err != nil {
		t.Fatalf("PresentUpgradeToken: %v", err)
	}
	return res
}

// TestMintUpgradeTokenStoresOnlyTheHash: the raw token is 64 hex
// characters and never stored; the row holds its SHA-256, a 15-minute
// expiry and the version pair the window will cover.
func TestMintUpgradeTokenStoresOnlyTheHash(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		upgradeAgent(t, database, "a1", "1.1.0+old")
		raw, tok := mintUpgrade(t, database, "a1", upgradeT0)
		if !validUpgradeTokenShape(raw) {
			t.Fatalf("raw token %q is not 64 lowercase hex characters", raw)
		}
		if tok.FromVersion != "1.1.0+old" || tok.ToVersion != "1.2.0+new" {
			t.Errorf("versions = %q -> %q, want 1.1.0+old -> 1.2.0+new", tok.FromVersion, tok.ToVersion)
		}
		if !tok.ExpiresAt.Equal(upgradeT0.Add(UpgradeTokenTTL)) {
			t.Errorf("expires = %v, want %v", tok.ExpiresAt, upgradeT0.Add(UpgradeTokenTTL))
		}
		var hash string
		if err := database.QueryRow(`SELECT token_hash FROM upgrade_tokens WHERE id = ?`, tok.ID).Scan(&hash); err != nil {
			t.Fatalf("read row: %v", err)
		}
		if hash != HashToken(raw) || strings.Contains(hash, raw) {
			t.Errorf("token_hash = %q, want HashToken(raw) and never the raw value", hash)
		}
	})
}

// TestMintUpgradeTokenRefusals: an unknown agent, and an agent that is
// not behind (current, newer, or never reported), get no token.
func TestMintUpgradeTokenRefusals(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		if _, _, err := MintUpgradeToken(ctx, database, "nope", "1.2.0", upgradeT0); !errors.Is(err, ErrCanaryNotFound) {
			t.Errorf("unknown agent: err = %v, want ErrCanaryNotFound", err)
		}
		upgradeAgent(t, database, "cur", "1.2.0+other")
		upgradeAgent(t, database, "dev", "dev")
		for _, id := range []string{"cur", "dev"} {
			if _, _, err := MintUpgradeToken(ctx, database, id, "1.2.0+new", upgradeT0); !errors.Is(err, ErrAgentNotBehind) {
				t.Errorf("%s: err = %v, want ErrAgentNotBehind", id, err)
			}
		}
		var n int
		if err := database.QueryRow(`SELECT COUNT(*) FROM upgrade_tokens`).Scan(&n); err != nil || n != 0 {
			t.Errorf("rows = %d (%v), want 0", n, err)
		}
	})
}

// TestPresentUpgradeTokenAcceptsOnce: the right agent's unused,
// unexpired token opens a window of exactly UpgradeWindow; the second
// presentation opens nothing.
func TestPresentUpgradeTokenAcceptsOnce(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		upgradeAgent(t, database, "a1", "1.1.0+old")
		raw, _ := mintUpgrade(t, database, "a1", upgradeT0)

		at := upgradeT0.Add(14 * time.Minute)
		res := present(t, database, "a1", raw, at)
		if res.Outcome != UpgradeTokenAccepted {
			t.Fatalf("outcome = %v, want accepted", res.Outcome)
		}
		if !res.WindowUntil.Equal(at.Add(UpgradeWindow)) || res.FromVersion != "1.1.0+old" || res.ToVersion != "1.2.0+new" {
			t.Errorf("result = %+v, want a %v window for 1.1.0+old -> 1.2.0+new", res, UpgradeWindow)
		}
		if res := present(t, database, "a1", raw, at.Add(time.Second)); res.Outcome != UpgradeTokenSpent {
			t.Errorf("second presentation: outcome = %v, want already used", res.Outcome)
		}
		until, err := OpenUpgradeWindowUntil(context.Background(), database, "a1", at.Add(time.Second))
		if err != nil || until == nil || !until.Equal(at.Add(UpgradeWindow)) {
			t.Errorf("OpenUpgradeWindowUntil = %v, %v; want the first window's end, unchanged", until, err)
		}
	})
}

// TestPresentUpgradeTokenRefusals: every refusal opens nothing.
func TestPresentUpgradeTokenRefusals(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		upgradeAgent(t, database, "a1", "1.1.0")
		upgradeAgent(t, database, "a2", "1.1.0")

		wrong, _ := mintUpgrade(t, database, "a2", upgradeT0)
		if res := present(t, database, "a1", wrong, upgradeT0); res.Outcome != UpgradeTokenWrongAgent || res.TokenCanaryID != "a2" {
			t.Errorf("another agent's token: %+v, want wrong agent (a2)", res)
		}
		// Still a2's to spend: the refusal did not burn it.
		if res := present(t, database, "a2", wrong, upgradeT0); res.Outcome != UpgradeTokenAccepted {
			t.Errorf("a2's own token after a1's refusal: %v, want accepted", res.Outcome)
		}
		// Spent and another agent's: still reported as another agent's.
		if res := present(t, database, "a1", wrong, upgradeT0); res.Outcome != UpgradeTokenWrongAgent {
			t.Errorf("another agent's spent token: %v, want wrong agent", res.Outcome)
		}

		expired, _ := mintUpgrade(t, database, "a1", upgradeT0)
		if res := present(t, database, "a1", expired, upgradeT0.Add(UpgradeTokenTTL)); res.Outcome != UpgradeTokenExpired {
			t.Errorf("at expiry: %v, want expired", res.Outcome)
		}

		older, _ := mintUpgrade(t, database, "a1", upgradeT0)
		newer, _ := mintUpgrade(t, database, "a1", upgradeT0.Add(time.Minute))
		if res := present(t, database, "a1", older, upgradeT0.Add(2*time.Minute)); res.Outcome != UpgradeTokenSuperseded {
			t.Errorf("superseded token: %v, want superseded", res.Outcome)
		}

		for _, raw := range []string{strings.Repeat("0", 64), "", "not-a-token", strings.ToUpper(newer), newer + "0"} {
			if res := present(t, database, "a1", raw, upgradeT0); res.Outcome != UpgradeTokenUnknown {
				t.Errorf("token %q: %v, want unknown", raw, res.Outcome)
			}
		}

		if until, err := OpenUpgradeWindowUntil(ctx, database, "a1", upgradeT0.Add(3*time.Minute)); err != nil || until != nil {
			t.Errorf("a1 has a window after nothing but refusals: %v, %v", until, err)
		}
		// The newer token is still good.
		if res := present(t, database, "a1", newer, upgradeT0.Add(3*time.Minute)); res.Outcome != UpgradeTokenAccepted {
			t.Errorf("newer token: %v, want accepted", res.Outcome)
		}
	})
}

// TestPresentUpgradeTokenConcurrent: of many simultaneous presentations
// of one token, exactly one is accepted.
func TestPresentUpgradeTokenConcurrent(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		upgradeAgent(t, database, "a1", "1.1.0")
		raw, _ := mintUpgrade(t, database, "a1", upgradeT0)

		const n = 8
		var wg sync.WaitGroup
		results := make([]UpgradeTokenResult, n)
		errs := make([]error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i], errs[i] = PresentUpgradeToken(context.Background(), database, "a1", raw, upgradeT0.Add(time.Minute))
			}(i)
		}
		wg.Wait()
		accepted := 0
		for i := range results {
			if errs[i] != nil {
				t.Fatalf("presentation %d: %v", i, errs[i])
			}
			switch results[i].Outcome {
			case UpgradeTokenAccepted:
				accepted++
			case UpgradeTokenSpent:
			default:
				t.Errorf("presentation %d: %v, want accepted or already used", i, results[i].Outcome)
			}
		}
		if accepted != 1 {
			t.Errorf("accepted %d times, want exactly 1", accepted)
		}
	})
}

// TestUpgradeWindowCovers: only the exact pair, either order, only for
// that agent, only inside the window.
func TestUpgradeWindowCovers(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		upgradeAgent(t, database, "a1", "1.1.0+old")
		upgradeAgent(t, database, "a2", "1.1.0+old")
		raw, _ := mintUpgrade(t, database, "a1", upgradeT0)
		opened := upgradeT0.Add(time.Minute)
		present(t, database, "a1", raw, opened)

		cases := []struct {
			name, id, a, b string
			at             time.Time
			want           bool
		}{
			{"old then new", "a1", "1.1.0+old", "1.2.0+new", opened, true},
			{"new then old", "a1", "1.2.0+new", "1.1.0+old", opened.Add(UpgradeWindow - time.Nanosecond), true},
			{"a third version", "a1", "1.1.0+old", "9.9.9", opened, false},
			{"same core, other build", "a1", "1.1.0+other", "1.2.0+new", opened, false},
			{"window ended", "a1", "1.1.0+old", "1.2.0+new", opened.Add(UpgradeWindow), false},
			{"another agent", "a2", "1.1.0+old", "1.2.0+new", opened, false},
		}
		for _, c := range cases {
			got, err := UpgradeWindowCovers(ctx, database, c.id, c.a, c.b, c.at)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if got != c.want {
				t.Errorf("%s: covers = %v, want %v", c.name, got, c.want)
			}
		}
	})
}

// TestUpgradeInProgressState: ListCanaries shows upgrade_in_progress,
// ranked straight before agent_out_of_date, with the window's end, from
// acceptance until the window ends, and not after.
func TestUpgradeInProgressState(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		upgradeAgent(t, database, "a1", "1.1.0")
		raw, _ := mintUpgrade(t, database, "a1", upgradeT0)

		list := func(at time.Time) Canary {
			t.Helper()
			cs, err := ListCanaries(ctx, database, at, time.Hour, "1.2.0+new")
			if err != nil || len(cs) != 1 {
				t.Fatalf("ListCanaries = %v, %v", cs, err)
			}
			return cs[0]
		}
		if c := list(upgradeT0.Add(time.Second)); c.UpgradeWindowUntil != nil || strings.Contains(strings.Join(c.ActiveStates, ","), "upgrade_in_progress") {
			t.Errorf("a minted, unused token already shows a window: %+v", c.ActiveStates)
		}

		opened := upgradeT0.Add(time.Minute)
		present(t, database, "a1", raw, opened)
		c := list(opened.Add(time.Second))
		if got := strings.Join(c.ActiveStates, ","); got != "upgrade_in_progress,agent_out_of_date" {
			t.Errorf("active_states = %s, want upgrade_in_progress,agent_out_of_date", got)
		}
		if c.Status != string(StateUpgradeInProgress) {
			t.Errorf("status = %s, want upgrade_in_progress", c.Status)
		}
		if c.UpgradeWindowUntil == nil || !c.UpgradeWindowUntil.Equal(opened.Add(UpgradeWindow)) {
			t.Errorf("UpgradeWindowUntil = %v, want %v", c.UpgradeWindowUntil, opened.Add(UpgradeWindow))
		}
		if healthStateRank[StateRenewalStalled] >= healthStateRank[StateUpgradeInProgress] ||
			healthStateRank[StateUpgradeInProgress]+1 != healthStateRank[StateAgentOutOfDate] {
			t.Errorf("rank: upgrade_in_progress must sit straight before agent_out_of_date, after renewal_stalled")
		}

		c = list(opened.Add(UpgradeWindow))
		if c.UpgradeWindowUntil != nil || strings.Contains(strings.Join(c.ActiveStates, ","), "upgrade_in_progress") {
			t.Errorf("window still shown at its end: %v", c.ActiveStates)
		}
	})
}
