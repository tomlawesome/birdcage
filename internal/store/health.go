// Issue #45: a canary that cannot report must say so as loudly as one
// that is actively silent. This file turns the signals #32 already
// writes -- rate-limit crossings, the token-conflict check, the agent's
// own heartbeat self-report, and canary_tokens' mint/use timestamps --
// into the ranked, ordered health state ListCanaries attaches to every
// canary. It adds no table: every signal here already exists in the
// schema (audit_log, canary_tokens, canaries.agent_log_read_ok).
//
// Scope note: of the issue's eight states, silent (already built,
// #34/#38), throttled, not-delivering, rotation-stalled, token conflict,
// -- as of #46 -- self-test-failed and -- as of #47 -- pending are
// computed here. Agent-out-of-date (#48) still reads data that doesn't
// exist in this schema yet -- its slot in healthStateRank remains
// reserved, not emitted, so wiring it in later stays an insertion, not a
// renumbering.
package store

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// HealthState is a canary's single worst-ranked, dashboard-facing status.
// It replaces the earlier plain "ok"/"silent" boolean the JSON field
// still carries under the name "status" -- issue #45: "the current
// frontend model ... becomes an ordered enum, not another boolean."
type HealthState string

const (
	// StateTokenConflict is a superseded credential presented while its
	// successor is live: a revoked token (ingest.token_conflict, #45) or,
	// since issue #130, a revoked client certificate
	// (ingest.cert_conflict) -- ADR-0012 B4: "the state widens to mean
	// either".
	StateTokenConflict HealthState = "token_conflict"
	// StateCredentialConflict (issue #130, ADR-0012 B4) is one live
	// certificate used from two source addresses, or by two agent
	// builds, within credentialConflictWindow. Ranked with token
	// conflict, immediately after it. Never revokes anything.
	StateCredentialConflict HealthState = "credential_conflict"
	StateSilent             HealthState = "silent"
	StateNotDelivering      HealthState = "not_delivering"
	// StateTestFailed (issue #46) is a canary whose most recently
	// *completed* scheduled self-test run has passed=false -- see
	// applySelfTestState in selftest.go. Ranked between not-delivering
	// and throttled, per the slot this file's own package doc comment
	// already reserved for it.
	StateTestFailed      HealthState = "self_test_failed"
	StateThrottled       HealthState = "throttled"
	StateRotationStalled HealthState = "rotation_stalled"
	// StateRenewalStalled (issue #130, ADR-0012 B2; answers #72) is
	// rotation-stalled's certificate twin: the certificate the agent is
	// using is past half-life plus renewalStalledMargin with no renewal
	// completed. Ranked immediately after rotation-stalled. At the
	// certificate's expiry it gives way to not-delivering.
	StateRenewalStalled HealthState = "renewal_stalled"
	// StatePending (issue #47 steps 7-9) is a canary provisioned through
	// POST /enrol/provision whose first self-test round trip has not yet
	// passed -- store.Canary.RegisteredAt nil. Ranked last of the fault
	// states, after rotation-stalled and before ok, exactly the slot the
	// issue's own precedence list gives it ("... rotation stalled, agent
	// out of date, pending") once agent-out-of-date (still unbuilt, #48)
	// is removed -- the same "relative order preserved, gap not filled"
	// reasoning healthStateRank's own doc comment already gives for
	// self-test-failed's slot.
	StatePending HealthState = "pending"
	StateOK      HealthState = "ok"
)

// healthStateRank orders HealthState worst-first: issue #45's own
// proposed precedence ("token conflict, silent, not delivering, self-test
// failed, throttled, rotation stalled, agent out of date, pending") with
// the one state this slice still doesn't build (agent-out-of-date, #48)
// removed. Removing it doesn't change the relative order of what's left
// -- agent-out-of-date sat between rotation-stalled and pending, and that
// gap isn't filled by anything built here. The issue itself calls this
// order "proposed, not yet ratified"; it is implemented as specified and
// flagged as contested, not silently finalized.
//
// Issue #130 adds two states, each beside its twin: credential-conflict
// straight after token-conflict (both are "two holders of one
// credential"), renewal-stalled straight after rotation-stalled (the
// same failure for the certificate instead of the token).
var healthStateRank = map[HealthState]int{
	StateTokenConflict:      0,
	StateCredentialConflict: 1,
	StateSilent:             2,
	StateNotDelivering:      3,
	StateTestFailed:         4,
	StateThrottled:          5,
	StateRotationStalled:    6,
	StateRenewalStalled:     7,
	StatePending:            8,
	StateOK:                 9,
}

// Recency windows and thresholds this slice introduces. None of these
// numbers is in the ratified issue text; each is a documented, tunable
// implementation choice -- written down as contested per
// docs/security-by-design.md rather than presented as settled.
const (
	// throttledWindow is how long a rate-limit crossing keeps a canary's
	// tile reading "throttled" after the most recent one. The limiter
	// itself is a per-minute token bucket (internal/ingest/ratelimit.go),
	// so a crossing more than a few minutes old says nothing about
	// whether the canary is throttled right now; 5 minutes gives an
	// operator time to notice a short burst without the tile going stale
	// mid-incident.
	throttledWindow = 5 * time.Minute

	// tokenConflictQuietPeriod is not an expiry: latestAuditSince takes
	// the most recent ingest.token_conflict entry, so the clock restarts
	// on every new conflict and this is how long a canary's tile keeps
	// reading "token conflict" after the last one. Resolution, per the
	// owner (2026-09-17), is the token no longer conflicting -- either
	// the admin fixed the cause or rotation started working, and both
	// look identical from birdcage, as the conflicts simply stopping.
	// There is deliberately no acknowledge action: a click would only
	// record that somebody looked, not that the problem ended. So the
	// state holds for as long as conflicts keep arriving and clears only
	// after a quiet period with none. 24h is a conservative margin over
	// the ~60s poll interval of a cloned box that is still live, chosen
	// to favor not missing an overnight event over aging out quickly.
	tokenConflictQuietPeriod = 24 * time.Hour

	// rotationStalledThreshold is issue #45's own number: a newly issued
	// token unused for 15 minutes.
	rotationStalledThreshold = 15 * time.Minute

	// rotationStalledEscalateThreshold is issue #45's own number: the
	// issued-but-unused signal's wording escalates after 24 hours.
	rotationStalledEscalateThreshold = 24 * time.Hour

	// rotationStaleThreshold is issue #45's own number ("no completed
	// rotation for over about 25 h") -- the second, independent trigger
	// that catches an agent that never asks to rotate at all, distinct
	// from an issued-but-unused token.
	rotationStaleThreshold = 25 * time.Hour
)

// notDelivering reports whether c's own agent self-report says its log
// read is failing. AgentLogReadOK is nil until the agent's first
// heartbeat over the ingest token (#32 slice 5a) -- nil must never read
// as failing, only an explicit false does; a canary that has simply
// never sent a self-report yet is not "not delivering", it has nothing
// to say yet.
//
// The issue's other half of this state -- "the agent's queue is backing
// up" -- is deliberately not implemented: birdcage stores only the
// latest queue_depth snapshot, not a series, so "backing up" (a trend)
// can't be derived from it without inventing an unratified threshold,
// and the number that would give a raw depth meaning (the agent's queue
// cap) is #48's to define and isn't in this schema yet. Revisit once #48
// lands.
func notDelivering(c Canary) bool {
	return c.AgentLogReadOK != nil && !*c.AgentLogReadOK
}

// latestAuditSince returns the most recent created_at among audit_log
// rows matching action and target with created_at >= cutoff, or nil if
// none. The cutoff filter runs in SQL using timeCompare (the existing,
// engine-portable mechanism every other range filter in this package
// uses -- see receivedAtCompare's doc comment), which parses the stored
// text into a real timestamp before comparing rather than comparing the
// TEXT column lexicographically, so it does not reintroduce the
// trimmed-fractional-second bug. The final max, and every boundary
// decision built on it, is computed in Go: with a handful of matching
// rows expected inside a several-minute-to-a-day window, an ORDER BY on
// the same TEXT column would only reintroduce the bug the filter just
// avoided.
func latestAuditSince(ctx context.Context, database *db.DB, action, target string, cutoff time.Time) (*time.Time, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT created_at FROM audit_log
		WHERE action = ? AND target = ? AND `+timeCompare(database.Engine, "created_at", ">=")+`
		`, action, target, cutoff.UTC().Format(receivedAtLayout))
	if err != nil {
		return nil, fmt.Errorf("query audit log for %s/%s: %w", action, target, err)
	}
	defer func() { _ = rows.Close() }()

	var latest *time.Time
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan audit log created_at: %w", err)
		}
		t, err := time.Parse(receivedAtLayout, raw)
		if err != nil {
			return nil, fmt.Errorf("parse audit log created_at %q: %w", raw, err)
		}
		if latest == nil || t.After(*latest) {
			latest = &t
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit log for %s/%s: %w", action, target, err)
	}
	return latest, nil
}

// rotationSignal reports whether canaryID's rotation looks stalled as of
// now, and how long, from the two independent triggers issue #45
// defines. escalated means the wording should say so more urgently (the
// issued-but-unused signal past 24h, or the no-completed-rotation signal,
// which is inherently already past its own 25h bar).
func rotationSignal(ctx context.Context, database *db.DB, canaryID string, now time.Time) (stalled, escalated bool, sinceS int64, err error) {
	tokens, err := ListCanaryTokensForCanary(ctx, database, canaryID)
	if err != nil {
		return false, false, 0, fmt.Errorf("list canary tokens for %s: %w", canaryID, err)
	}
	if len(tokens) == 0 {
		return false, false, 0, nil
	}
	sort.Slice(tokens, func(i, j int) bool { return tokens[i].CreatedAt.Before(tokens[j].CreatedAt) })

	// Signal A: the latest-issued token is unused, and this canary has
	// rotated before (len(tokens) > 1) -- a first-ever, still-unused
	// token is enrollment/pending territory (#47), not a stalled
	// rotation. "Latest issuance" (not "any unused token") so a
	// superseded, orphaned issue-but-never-used token from an earlier
	// rotation attempt doesn't fire this forever once a later rotation
	// has completed.
	latest := tokens[len(tokens)-1]
	if len(tokens) > 1 && latest.LastUsedAt == nil {
		elapsed := now.Sub(latest.CreatedAt)
		if elapsed >= rotationStalledThreshold {
			return true, elapsed >= rotationStalledEscalateThreshold, int64(elapsed.Seconds()), nil
		}
	}

	// Signal B: no completed rotation in ~25h -- the agent that never
	// asks at all. "Completed" = the most recently minted token that has
	// actually been used, i.e. the credential the agent is (or was)
	// actively presenting.
	var activated *CanaryToken
	for i := len(tokens) - 1; i >= 0; i-- {
		if tokens[i].LastUsedAt != nil {
			t := tokens[i]
			activated = &t
			break
		}
	}
	if activated != nil {
		elapsed := now.Sub(activated.CreatedAt)
		if elapsed >= rotationStaleThreshold {
			return true, true, int64(elapsed.Seconds()), nil
		}
	}

	return false, false, 0, nil
}

// applyHealthState computes c's ordered HealthState (issue #45) from the
// silent/ok status applyStatus already derived, plus the throttled,
// not-delivering, rotation-stalled, token-conflict, (#46) self-test-
// failed and (#47) pending signals passed in.
// c.ActiveStates is filled with every active state, worst first, and
// c.Status with the head of that list ("one state on the tile, the
// worst; the rest in its detail" -- issue #45); every other active
// signal's own detail fields are still populated, so a caller that
// wants to show more than the headline state can.
//
// pending never overrides a genuinely worse state (silent, throttled,
// self-test-failed and the rest all rank above it), so a pending canary
// that is also, say, self-test-failed (a run that expired unmatched --
// #47 step 3's own "leaves the canary pending, and self_test_failed")
// shows the worse headline with pending still present in ActiveStates.
// What pending guarantees on its own is issue #47's "never a healthy
// canary on the dashboard": with nothing worse active, Status still
// reads "pending", never "ok".
func applyHealthState(c *Canary, notDeliveringNow bool, throttledSince *time.Time, rotationStalled, rotationEscalated bool, rotationSinceS int64, tokenConflictSince *time.Time, testFailed, pending bool, now time.Time) {
	if notDeliveringNow {
		c.NotDelivering = true
	}
	if throttledSince != nil {
		s := int64(now.Sub(*throttledSince).Seconds())
		c.ThrottledForS = &s
	}
	if rotationStalled {
		c.RotationStalled = true
		c.RotationStalledForS = &rotationSinceS
		c.RotationStalledEscalated = rotationEscalated
	}
	if tokenConflictSince != nil {
		s := int64(now.Sub(*tokenConflictSince).Seconds())
		c.TokenConflictForS = &s
	}

	// The full set first, then Status as its head. Issue #45 asked only
	// for the worst state; #56's history needs every active one, and
	// deriving the set once here is what stops the recorder growing a
	// second copy of this precedence to disagree with.
	active := []HealthState{}
	add := func(state HealthState, on bool) {
		if on {
			active = append(active, state)
		}
	}
	// applyStatus has already run, so c.Status carries "silent" or "ok"
	// at this point -- silent is one of the states, not a separate axis.
	add(StateSilent, c.Status == string(StateSilent))
	add(StateTokenConflict, tokenConflictSince != nil)
	add(StateNotDelivering, notDeliveringNow)
	add(StateTestFailed, testFailed)
	add(StateThrottled, throttledSince != nil)
	add(StateRotationStalled, rotationStalled)
	add(StatePending, pending)
	sort.SliceStable(active, func(i, j int) bool {
		return healthStateRank[active[i]] < healthStateRank[active[j]]
	})

	c.ActiveStates = nil
	c.Status = string(StateOK)
	if len(active) > 0 {
		c.ActiveStates = make([]string, len(active))
		for i, state := range active {
			c.ActiveStates[i] = string(state)
		}
		c.Status = c.ActiveStates[0]
	}
}
