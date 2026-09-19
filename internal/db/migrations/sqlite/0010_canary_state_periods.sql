-- canary_state_periods is issue #56's record of how long each canary
-- spent in each of issue #45's health states: one row per span a state
-- was continuously active, opened when the state starts and closed when
-- it stops. #45 computes those states fresh on every GET /api/canaries
-- and keeps nothing, so "this canary was throttled for eleven minutes
-- last night" had nowhere to come from. The signals themselves are not
-- re-derived here -- internal/history's recorder reads exactly what
-- ListCanaries already derived (internal/store/health.go) and only
-- writes down when each state started and stopped.
--
-- state is the same closed set #45 ranks (token_conflict, silent,
-- not_delivering, throttled, rotation_stalled), plus "unobserved": the
-- span in which birdcage itself was not running, which is deliberately
-- recorded as its own state rather than left looking healthy. As with
-- 0006_canary_commands.sql's kind and 0007_settings.sql's key, the set
-- is closed in Go (internal/store's HealthState), not by a CHECK
-- constraint that would have to be written once per engine and would
-- then disagree with the Go list the moment either changed.
--
-- ended_at NULL is the whole definition of "this state is active right
-- now", the same shape canary_commands.delivered_at uses for "still
-- owed". end_reason says why a span ended and is NULL exactly while
-- ended_at is: "cleared" (the state simply stopped being active),
-- "quiet_period" (token_conflict, which #45 clears only after a quiet
-- period with no new conflicts rather than by being resolved), or
-- "unobserved" (birdcage was not running, so the span was closed at the
-- last tick it recorded rather than at a time it actually observed).
--
-- flap_count is how many times one span was re-entered inside
-- internal/history's 10-minute collapse window instead of a new row
-- being inserted. That collapse is the table's growth bound: without it
-- an attacker who can pace a signal -- crossing the rate limit every
-- few seconds, say -- would choose how many rows birdcage writes.
--
-- started_at/ended_at are RFC3339Nano text, the layout every timestamp
-- column in this schema uses (internal/store's receivedAtLayout). They
-- are compared as instants, never as text: RFC3339Nano trims trailing
-- zeros from the fractional seconds, so a lexicographic SQL comparison
-- sorts "...:00Z" after "...:00.5Z". Range filters go through
-- internal/store's timeCompare (julianday()/::timestamptz); every
-- ordering and every max is computed in Go on parsed time.Time values,
-- never by SQL ORDER BY or MAX on these columns. See
-- RevokeCanaryTokensSupersededBy's comment in internal/store/token.go
-- for the two rotation tests this trap already cost.
--
-- canary_id carries no declared foreign key, matching canary_tokens in
-- 0004, canary_commands in 0006 and heartbeats in 0003. A declared
-- reference would also behave differently on the two engines -- SQLite
-- does not enforce one unless foreign_keys is pragma-enabled (it is
-- not, see internal/db.Open), Postgres always does -- which is exactly
-- the per-engine divergence issue #7 treats as a defect.
CREATE TABLE IF NOT EXISTS canary_state_periods (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    canary_id  TEXT NOT NULL,
    state      TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at   TEXT,
    flap_count INTEGER NOT NULL DEFAULT 1,
    end_reason TEXT
);

-- The two query shapes that exist: every open span (the recorder's own
-- per-tick reconcile, ended_at IS NULL), and the most recent closed span
-- for one canary and state (the flap-collapse lookup). Both lead on
-- canary_id and state, so one index carrying ended_at serves both.
CREATE INDEX IF NOT EXISTS idx_canary_state_periods_open ON canary_state_periods(canary_id, state, ended_at);
