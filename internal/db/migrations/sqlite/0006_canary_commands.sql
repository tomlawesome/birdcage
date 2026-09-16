-- canary_commands is the one direction birdcage can ask a canary to do
-- something (issue #32 slice 5b). It is a queue the agent (#48) drains by
-- polling the ingest submux on its own token; birdcage never connects to a
-- canary, so nothing here is pushed. SaltStack CVE-2020-11651 is the
-- record of what the other shape costs: an unauthenticated bypass on a
-- master's management channel, exploited in the wild.
--
-- kind is the only thing a command carries besides its parameters, and the
-- set of kinds is deliberately closed in Go (store.CommandKind), not here:
-- a CHECK constraint would have to be written twice, once per engine, and
-- would then disagree with the Go allow-list the moment one side changed.
-- M1 mints exactly one kind, "selftest" (#46). "upgrade" is named in #32
-- and is deliberately NOT mintable yet: until an admin's authority to
-- order one can be established (owner, 2026-09-16) there must be no way to
-- order an unattended upgrade at all.
--
-- delivered_at is set before the command is written to the wire, never
-- after (#32: "a crash between the two loses the command rather than
-- doubling it. A lost command is a retry; a doubled one is two self-test
-- sweeps or two upgrades"). A NULL delivered_at is therefore the whole
-- definition of "still owed to a canary".
--
-- expires_at is stored, not derived, so a command's lifetime is a fact
-- about that command rather than a constant the code could change
-- underneath already-queued rows. It is compared in Go, never in SQL:
-- these are RFC3339Nano strings, whose trailing zeros are trimmed, so
-- lexicographic SQL comparison puts "…:00Z" after "…:00.5Z". The same
-- trap cost two rotation tests in 0004's lifetime -- see
-- RevokeCanaryTokensSupersededBy's comment in internal/store/token.go.
--
-- canary_id carries no declared foreign key, matching canary_tokens in
-- 0004 and heartbeats in 0003.
CREATE TABLE IF NOT EXISTS canary_commands (
    id           TEXT PRIMARY KEY,
    canary_id    TEXT NOT NULL,
    kind         TEXT NOT NULL,
    params       TEXT,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    delivered_at TEXT
);

-- The only query shape the poll uses: everything still owed to one
-- canary. Undelivered rows are the small minority once a fleet is
-- running, so the index leads on canary_id and carries delivered_at.
CREATE INDEX IF NOT EXISTS idx_canary_commands_pending ON canary_commands(canary_id, delivered_at);
