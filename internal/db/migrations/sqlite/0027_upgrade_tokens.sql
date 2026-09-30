-- 0027_upgrade_tokens.sql is issue #54's upgrade token (owner,
-- 2026-09-27; ADR-0012's B4 amendment). Following an agent's upgrade
-- command, the old build and the new one report two agent versions on
-- one certificate within B4's 60-second window, which is exactly what
-- the dual-use check calls credential_conflict. The operator's upgrade
-- command now carries a single-use token, bound to one agent, valid for
-- 15 minutes; the new agent presents it once, beside its own mTLS
-- certificate and bearer token, and birdcage opens a 5-minute window in
-- which that one version change on that one agent is not flagged.
--
-- Only the SHA-256 of the token is stored (store.HashToken), like every
-- other token here. from_version and to_version are the one version
-- pair the window covers: the agent's last-reported build when the token
-- was minted, and birdcage's own build then. Any third version, and
-- every address change, flags as before.
--
-- used_at is set exactly once (UPDATE ... WHERE used_at IS NULL), which
-- is what makes the token single use under concurrent presentation;
-- window_until is used_at plus the window. superseded_at is set on every
-- unused token for the agent when a newer one is minted, so at most one
-- is ever live.
--
-- Timestamps are RFC 3339 text like every other table here; every
-- comparison that matters is made in Go on parsed values.
CREATE TABLE IF NOT EXISTS upgrade_tokens (
    id            TEXT PRIMARY KEY,
    agent_id      TEXT NOT NULL,
    token_hash    TEXT NOT NULL,
    from_version  TEXT NOT NULL,
    to_version    TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    superseded_at TEXT,
    used_at       TEXT,
    window_until  TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_upgrade_tokens_hash     ON upgrade_tokens(token_hash);
CREATE INDEX IF NOT EXISTS        idx_upgrade_tokens_agent_id ON upgrade_tokens(agent_id);
