-- canary_tokens is the bearer credential each canary's agent presents on
-- the ingest submux (issue #32, slice 1): one row per minted token. The
-- raw token value is never stored -- only its SHA-256 (hex-encoded, see
-- internal/store/token.go's HashToken) goes in token_hash, which is what
-- LookupCanaryTokenByHash looks up by; the raw value is returned to the
-- minting caller once and never written down. canary_id carries no
-- declared foreign key, matching heartbeats.canary_id in
-- 0003_canaries.sql -- birdcage's schema doesn't enforce that
-- relationship in SQL, only in the store layer.
CREATE TABLE IF NOT EXISTS canary_tokens (
    id           TEXT PRIMARY KEY,
    canary_id    TEXT NOT NULL,
    token_hash   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at   TEXT
);
-- token_hash is the sole lookup key an incoming request carries (issue
-- #32 slice 2), so it must be unique as well as indexed.
CREATE UNIQUE INDEX IF NOT EXISTS idx_canary_tokens_hash       ON canary_tokens(token_hash);
CREATE INDEX IF NOT EXISTS        idx_canary_tokens_canary_id  ON canary_tokens(canary_id);

-- event_id lets the same OpenCanary event delivered twice -- by both the
-- agent's loopback road and its log-tail road, or after an agent
-- restart replays a batch birdcage never acknowledged -- get stored
-- once: it is the SHA-256 (hex) of the JSON string OpenCanary itself
-- emitted (#48), and internal/store's InsertAlertIfNew is the
-- insert-or-ignore write path built on the unique index below. The
-- index is a plain (not partial/WHERE) unique index deliberately: SQL's
-- own unique-constraint semantics treat every NULL as distinct from
-- every other NULL, so a plain index already allows any number of NULL
-- event_id rows with no WHERE clause needed -- verified for both
-- engines, rather than assumed, by
-- TestEventIDUniqueIndexAllowsMultipleNulls in
-- internal/db/migrate_test.go. Pre-agent syslog-era rows get NULL here
-- and are never backfilled -- they were never deduplicated either.
ALTER TABLE alerts ADD COLUMN event_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_event_id ON alerts(event_id);
