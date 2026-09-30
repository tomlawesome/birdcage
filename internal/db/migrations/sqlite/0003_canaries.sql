-- canaries is the registry of enrolled OpenCanary instances (issue #34):
-- id is the same instance_id alerts.instance_id carries, so a canary's
-- alert history is found by joining on it directly -- no separate foreign
-- key column needed. ports is a comma-separated list of raw port numbers
-- (e.g. "22,80,445"); internal/store maps each to a well-known service
-- name for display, since birdcage has no visibility into the OpenCanary
-- instance's own config (see internal/store/canary.go).
CREATE TABLE IF NOT EXISTS canaries (
    id                   TEXT PRIMARY KEY,
    name                 TEXT NOT NULL,
    lane                 TEXT NOT NULL,
    ports                TEXT NOT NULL DEFAULT '',
    heartbeat_interval_s INTEGER NOT NULL DEFAULT 60,
    enrolled_at          TEXT NOT NULL,
    last_heartbeat_at    TEXT
);

-- heartbeats is pruned to the last 24h on every insert (internal/store's
-- RecordHeartbeat) -- the band only ever draws individual beats in the
-- stretched last quarter hour, so nothing older is ever read.
CREATE TABLE IF NOT EXISTS heartbeats (
    canary_id TEXT NOT NULL,
    at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_heartbeats_canary_id ON heartbeats(canary_id);
CREATE INDEX IF NOT EXISTS idx_heartbeats_at         ON heartbeats(at);
