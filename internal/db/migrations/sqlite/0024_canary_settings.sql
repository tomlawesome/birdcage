-- canary_settings is issue #124's per-canary settings table: the
-- mechanism that lets an operator change a running agent's behaviour
-- (segment profile, bait names, pace floor/ceiling, working hours --
-- issue #86's own settings, the first user of this) from the canary
-- page, with no container restart, in place of the environment
-- variables that were previously the only way (cmd/mockingbird/
-- poisoner.go's own comment: "birdcage has no channel that pushes a
-- setting to an agent at all today").
--
-- One row per (agent_id, key), the same "closed key set validated in Go,
-- not a SQL CHECK constraint" shape 0007_settings.sql's own comment
-- explains for the fleet-wide settings table -- internal/store/
-- canary_settings.go's canarySettingDefs is the closed list, and
-- ListCanarySettings/SetCanarySettings are the only door into this
-- table. version increments on every write to that key (starting at 1),
-- carried for the same audit-trail reason canary_commands and settings
-- carry updated_at, and because the issue's own decided shape names it
-- explicitly ("key/value with a version").
--
-- No declared foreign key on agent_id, matching this schema's existing
-- stance (0014_scan_snapshots.sql's own comment): canary_tokens,
-- canary_commands and mail_outbox all carry an agent_id with no FK
-- either.
--
-- How this reaches a running agent: the agent sends the sha256 hex of
-- its own currently-effective settings on every heartbeat
-- (internal/ingest/heartbeat.go's settings_hash); birdcage compares that
-- against the hash of this table's current rows for that canary
-- (internal/store's SettingsHash) and, when they differ, answers with
-- the full row set as a `settings` object beside `ok`. The agent applies
-- what it validates and reports its new effective hash on its next
-- heartbeat. agents.settings_hash/settings_hash_at (below) is what
-- birdcage last received, so "has the agent confirmed this value" is a
-- read-time comparison against this table's current hash, not a second
-- write path to keep in sync.
CREATE TABLE IF NOT EXISTS canary_settings (
    agent_id   TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    version    INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (agent_id, key)
);

CREATE INDEX IF NOT EXISTS idx_canary_settings_agent_id ON canary_settings(agent_id);

-- agents gains settings_hash/settings_hash_at: the sha256 hex an agent's
-- heartbeat most recently reported, and when. NULL for every agent until
-- its first heartbeat under this change -- including one that predates
-- it entirely, which reports no hash at all (issue #124's "an old agent
-- that sends no hash must keep working"): its facts column simply shows
-- no settings rows, the same "a fact birdcage does not know is left out"
-- rule the rest of the facts column already follows.
ALTER TABLE agents ADD COLUMN settings_hash TEXT;
ALTER TABLE agents ADD COLUMN settings_hash_at TEXT;

-- enrolment_sessions gains bait_names/segment_profile: `birdcage agent
-- enrol --bait-names/--segment-profile`'s own values (cmd/birdcage/
-- canary.go), carried on the session the same way agent_name and lane
-- already are, until store.Provision reads them to seed this canary's
-- first canary_settings rows -- "enrolment writes the first values from
-- its flags", so the flags become the settings table's defaults rather
-- than the only way to set them. NULL/empty means the operator passed
-- neither flag, in which case Provision seeds nothing and the agent
-- keeps reading its environment variables, exactly as before this
-- issue.
ALTER TABLE enrolment_sessions ADD COLUMN bait_names TEXT;
ALTER TABLE enrolment_sessions ADD COLUMN segment_profile TEXT;
