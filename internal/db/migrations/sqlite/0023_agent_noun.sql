-- 0023_agent_noun.sql is issue #107's schema half of the fleet-noun
-- rename: ADR-0009 ("an agent has a kind") gave nodes a kind --
-- honeypot, scanner -- so "canary" is one kind of agent, not the
-- category every enrolled node belongs to. This migration renames the
-- tables and columns that named the node after its original, honeypot-
-- only kind, to the general noun the schema should have used once a
-- scanner could enrol too.
--
-- Renamed, table for table: canaries -> agents (the fleet registry),
-- canary_tokens -> agent_tokens (the ingest bearer credential),
-- canary_commands -> agent_commands (the command queue), and
-- canary_state_periods -> agent_state_periods (issue #56's health-state
-- history). Every canary_id column elsewhere -- heartbeats,
-- agent_tokens, agent_commands, agent_state_periods, client_certs,
-- mail_outbox, self_test_runs, scan_snapshots and enrolment_sessions --
-- becomes agent_id, and enrolment_sessions.canary_name (the operator's
-- `birdcage agent enrol --name`, captured before the node exists)
-- becomes agent_name for the same reason.
--
-- Left alone on purpose: OpenCanary itself, the mockingbird image, lure
-- and trace wording, and every JSON field/HTTP route (/api/canaries,
-- canary_id) -- those are the honeypot product and the API contract,
-- not this schema's internal naming, and out of scope for #107.
--
-- Plain ALTER TABLE ... RENAME TO / RENAME COLUMN, supported by both
-- engines (SQLite since 3.25.0; modernc.org/sqlite's embedded version is
-- well past that) and forward-only like every other migration here: no
-- down file, nothing destroyed, only renamed. SQLite's RENAME COLUMN
-- also rewrites the body of any index that referenced the old column
-- name, but not the index's own name, so the indexes below are dropped
-- and recreated under names that match the new nouns rather than left
-- with a stale "canary" name pointing at an "agent" column.
ALTER TABLE canaries             RENAME TO agents;
ALTER TABLE canary_tokens        RENAME TO agent_tokens;
ALTER TABLE canary_commands      RENAME TO agent_commands;
ALTER TABLE canary_state_periods RENAME TO agent_state_periods;

ALTER TABLE heartbeats           RENAME COLUMN canary_id TO agent_id;
ALTER TABLE agent_tokens         RENAME COLUMN canary_id TO agent_id;
ALTER TABLE agent_commands       RENAME COLUMN canary_id TO agent_id;
ALTER TABLE agent_state_periods  RENAME COLUMN canary_id TO agent_id;
ALTER TABLE client_certs         RENAME COLUMN canary_id TO agent_id;
ALTER TABLE mail_outbox          RENAME COLUMN canary_id TO agent_id;
ALTER TABLE self_test_runs       RENAME COLUMN canary_id TO agent_id;
ALTER TABLE scan_snapshots       RENAME COLUMN canary_id TO agent_id;
ALTER TABLE enrolment_sessions   RENAME COLUMN canary_id TO agent_id;
ALTER TABLE enrolment_sessions   RENAME COLUMN canary_name TO agent_name;

DROP INDEX IF EXISTS idx_heartbeats_canary_id;
CREATE INDEX IF NOT EXISTS idx_heartbeats_agent_id ON heartbeats(agent_id);

DROP INDEX IF EXISTS idx_canary_tokens_hash;
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_tokens_hash ON agent_tokens(token_hash);

DROP INDEX IF EXISTS idx_canary_tokens_canary_id;
CREATE INDEX IF NOT EXISTS idx_agent_tokens_agent_id ON agent_tokens(agent_id);

DROP INDEX IF EXISTS idx_canary_commands_pending;
CREATE INDEX IF NOT EXISTS idx_agent_commands_pending ON agent_commands(agent_id, delivered_at);

DROP INDEX IF EXISTS idx_canary_state_periods_open;
CREATE INDEX IF NOT EXISTS idx_agent_state_periods_open ON agent_state_periods(agent_id, state, ended_at);

DROP INDEX IF EXISTS idx_mail_outbox_kind;
CREATE INDEX IF NOT EXISTS idx_mail_outbox_kind ON mail_outbox(kind, agent_id, created_at);

DROP INDEX IF EXISTS idx_self_test_runs_canary_id;
CREATE INDEX IF NOT EXISTS idx_self_test_runs_agent_id ON self_test_runs(agent_id);

DROP INDEX IF EXISTS idx_self_test_runs_one_open_scan;
CREATE UNIQUE INDEX IF NOT EXISTS idx_self_test_runs_one_open_scan
    ON self_test_runs(agent_id) WHERE completed_at IS NULL AND stage IS NOT NULL;

DROP INDEX IF EXISTS idx_scan_snapshots_canary_id;
CREATE INDEX IF NOT EXISTS idx_scan_snapshots_agent_id ON scan_snapshots(agent_id);

DROP INDEX IF EXISTS idx_client_certs_canary_id;
CREATE INDEX IF NOT EXISTS idx_client_certs_agent_id ON client_certs(agent_id);
