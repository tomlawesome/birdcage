-- canaries gains the ingest-token-authenticated heartbeat's self-report
-- fields (issue #32 slice 5a): the agent's own view of its health --
-- queue depth, whether its OpenCanary log read is healthy, the last
-- event id it has seen, and its own version -- since birdcage never
-- connects to the agent to check on it directly. This is what #45's
-- "not delivering" state and a stale-agent-version signal stand on;
-- reading and surfacing them is #45's job, this migration only makes
-- room to store them.
--
-- All four are nullable: every canary enrolled before #48's agent
-- exists (and any that never rotates onto the new heartbeat route) has
-- never sent a self-report at all, which must stay distinct from a
-- report that legitimately carries a zero queue depth or an empty
-- last-seen event id. agent_log_read_ok is stored as INTEGER (0/1)
-- rather than a native boolean type, matching this schema's existing
-- convention of using engine-portable INTEGER for both (see
-- 0003_canaries.sql's heartbeat_interval_s) rather than branching DDL
-- per engine.
ALTER TABLE canaries ADD COLUMN agent_version TEXT;
ALTER TABLE canaries ADD COLUMN agent_queue_depth INTEGER;
ALTER TABLE canaries ADD COLUMN agent_log_read_ok INTEGER;
ALTER TABLE canaries ADD COLUMN agent_last_event_id TEXT;
