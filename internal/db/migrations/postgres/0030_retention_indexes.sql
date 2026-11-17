-- 0030_retention_indexes.sql is issue #213's retention (owner question
-- 39): store.PruneByAge removes one agent's fixed findings by last_seen
-- and its scan snapshots by received_at on every scan ingest. These two
-- indexes let both deletes read only the rows they remove, instead of
-- every fixed finding (up to 50,000) or every snapshot the agent has.
--
-- Each replaces an index it extends by one column, so every query the
-- old one served (agent_id, or agent_id and state) is still served.
-- last_seen and received_at are RFC3339Nano UTC text; PruneByAge only
-- ever compares them against a whole-second prefix, which sorts
-- correctly as text (see PruneByAge's comment), so a text index fits.
DROP INDEX IF EXISTS idx_findings_agent_state;
CREATE INDEX IF NOT EXISTS idx_findings_agent_state_last_seen ON findings(agent_id, state, last_seen);

DROP INDEX IF EXISTS idx_scan_snapshots_agent_id;
CREATE INDEX IF NOT EXISTS idx_scan_snapshots_agent_received ON scan_snapshots(agent_id, received_at);
