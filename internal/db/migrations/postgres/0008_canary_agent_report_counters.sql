-- canaries gains the four heartbeat fields #32/#48's process-composition
-- design (issue #48, note "cmd/birdcage-agent: process composition", gap
-- 3) adds on top of 0005_canary_agent_report.sql's original four: the
-- agent's cumulative dropped-for-capacity count (queue.MemQueue.Dropped()),
-- its cumulative permanently-rejected count (MemQueue.RejectedCount()),
-- its cumulative event-id-collision count (the same id at two distinct log
-- positions -- issue #48's "The event id" section, expected zero forever),
-- and whether its last log-tailer resume found the acknowledged position
-- or had to fall back (tailer.ResumeResult.PositionFound).
--
-- All four are nullable, for exactly 0005's reason: an agent built before
-- this change (or mid-rollout) sends the original four fields only, and
-- "never reported this field" must stay distinct from "reported zero" --
-- zero dropped is good news, absent is no news. agent_position_found is
-- stored as INTEGER (0/1) rather than a native boolean type, matching
-- 0005's own treatment of agent_log_read_ok and this schema's existing
-- convention (0003_canaries.sql's heartbeat_interval_s) of engine-portable
-- INTEGER over per-engine boolean DDL.
ALTER TABLE canaries ADD COLUMN agent_dropped INTEGER;
ALTER TABLE canaries ADD COLUMN agent_rejected INTEGER;
ALTER TABLE canaries ADD COLUMN agent_event_id_collisions INTEGER;
ALTER TABLE canaries ADD COLUMN agent_position_found INTEGER;
