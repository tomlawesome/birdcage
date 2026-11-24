-- Issue #227: scheduled downtime for a canary. maintenance_until is the end
-- of the canary's maintenance window, an RFC 3339 UTC time, or NULL when it
-- is not in maintenance. While now < maintenance_until the canary's health
-- warnings (silent, self-test failed) are quiet; hits are never affected.
-- It is birdcage-side state, not an agent setting: it is not a
-- canary_settings row and never reaches the settings hash or the agent.
ALTER TABLE agents ADD COLUMN maintenance_until TEXT NULL;
