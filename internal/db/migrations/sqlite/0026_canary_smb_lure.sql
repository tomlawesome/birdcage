-- 0026_canary_smb_lure.sql is issue #54's own addition: the SMB lure's
-- enrolment-time identity -- on/off, workgroup, share names
-- (cmd/birdcage/canary_lure.go's --lure/--smb-workgroup/--smb-shares
-- flags) -- carried past enrolment for the first time. Until now these
-- three values only decided what `birdcage agent enrol` printed
-- (canary_lure.go's own package comment: "Nothing here is sent to the
-- server or stored"); building a canary's upgrade command (the copy-
-- paste command that pulls current images and recreates its containers,
-- #54) needs to know, later, whether that canary ever got a lure at
-- all.
--
-- Carried the same way bait_names/segment_profile already are
-- (0024_canary_settings.sql): enrolment_sessions gains the raw flag
-- values until store.Provision copies them onto the new agents row,
-- where they live for the life of the canary.
--
-- Deliberately not canary_settings (0024): that table is the closed set
-- of values birdcage pushes to a *running agent* over heartbeat, hashed
-- and confirmed back (SettingsHash) -- the SMB lure is a sibling
-- container with no heartbeat and nothing ever pushed to it. This is a
-- plain enrolment-time fact about the canary, the same kind kind/ports/
-- lane already are, so it lives beside them on agents, not in that
-- table.
--
-- smb_lure is nullable, stored 0/1, the same tri-state convention
-- agent_opencanary_up (0025) already uses: NULL means unknown, not off
-- -- every agents row that predates this migration reads back NULL, and
-- nothing here backfills a guess for it (owner, 2026-09-27: "treat lure
-- as unknown ... never guess silently"). smb_workgroup and smb_shares
-- are NULL whenever smb_lure is NULL or 0; smb_shares holds the three
-- names comma-joined, the same form canary_settings' bait_names already
-- uses for a short fixed list.
ALTER TABLE enrolment_sessions ADD COLUMN smb_lure INTEGER;
ALTER TABLE enrolment_sessions ADD COLUMN smb_workgroup TEXT;
ALTER TABLE enrolment_sessions ADD COLUMN smb_shares TEXT;

ALTER TABLE agents ADD COLUMN smb_lure INTEGER;
ALTER TABLE agents ADD COLUMN smb_workgroup TEXT;
ALTER TABLE agents ADD COLUMN smb_shares TEXT;
