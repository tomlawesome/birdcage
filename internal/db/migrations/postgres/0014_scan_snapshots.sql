-- 0014_scan_snapshots.sql is issue #108 slice 1's server-side receipt of
-- one Nightjar scan (ADR-0010): who scanned, when, with which engine and
-- database, what it found and which host paths it could not see --
-- never the findings themselves. #109's findings store hangs off this
-- table's id, which is why the primary key is a real auto-generated id
-- rather than anything derived from the scan's own content.
--
-- canary_id is the scanning agent's identity -- the same canaries.id an
-- enrolled honeypot uses (0003_canaries.sql), since a scanner enrols
-- through the same registry with a different agentkind.Kind (#105). No
-- REFERENCES constraint, matching this schema's existing stance on
-- canary_id columns (0003_canaries.sql's heartbeats table, 0006's
-- canary_commands): the row can outlive the agent, and neither engine
-- needs the same mechanism to enforce it.
--
-- taken_at is when the agent started the scan; received_at is when
-- birdcage's own POST /ingest/scans stored it -- the same taken/received
-- split issue #32's alerts already carry (the source is never trusted
-- for the receipt clock; birdcage's own time is). Both are RFC3339Nano
-- text, the layout every timestamp column in this schema uses
-- (internal/store's receivedAtLayout), compared as instants and never as
-- text -- see 0012_approvals.sql's own comment for the trimmed-
-- fractional-second trap that rule exists for.
--
-- engine_name/engine_version identify the scanner (internal/scan.EngineName
-- is "grype", pinned by ADR-0010); db_built_at is the vulnerability
-- database's own build timestamp, the field ADR-0010 decision 8's
-- staleness proof reads. db_built_at is nullable: internal/scan's Result
-- leaves its whole Engine zero-valued on a run that failed before ever
-- loading a database (grype missing, a crash before any document was
-- produced), and there is nothing honest to report there. engine_name
-- and engine_version default to '' rather than NULL for the same case,
-- since this table always writes a row with a value for them, present
-- or not -- mirroring canaries.agent_version's own plain-empty-string
-- convention (migration 0005).
--
-- status is closed in Go (store.ScanStatusOK/ScanStatusFailed), not a
-- SQL CHECK constraint, the same reasoning 0006_canary_commands.sql's
-- kind column and 0013_agent_kinds.sql's kind columns both give: a
-- constraint would have to be written once per engine and would then
-- disagree with the Go set the moment either changed. reason is
-- required exactly when status is "failed", enforced in Go by
-- store.RecordScanSnapshot -- ADR-0010 decision 8's "never an empty
-- finding set presented as clean" starts here: a scan birdcage cannot
-- explain a failure for is not represented at all.
--
-- finding_count is validated and counted from the posted findings, never
-- the findings themselves -- #109 adds the store those hang off this
-- table's id from. It is zero exactly when status is "failed" (the same
-- rule internal/scan.Result.Findings already carries on the agent side).
--
-- masked_paths (design decision on #108, 2026-09-22, on top of the "Scanner
-- agent, slice 1" plan) records the host paths the scanner's read-only
-- root mount covered over with tmpfs/`/dev/null` before this scan ran
-- (/etc/shadow, /etc/ssh, /root, /proc, /run, /home and similar) --
-- commit 4's run command builds that list, this column is where the
-- receipt says so, since a covered path is a path the scan could not
-- see and that blind spot must be on the record rather than implied.
-- Stored as JSON text, matching canary_commands.params' own precedent
-- (0006_canary_commands.sql) for a structured/list-valued column in this
-- schema -- a comma-joined string (canaries.ports' own convention,
-- 0003_canaries.sql) is not used here because a path, unlike a bare port
-- number, is free text that could itself contain a comma. Defaults to
-- '[]', never NULL: every snapshot this table has ever recorded has an
-- opinion about what it could and could not see, including "nothing was
-- masked".
CREATE TABLE IF NOT EXISTS scan_snapshots (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    canary_id      TEXT NOT NULL,
    taken_at       TEXT NOT NULL,
    received_at    TEXT NOT NULL,
    engine_name    TEXT NOT NULL DEFAULT '',
    engine_version TEXT NOT NULL DEFAULT '',
    db_built_at    TEXT,
    status         TEXT NOT NULL,
    reason         TEXT NOT NULL DEFAULT '',
    finding_count  INTEGER NOT NULL,
    masked_paths   TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_scan_snapshots_canary_id ON scan_snapshots(canary_id);
