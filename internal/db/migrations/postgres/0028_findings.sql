-- 0028_findings.sql is issue #109's findings store (ADR-0010 decisions 4
-- and 5): a vulnerability is a standing condition, not a moment, so it
-- gets its own table with a first seen, a last seen, a state and an
-- operator decision -- never the alerts table, which is rightly
-- append-only for things that happened at a time.
--
-- Precedent and departure from it: 0010_canary_state_periods.sql is the
-- nearest existing span-with-closed-state-set table, and this follows
-- its conventions (closed state set in Go, not a CHECK constraint;
-- timestamps are RFC3339Nano text, compared as instants in Go, never in
-- SQL -- see that migration's own comment for the trimmed-fractional-
-- second trap this avoids by construction). It departs on shape:
-- canary_state_periods is one row per *span* a state held, reopened
-- freely; findings is one row per *identity* (agent, target,
-- vulnerability), updated in place, because ADR-0010 decision 5's
-- snapshot diff needs to ask "have I seen this exact finding before" in
-- one lookup, not scan a span history.
--
-- agent_id carries no declared foreign key, matching every other
-- agent_id column in this schema (scan_snapshots, heartbeats,
-- agent_commands, ...) -- issue #7's stance that the two engines must
-- not diverge on enforcement, and 0010's own comment for the fuller
-- reasoning.
--
-- target is the vulnerable thing within one scan -- "the container
-- image or the host package" per the issue -- encoded as
-- "<artifact type>:<package name>" (internal/scan.Finding's own Type
-- and Package fields, e.g. "apk:openssl"). The type prefix is there
-- because this slice only ever populates it from one ecosystem (host
-- OS packages, #108), but #113's container-image scanning will add
-- others (npm, python, ...) sharing this same table, and a bare package
-- name is not guaranteed unique across ecosystems. installed_version
-- and severity are the posted finding's own metadata, refreshed on
-- every scan that still reports the finding -- kept here (beyond the
-- issue's explicit first_seen/last_seen/state/fixing_version list)
-- because discarding them would mean the one table recording a
-- vulnerability's existence cannot say what version is running or how
-- bad it is, which is the whole reason #108's ingest handler validates
-- them in the first place. They are not part of the identity key: a
-- package upgrading from one vulnerable version to another still
-- vulnerable to the *same* CVE is the same finding continuing, not a
-- new one.
--
-- state is open, accepted (an operator decision, surviving rescans) or
-- fixed (absent from the most recent complete snapshot) -- the closed
-- set store.FindingState holds in Go, same reasoning as every other
-- closed-set column in this schema (0006's kind, 0013's agent kind,
-- 0010's own state column above). accepted_by/accepted_at are set
-- together, by the store's acceptance method (operator CLI only --
-- the dashboard API stays read-only until login exists, #134), and
-- cleared if a fixed-then-reappeared finding is reopened: an operator
-- who accepted a vulnerability that then went away and came back is
-- asked again, not silently re-covered by a decision made about a
-- package version that may no longer be the one running.
--
-- first_seen/last_seen are birdcage's own received-at clock (the scan
-- snapshot's ReceivedAt, never the agent's own TakenAt) -- the same
-- "never trust the source for the receipt clock" rule scan_snapshots'
-- own migration states for its taken_at/received_at split.
CREATE TABLE IF NOT EXISTS findings (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    agent_id          TEXT NOT NULL,
    target            TEXT NOT NULL,
    vulnerability_id  TEXT NOT NULL,
    severity          TEXT NOT NULL DEFAULT '',
    installed_version TEXT NOT NULL DEFAULT '',
    fixing_version    TEXT NOT NULL DEFAULT '',
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL,
    state             TEXT NOT NULL,
    accepted_by       TEXT,
    accepted_at       TEXT
);

-- The identity key the issue names (agent, target, vulnerability id):
-- one row per finding, upserted by store.ApplyFindingSnapshot rather
-- than ever inserted twice for the same triple.
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_identity ON findings(agent_id, target, vulnerability_id);

-- The diff's own read shape: every currently-live (open or accepted)
-- finding for one agent, to compare against a freshly posted snapshot.
CREATE INDEX IF NOT EXISTS idx_findings_agent_state ON findings(agent_id, state);
