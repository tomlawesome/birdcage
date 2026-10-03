-- settings stores the operator-facing configuration issue #46 calls data,
-- not configuration (note 17934, 2026-09-13): the self-test on/off switch,
-- its schedule, the "same schedule as key rotation" toggle, and the
-- rotation schedule itself. Unlike ports, database URLs and addresses --
-- which stay in environment variables because they only change with a
-- redeploy -- these are the kind of thing an operator changes on a Tuesday
-- afternoon, so they live in a row a CLI command can write today and the
-- dashboard (#8) can write later, both through the same store functions
-- rather than a second copy that can disagree.
--
-- One row per setting, keyed by name, rather than one column per setting:
-- adding a setting later is a new row, not a migration. This is NOT a
-- free-form key/value store, though -- the set of valid keys, and what
-- counts as a valid value for each, is a closed list in Go
-- (internal/store/settings.go's settingDefs), the same shape
-- 0006_canary_commands.sql's kind column uses for CommandKind: a SQL CHECK
-- constraint would have to be written once per engine and would then
-- disagree with the Go list the moment either changed. store.GetSetting and
-- store.SetSetting are the only door into this table, and both reject
-- anything outside that list before it reaches SQL -- a typo'd key or a
-- malformed value fails loudly rather than silently storing something
-- nothing ever reads.
--
-- value is TEXT for every setting in this slice (a bool as "true"/"false",
-- a schedule as a 24-hour "HH:MM" UTC time) rather than a typed column per
-- kind, since one engine-portable TEXT column is enough when the
-- type-per-key checking happens in Go regardless.
--
-- updated_at is an RFC3339Nano string, like every other timestamp column in
-- this schema, and -- per this package's standing rule -- is compared in
-- Go, never in SQL (see RevokeCanaryTokensSupersededBy's comment in
-- internal/store/token.go for why: the two engines round trailing
-- fractional-second zeros differently, so a raw SQL >=/<= comparison can
-- disagree between them on values that differ only in how they trimmed).
-- Nothing in this slice compares updated_at yet; it is carried for the same
-- reason created_at is on every other table -- a record of when a value
-- last changed -- and stored the same way so a later comparison doesn't
-- have to learn a new rule.
--
-- A setting that has never been written has no row at all: store.GetSetting
-- returns its documented Go default rather than treating a missing row as
-- an error or an empty value, so this table only ever holds the settings an
-- operator actually touched.
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
