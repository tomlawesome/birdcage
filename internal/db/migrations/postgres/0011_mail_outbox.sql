-- mail_outbox is issue #55's queue of alerts birdcage owes an
-- administrator. It exists because sending is the one thing here that
-- depends on a machine birdcage does not control: an SMTP server that is
-- down, slow, or refusing authentication must never be able to roll back
-- birdcage's own record of what happened, and an alert that could not be
-- delivered must still be owed rather than lost.
--
-- So the row is written in the same transaction as the state period that
-- caused it (internal/history's recorder calls a hook; internal/mail
-- writes the row), and a separate tick on the same 30-second loop drains
-- the table. A row with sent_at NULL is still owed; a row with sent_at
-- set is a record of something that went out.
--
-- kind is the closed set internal/store's MailKind holds -- today only
-- "token_conflict". Closed in Go rather than by a CHECK constraint, the
-- same reasoning 0006_canary_commands.sql's kind, 0007_settings.sql's
-- key and 0010_canary_state_periods.sql's state all give: a constraint
-- would have to be written once per engine and would then disagree with
-- the Go list the moment either changed.
--
-- canary_id is nullable because not every kind of mail is about a
-- canary. It carries no declared foreign key, matching canary_tokens in
-- 0004, canary_commands in 0006, heartbeats in 0003 and
-- canary_state_periods in 0010 -- and for the extra reason that this
-- table is evidence: a mail birdcage sent about a canary that has since
-- been deleted is still a true record of a mail birdcage sent.
--
-- subject and body are the finished message text, composed when the row
-- is written rather than when it is sent. A message rendered at send
-- time would describe the fleet as it is at the moment the SMTP server
-- finally came back, which may be hours after the event it is about.
--
-- attempts/next_attempt_at/last_error are the retry state. The sender
-- picks up rows where sent_at IS NULL AND next_attempt_at <= now; a
-- failure records attempts+1, the error, and a next attempt one minute
-- doubled per attempt up to a one-hour ceiling. last_error is birdcage's
-- own wording plus the server's, with the credential scrubbed out --
-- SECURITY.md's "never logged" rule covers a database column exactly as
-- much as a log line.
--
-- suppressed_count is how many further alerts for the same canary and
-- kind birdcage deliberately did not send while this row was the most
-- recent one -- the per-canary cooldown and the fleet-wide hourly cap
-- (internal/mail's named constants) are rate limits, and a rate limit
-- that silently drops what it stops is indistinguishable from a bug.
-- The next mail that does go out says how many were suppressed and
-- since when. The dashboard tile is never affected by any of this: the
-- state is the state whether or not an email was sent about it.
--
-- created_at/next_attempt_at/sent_at are RFC3339Nano text, the layout
-- every timestamp column in this schema uses (internal/store's
-- receivedAtLayout). They are compared as instants, never as text:
-- RFC3339Nano trims trailing zeros from the fractional seconds, so a
-- lexicographic SQL comparison sorts "...:00Z" after "...:00.5Z". Range
-- filters narrow through internal/store's timeCompare; every ordering
-- and every max is decided in Go on parsed time.Time values. See
-- 0010_canary_state_periods.sql's comment for the two rotation tests
-- this trap has already cost.
CREATE TABLE IF NOT EXISTS mail_outbox (
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind             TEXT NOT NULL,
    canary_id        TEXT,
    subject          TEXT NOT NULL,
    body             TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    attempts         INTEGER NOT NULL DEFAULT 0,
    next_attempt_at  TEXT NOT NULL,
    last_error       TEXT,
    sent_at          TEXT,
    suppressed_count INTEGER NOT NULL DEFAULT 0
);

-- The two query shapes that exist: everything still owed (the sender's
-- own per-tick drain, plus GET /api/mail's pending/failing counts), and
-- the most recent row for one canary and kind (the cooldown lookup, and
-- where a suppressed alert is counted).
CREATE INDEX IF NOT EXISTS idx_mail_outbox_unsent ON mail_outbox(sent_at, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_mail_outbox_kind ON mail_outbox(kind, canary_id, created_at);
