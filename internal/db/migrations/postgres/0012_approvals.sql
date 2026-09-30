-- approvals is issue #54's record of every administrator reply
-- birdcage has taken out of the approval mailbox (internal/mailbox),
-- verified or not. It exists for two reasons, and the second is the
-- one that matters.
--
-- The first is bookkeeping: an operator asking "did my approval
-- arrive, and what did birdcage make of it?" has somewhere to look.
--
-- The second is that the raw message is evidence birdcage cannot forge.
-- ADR-0007 makes each agent verify the administrator's DKIM signature
-- for itself, against DNS, on the bytes birdcage hands it. So the bytes
-- have to be kept exactly as they arrived -- raw is the message as the
-- IMAP server sent it, not a re-rendered copy. A birdcage that has been
-- taken over can withhold a row or invent one; it cannot make an
-- invented one verify.
--
-- message_id is UNIQUE, and that constraint is the replay defence, not
-- a tidiness rule. An approval is used once: the same signed message
-- replayed later is still a perfectly valid signature, so "have I seen
-- this Message-ID?" is the only thing standing between one approval and
-- an attacker reusing it. store.ApprovalSeen reads it and
-- internal/agent/approval's Seen hook is wired to that; the constraint
-- is the backstop for a race between two processes.
--
-- verified_at and reject_reason are the outcome, exactly one of which
-- is ever set. reject_reason is the verifier's own wording -- the first
-- rule the message broke, in plain words -- because "rejected" with no
-- reason is indistinguishable from a bug in the verifier.
--
-- applied_at is when the approval actually caused something to happen.
-- It is always NULL in slice 1: `upgrade` is still unmintable
-- (store.CommandKind, pinned by TestUpgradeCommandCannotBeMinted) and
-- there are no pending requests for an approval to match. The column
-- exists now so slice 2 marks a row rather than inventing a second
-- table to say the same thing.
--
-- reference is the token the subject carried, "[birdcage <ref>]" with
-- the brackets stripped. Not unique: an administrator may reply twice,
-- and a rejected first attempt followed by a good second one is a
-- sequence worth keeping both halves of.
--
-- raw is capped at 1 MiB by the two packages that write it
-- (internal/mailbox skips anything larger without downloading it;
-- internal/agent/approval refuses to parse it), not by a CHECK
-- constraint -- the same reasoning 0006_canary_commands.sql's kind and
-- 0011_mail_outbox.sql's kind give for closing a set in Go: a
-- constraint would have to be written once per engine and would then
-- disagree with the Go limit the moment either changed.
--
-- received_at/verified_at/applied_at are RFC3339Nano text, the layout
-- every timestamp column in this schema uses (internal/store's
-- receivedAtLayout). They are compared as instants, never as text:
-- RFC3339Nano trims trailing zeros from the fractional seconds, so a
-- lexicographic SQL comparison sorts "...:00Z" after "...:00.5Z". Every
-- ordering and every max is decided in Go on parsed time.Time values.
-- See 0010_canary_state_periods.sql's comment for the two rotation
-- tests this trap has already cost.
CREATE TABLE IF NOT EXISTS approvals (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    message_id    TEXT NOT NULL UNIQUE,
    from_address  TEXT NOT NULL,
    subject       TEXT NOT NULL,
    reference     TEXT NOT NULL,
    received_at   TEXT NOT NULL,
    verified_at   TEXT,
    reject_reason TEXT,
    raw           BYTEA NOT NULL,
    applied_at    TEXT
);

-- The two query shapes that exist: "have I seen this Message-ID?"
-- (already served by the UNIQUE index above) and "what has arrived for
-- this request?", which is how slice 2 finds the approval for a pending
-- upgrade.
CREATE INDEX IF NOT EXISTS idx_approvals_reference ON approvals(reference, received_at);
