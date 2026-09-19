-- enrolment_sessions is issue #47 slice 1b's record of one deploy-token
-- exchange: mint (birdcage, `birdcage canary enrol`), first contact (a
-- freshly booted canary's one call to POST /enrol/hello), and
-- provisioning/verification (later slices). Deliberately its own table
-- and its own endpoint mux -- design note decision 1: "A separate
-- enrolment_sessions table and a separate endpoint mux, never the
-- canary_tokens model." A deploy token authenticates exactly one
-- request, once; canary_tokens' bearer-credential-for-every-request
-- shape (0004_canary_tokens.sql) does not fit that.
--
-- token_hash is the deploy token's SHA-256 (hex), the same HashToken
-- convention canary_tokens.token_hash already uses (internal/store's
-- MintEnrolmentSession) -- the raw value is shown once at mint and never
-- stored.
--
-- canary_name and lane are `birdcage canary enrol --name/--lane`'s two
-- required flags (issue #47 slice 3), captured at mint time and carried
-- on the session until a later slice's provisioning step (store.Provision)
-- reads them to build the canaries row -- the operator names the canary
-- before it exists, not after.
--
-- first_contact_deadline is created_at + 5 minutes: a deploy token not
-- presented to POST /enrol/hello by then can never succeed (state moves
-- to "expired" on the next attempt). burned_at is set the moment first
-- contact succeeds, in the same transaction that mints
-- enrolment_secret_hash (design note decision 1: "First contact sets
-- burned_at in the same transaction that generates the enrolment
-- secret"). A session whose burned_at is already set refuses every
-- later POST /enrol/hello with the same uniform refusal an unknown or
-- expired token gets (internal/enrol) -- a crash between burning and
-- returning the secret leaves the row burned; the secret is never
-- re-issued.
--
-- enrolment_secret_hash is the SHA-256 (hex) of the fresh secret first
-- contact mints and returns exactly once (design note decision 2); NULL
-- until then, and deliberately nullable again afterwards -- a later
-- slice shreds it (sets it back to NULL) once provisioning has consumed
-- it, so the schema already allows that rather than needing a migration
-- to add it.
--
-- window_deadline is burned_at + 30 minutes, the provisioning window a
-- later slice enforces; NULL until first contact sets it alongside
-- burned_at.
--
-- state is the closed set of session states (internal/store's
-- EnrolmentState: minted, contacted, provisioned, verified, expired,
-- failed) -- kept as a closed list in Go rather than a SQL CHECK
-- constraint, the same reasoning 0006_canary_commands.sql's kind column
-- and 0007_settings.sql's key column both use.
--
-- canary_id is NULL until provisioning (a later slice) names which
-- canary this session became; no declared foreign key, matching
-- canary_tokens.canary_id and canary_commands.canary_id.
CREATE TABLE IF NOT EXISTS enrolment_sessions (
    id                      TEXT PRIMARY KEY,
    token_hash              TEXT NOT NULL,
    canary_name             TEXT NOT NULL,
    lane                    TEXT NOT NULL,
    created_at              TEXT NOT NULL,
    first_contact_deadline  TEXT NOT NULL,
    burned_at               TEXT,
    enrolment_secret_hash   TEXT,
    window_deadline         TEXT,
    state                   TEXT NOT NULL,
    canary_id               TEXT
);

-- token_hash is the sole lookup key POST /enrol/hello carries, so it
-- must be unique as well as indexed -- the same shape
-- idx_canary_tokens_hash uses in 0004_canary_tokens.sql.
CREATE UNIQUE INDEX IF NOT EXISTS idx_enrolment_sessions_token_hash ON enrolment_sessions(token_hash);
