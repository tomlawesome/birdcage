-- client_certs records every client certificate birdcage signs for an
-- agent (issue #130, ADR-0012 Part B2). The ingest auth path refuses any
-- presented certificate whose SHA-256 fingerprint is not a live row
-- here, whatever its signature: a certificate birdcage did not record,
-- or has revoked, is a 401. Rows are written at provisioning and at
-- every renewal (POST /ingest/renew), in the same transaction that
-- signs them.
--
-- id is issuance order and nothing else. "Older than" (the one-way rule:
-- a certificate's first use revokes every certificate issued before it
-- for the same canary) is decided on id, never on not_before: X.509
-- validity has one-second resolution, and the two engines compare
-- stored text timestamps at different resolutions (docs/flakes.md), so
-- two renewals inside one second would otherwise be unordered.
--
-- Timestamps are RFC 3339 text like every other table here; any
-- comparison that matters is made in Go on parsed values.
--
-- Nodes enrolled before this table existed have no row, so their
-- certificates fail closed and every such node re-enrols once
-- (ADR-0012, Consequences). Nothing is backfilled: birdcage never
-- recorded what it issued, so there is nothing trustworthy to backfill
-- from.
CREATE TABLE IF NOT EXISTS client_certs (
    id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    canary_id          TEXT NOT NULL,
    serial             TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    not_before         TEXT NOT NULL,
    not_after          TEXT NOT NULL,
    first_used_at      TEXT,
    revoked_at         TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_client_certs_fingerprint ON client_certs(fingerprint_sha256);
CREATE INDEX IF NOT EXISTS        idx_client_certs_canary_id   ON client_certs(canary_id);

-- cert_fingerprint binds a bearer token to the client certificate it was
-- minted under (ADR-0012 B3, RFC 8705's shape). NULL for every token
-- minted before this column existed and for tokens minted outside the
-- enrolment/rotation paths (`birdcage canary add`); the ingest auth path
-- treats NULL as a mismatch, so such a token never authenticates over
-- mutual TLS.
ALTER TABLE canary_tokens ADD COLUMN cert_fingerprint TEXT;

-- The latest "one live credential, two places at once" observation
-- (ADR-0012 B4, ingest.credential_dual_use), kept on the canary so the
-- dashboard can say which two addresses, or which two agent builds, used
-- one certificate. Each pair is a JSON array of exactly two strings,
-- written with its own time; the credential_conflict state holds while
-- either time is recent and clears by itself after that. The audit log
-- keeps the history; these columns keep only the newest pair of each
-- kind. NULL until the first observation.
ALTER TABLE canaries ADD COLUMN credential_dual_use_addrs TEXT;
ALTER TABLE canaries ADD COLUMN credential_dual_use_addrs_at TEXT;
ALTER TABLE canaries ADD COLUMN credential_dual_use_versions TEXT;
ALTER TABLE canaries ADD COLUMN credential_dual_use_versions_at TEXT;
