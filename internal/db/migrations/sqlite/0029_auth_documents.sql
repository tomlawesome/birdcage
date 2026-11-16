-- 0029_auth_documents.sql is issue #8's sign-in storage (ADR-0016
-- decision 2): the shared auth module (gauntlet) owns no database, so
-- each of its stores -- accounts, tokens, signins -- is saved here as one
-- document, written by internal/authstore.
--
-- name is the store ("accounts", "tokens", "signins") and the primary
-- key, so there is exactly one row per store. payload is the store's
-- whole document, already sealed under BIRDCAGE_AUTH_KEY_FILE's key
-- (persist.Encrypt) before it reaches this table: nothing here is ever
-- readable without that key. The bytes are opaque to SQL and kept
-- exactly as given.
--
-- version is the optimistic-concurrency counter the module's persist
-- contract needs: a write names the version it read, and only succeeds
-- while that is still the stored one (authstore.Backend.Save). It is a
-- plain integer, counted up by one on every write; 0 is "no row yet".
-- updated_at is RFC3339Nano UTC text like every other timestamp in this
-- schema, for an operator reading the table, never compared in SQL.
CREATE TABLE IF NOT EXISTS auth_documents (
    name       TEXT PRIMARY KEY,
    payload    BLOB NOT NULL,
    version    INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);
