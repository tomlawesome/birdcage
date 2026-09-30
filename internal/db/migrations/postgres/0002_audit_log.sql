CREATE TABLE IF NOT EXISTS audit_log (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    action       TEXT NOT NULL CHECK (length(action) > 0),
    target       TEXT NOT NULL CHECK (length(target) > 0),
    reason       TEXT NOT NULL CHECK (length(reason) > 0),
    triggered_by TEXT NOT NULL CHECK (length(triggered_by) > 0),
    created_at   TEXT NOT NULL
);

-- Postgres has no per-statement RAISE(ABORT) trigger shorthand (SQLite's
-- form used in migrations/sqlite/0002_audit_log.sql): a BEFORE
-- UPDATE/DELETE trigger here must call a trigger function. CREATE OR
-- REPLACE TRIGGER (Postgres 14+) keeps this migration idempotent on
-- retry the same way SQLite's "IF NOT EXISTS" does.
CREATE OR REPLACE FUNCTION audit_log_block_mutation() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER audit_log_no_update
BEFORE UPDATE ON audit_log
FOR EACH ROW EXECUTE FUNCTION audit_log_block_mutation();

CREATE OR REPLACE TRIGGER audit_log_no_delete
BEFORE DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION audit_log_block_mutation();
