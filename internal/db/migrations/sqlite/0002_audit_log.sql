CREATE TABLE IF NOT EXISTS audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    action       TEXT NOT NULL CHECK (length(action) > 0),
    target       TEXT NOT NULL CHECK (length(target) > 0),
    reason       TEXT NOT NULL CHECK (length(reason) > 0),
    triggered_by TEXT NOT NULL CHECK (length(triggered_by) > 0),
    created_at   TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE is not permitted');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: DELETE is not permitted');
END;
