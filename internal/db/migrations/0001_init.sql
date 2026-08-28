CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT NOT NULL,
    source_ip   TEXT NOT NULL DEFAULT '',
    dest_port   INTEGER NOT NULL DEFAULT -1,
    service     TEXT NOT NULL,
    raw         TEXT NOT NULL,
    received_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_instance_id  ON alerts(instance_id);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip     ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_service        ON alerts(service);
CREATE INDEX IF NOT EXISTS idx_alerts_received_at    ON alerts(received_at);
