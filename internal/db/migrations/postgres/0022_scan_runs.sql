-- 0022_scan_runs.sql is issue #116's schema (ADR-0012 decisions 3, 4, 9
-- and 10): a scanner proves its enrolment by answering an ordered scan,
-- recorded on the same self_test_runs row a honeypot's self-test uses.
--
-- scan_snapshots.self_test_run_id names the run a snapshot settled --
-- self_test_runs.command_id, the run row's own key, never run_id: run_id
-- is what an agent answers with, and it stays out of every /api
-- response and the audit log (ADR-0012, Fleet's oracle). NULL for a
-- timer scan and for a snapshot that answered a spent or expired run.
-- db_refreshed_at is the agent's last successful `grype db update`;
-- db_refresh_error is that refresh's error text when this scan's refresh
-- failed (decision 10).
ALTER TABLE scan_snapshots ADD COLUMN self_test_run_id TEXT NULL;
ALTER TABLE scan_snapshots ADD COLUMN db_refreshed_at TEXT NULL;
ALTER TABLE scan_snapshots ADD COLUMN db_refresh_error TEXT NULL;

-- trigger says who ordered the run: 'proof' (enrolment proof, and every
-- honeypot row before this column -- "scheduled or first-contact") or
-- 'manual' (decision 7, not built yet). stage and stage_at are decision
-- 9's progress report; NULL on every honeypot run, set on every scan
-- run from its mint ('ordered') onward. reason is why a scan run did not
-- pass, NULL otherwise.
ALTER TABLE self_test_runs ADD COLUMN "trigger" TEXT NOT NULL DEFAULT 'proof';
ALTER TABLE self_test_runs ADD COLUMN stage TEXT NULL;
ALTER TABLE self_test_runs ADD COLUMN stage_at TEXT NULL;
ALTER TABLE self_test_runs ADD COLUMN reason TEXT NULL;

-- At most one open scan run per node (decision 7, "one run in flight per
-- scanner, proof or manual"), enforced by the database as well as by
-- store.MintScanCommand's own check, so two mint paths racing cannot
-- both win. stage IS NOT NULL is what marks a scan run: honeypot runs
-- never set it, and are not limited here.
CREATE UNIQUE INDEX IF NOT EXISTS idx_self_test_runs_one_open_scan
    ON self_test_runs(canary_id) WHERE completed_at IS NULL AND stage IS NOT NULL;

-- The node's database refresh while it is failing (decision 10).
-- db_refresh_failing_since is birdcage's own clock at the first failing
-- report since the last success -- never the agent's, so a wrong agent
-- clock cannot hide or hasten db_stale. Both NULL while refreshes
-- succeed.
ALTER TABLE canaries ADD COLUMN db_refresh_failing_since TEXT NULL;
ALTER TABLE canaries ADD COLUMN db_refresh_error TEXT NULL;
