-- self_test_runs and self_test_targets (issue #46 item 4) are the
-- durable record of one scheduled self-test sweep, kept apart from
-- canary_commands.params (0006_canary_commands.sql), which already
-- carries the marker each target planted (selftest.Params, marshalled
-- JSON): these two tables are what ListCanaries' health computation and
-- the deadline sweep (internal/selftestsched) read, so neither has to
-- unmarshal and re-derive that JSON on every tick or every dashboard
-- request.
--
-- self_test_runs.command_id is the canary_commands.id MintSelfTestCommand
-- minted this run against -- no declared foreign key, matching this
-- schema's existing stance on canary_id columns (0003's heartbeats,
-- 0006's canary_commands). run_id duplicates selftest.Params.RunID
-- (already unique per mint, randomHex-generated) so a log line or an
-- operator view can name a run without joining back through params.
--
-- completed_at and passed are both NULL until the run resolves one of
-- two ways: every target matched (store.MatchSelfTest sets passed = 1
-- the moment the last one does), or the deadline sweep finds deadline_at
-- passed with completed_at still NULL and sets passed = 0. A run that
-- has neither yet is "still running", not "unknown" -- ListCanaries'
-- health state only ever reads the most recently *completed* run, so an
-- in-flight one never flaps a canary's tile.
--
-- passed is stored as INTEGER (0/1), nullable, matching this schema's
-- existing engine-portable-INTEGER-over-native-boolean convention
-- (0005_canary_agent_report.sql's own comment) with NULL carrying "not
-- resolved yet", distinct from 0 ("resolved, failed").
CREATE TABLE IF NOT EXISTS self_test_runs (
    command_id   TEXT PRIMARY KEY,
    canary_id    TEXT NOT NULL,
    run_id       TEXT NOT NULL,
    issued_at    TEXT NOT NULL,
    deadline_at  TEXT NOT NULL,
    completed_at TEXT,
    passed       INTEGER
);
CREATE INDEX IF NOT EXISTS idx_self_test_runs_canary_id ON self_test_runs(canary_id);

-- self_test_targets is one row per service self_test_runs.command_id
-- probed. marker_hash is the sha256 hex digest of the marker
-- MintSelfTestCommand planted for this target -- the marker itself is
-- never stored a second time here (it already lives, in the clear,
-- inside canary_commands.params for the agent to read once; this table
-- exists so a matching alert can be recorded without ever needing to
-- read params back), so a reader of this table alone learns nothing an
-- attacker could replay. store.MatchSelfTest looks a matched marker up
-- by its hash and sets matched_at; when every target of a command_id has
-- matched_at set, the owning run is marked passed = 1.
--
-- Primary key (command_id, service, dest_port): #46's own module survey
-- note (internal/selftest/params.go's Target doc comment) that HTTP and
-- HTTPS are indistinguishable by service name alone -- dest_port is
-- part of what makes one target distinct from another within a run.
CREATE TABLE IF NOT EXISTS self_test_targets (
    command_id  TEXT NOT NULL,
    service     TEXT NOT NULL,
    dest_port   INTEGER NOT NULL,
    marker_hash TEXT NOT NULL,
    matched_at  TEXT,
    PRIMARY KEY (command_id, service, dest_port)
);
CREATE INDEX IF NOT EXISTS idx_self_test_targets_marker_hash ON self_test_targets(marker_hash);
