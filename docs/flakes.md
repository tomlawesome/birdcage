# Flakes

A flake is a check that failed and passed again on unchanged code (see the
testing-and-ci procedure). One heading per flake, one line per sighting. The
third sighting gets an issue, linked from the heading; until then this file is
the whole account.

## TestPublishDropsSlowestSubscriberRatherThanBlocking (internal/stream) -- fixed

- 2026-09-15 · b28c236 · local `go test ./internal/stream/... -race -count=5` ·
  failed once in 5 runs on code this package's own history shows untouched
  since `9a7fe52`: "fast subscriber was evicted; only the slow one should be".
  Timing-sensitive under `-race`'s added scheduling overhead.
- 2026-09-15 · ba2ec26 · local `go test ./internal/stream/ -race -count=10` ·
  failed 2 of 10 runs, same assertion.
- 2026-09-15 · fixed. The test, not the hub: it fired every publish back to
  back and assumed a concurrently draining reader kept up. Nothing scheduled
  that reader between publishes, so under `-race` its buffer sometimes filled
  and the hub correctly evicted it. The reader now acknowledges each event
  before the next is published. 70 consecutive `-race` runs clean.

## TestOldTokenInFlightDoesNotKillTheNewerOne (internal/ingest) -- not a flake; defect fixed

- 2026-09-15 · 2833431 · local `go test ./... -race` (full suite, no
  `-run` filter) · failed: "old token after the new one's first use:
  status = 200, want 401". Passed in 5/5 isolated re-runs
  (`-run TestOldTokenInFlightDoesNotKillTheNewerOne -count=5`), so this
  looks like the same class as the next heading below: back-to-back
  mints inside one test can land the same stored `created_at`, and
  RevokeCanaryTokensSupersededBy's ordering compares it with `<`.
- 2026-09-15 · 2833431 · local `go test ./internal/ingest/...` (full
  package, no `-run` filter) · same assertion failed again, same run in
  which `TestRotateOldTokenStopsWorkingOnlyAfterNewTokenFirstUsed` below
  passed -- so the two tests are not failing together, consistent with a
  timestamp-resolution race rather than shared state between them.

## TestRotateOldTokenStopsWorkingOnlyAfterNewTokenFirstUsed (internal/ingest) -- not a flake; defect fixed

- 2026-09-15 · 2833431 · local `go test ./internal/ingest/...` (full
  package, no `-run` filter) · failed: "old token after new one's first
  use: status = 200, want 401". Same symptom and same likely cause as
  `TestOldTokenInFlightDoesNotKillTheNewerOne` above: a rotation test
  that mints twice in quick succession, racing against whatever
  resolution `created_at` is actually stored and compared at.

### Both of the above: diagnosed 2026-09-15, and they were not flakes

The sighting notes above guessed right. `RevokeCanaryTokensSupersededBy`
compared `created_at` in SQL, and the two engines do not compare a stored
timestamp at the same resolution -- SQLite's `julianday()` works to roughly
50 microseconds, Postgres to a microsecond. Two tokens minted inside one of
those quanta compared EQUAL on SQLite, so the older one survived a sweep
that would have superseded it on Postgres.

That is a rule quietly meaning something different on each engine, not a
test that needs relaxing. The comparison now happens in Go on parsed
timestamps, which is exact on both. 8 consecutive `-race` runs of the full
package clean afterwards.

## e2e jobs: the built image disappears from the runner mid-pipeline -- not a flake; defect, see #112

Symptom, from `scripts/e2e/stack.sh`:

    stack: E2E_BIRDCAGE_IMAGE=birdcage-build:<id> names no local image -- it
    should have been built by build:images and handed to this job; refusing
    rather than building a different one

- 2026-09-22 · `5b7fbf5` (a docs-only merge, so nothing in the pipeline's own
  code could have caused it) · pipeline 1436 on `dev` · `build:images` ran at
  16:40:47 and succeeded at 16:42:15. `e2e:enrol-and-hit` and
  `e2e:enrol-and-hit:postgres` then passed, finishing 16:48:32. Every e2e job
  starting after that -- `e2e:smb` (16:48:34), `e2e:dashboard-own-ca`
  (16:48:53), `e2e:snmp` (16:49:11) -- failed on the line above. So the image
  was removed from the shared Docker daemon between 16:48:32 and 16:48:34,
  while the pipeline that built it was still running. Retrying the three e2e
  jobs alone cannot work: `build:images` does not re-run, so the image is
  still absent. Retrying `build:images` first and then the three turned all
  three green on unchanged code, and pipeline 1436 finished `success`.

- 2026-09-22 · pipeline 1437 on !51 · the same three-line failure, on
  `e2e:dashboard-own-ca` (16:51:03) and `e2e:snmp` (16:51:09), minutes after
  1436's own jobs had been put right.

### Diagnosed the same day, and it is not a flake

The second sighting gave it away: the two pipelines had killed each other.
`build:images` prunes every `birdcage-build:*` and `mockingbird-build:*` tag
except its own pipeline's, which is correct on a runner that runs one
pipeline at a time and wrong on this one, where the Docker daemon is shared
and pipelines overlap. 1437's build pruned 1436's image at 16:48; the hand
retry of 1436's build pruned 1437's at 16:51. Not random, and not the code
under test either time.

Filed as #112, which also carries the timing table and the candidate fixes.
`stack.sh` is not at fault: refusing to substitute an image is exactly what a
live test should do.

## e2e:enrol-and-hit / lifecycle.sh step 6 (revocation) -- not a flake; defect fixed, see #119

- 2026-09-23 · e60dfac · pipeline 1543, job 21207 · failed: "the alerts
  count changed across the refused request (51 -> 52): something was
  stored despite the 401". Retried as job 21261 on the same commit and
  passed.

### Diagnosed the same day, and it is not a flake

The step proved "nothing was stored despite the 401" by counting
`alerts where instance_id = $E2E_CANARY_ID` before and after the refused
request and requiring equality -- but that canary is live for the whole
journey (restarted in an earlier step, still delivering heartbeats and
self-tests later on), so any of its own real hits landing in the gap
between the two counts read as a false failure. Fixed by proving the
negative directly: post the revoked token's batch with a marker unique
to the run and query for that marker rather than for a count staying
still. Refs #119.

## TestRunCommandPollLoopDropsOnFullBuffer (cmd/mockingbird) -- fixed

- 2026-09-23 · 5a0c594 · pipeline 1528 `test:go` · "log output = ... context
  canceled, want a buffer-full drop naming cmd-1". The test slept a fixed
  50 ms for "several poll cycles at 5 ms"; under `-race` on a busy runner the
  first TLS handshake alone took longer, and the loop was cancelled before it
  had received a command. Passed 20/20 locally under `-race` on the same
  code.

### Fixed the same day

The test now cancels once the server has answered a second poll, which the
loop only starts after the first cycle's drop is logged. No sleep left.

