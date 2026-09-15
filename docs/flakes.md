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

## TestOldTokenInFlightDoesNotKillTheNewerOne (internal/ingest)

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

## TestRotateOldTokenStopsWorkingOnlyAfterNewTokenFirstUsed (internal/ingest)

- 2026-09-15 · 2833431 · local `go test ./internal/ingest/...` (full
  package, no `-run` filter) · failed: "old token after new one's first
  use: status = 200, want 401". Same symptom and same likely cause as
  `TestOldTokenInFlightDoesNotKillTheNewerOne` above: a rotation test
  that mints twice in quick succession, racing against whatever
  resolution `created_at` is actually stored and compared at.
