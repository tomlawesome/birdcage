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
