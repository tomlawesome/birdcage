# Flakes

A flake is a check that failed and passed again on unchanged code (see the
testing-and-ci procedure). One heading per flake, one line per sighting. The
third sighting gets an issue, linked from the heading; until then this file is
the whole account.

## TestPublishDropsSlowestSubscriberRatherThanBlocking (internal/stream)

- 2026-09-15 · b28c236 · local `go test ./internal/stream/... -race -count=5` ·
  failed once in 5 runs on code this package's own history shows untouched
  since `9a7fe52`: "fast subscriber was evicted; only the slow one should be".
  Timing-sensitive under `-race`'s added scheduling overhead.
