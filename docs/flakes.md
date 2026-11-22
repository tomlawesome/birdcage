# Flakes

A flake is a check that failed and passed again on unchanged code (see the
testing-and-ci procedure). One heading per flake, one line per sighting. The
third sighting gets an issue, linked from the heading; until then this file is
the whole account.

## TestSourceLimitersAllowBoundary (internal/enrol) -- #170

- 2026-09-23 · ed9668f · local `go test ./... -race` in a `golang:1.27`
  container reproducing the `test:go` conditions (real Postgres, non-root
  uid 1001) · "allow() call 3001 = true, want false (burst exhausted)".
  Passed on an immediate rerun of the identical command against the same
  code and the same containers. The assertion is on the exact boundary of a
  rate limiter's burst, so it looks timing-sensitive under `-race`'s added
  scheduling overhead -- but that is a guess from one sighting, not a
  diagnosis. First sighting; nothing changed on the strength of it.
- 2026-09-27 · 072b072 (unrelated change: #138, internal/store test speed)
  · local `go test -race ./...` in a `golang:1.27` container reproducing
  `test:go` (real Postgres, non-root uid 1001, several other containers
  sharing the host) · same symptom, "allow() call 3001 = true, want false
  (burst exhausted)". Second sighting; still not diagnosed, still not
  touched.
- 2026-10-03 · 4e0c378 · `test:go` on `main` pipeline 2006 (job 30280),
  just after the v0.1.0 promotion; the same code passed `test:go` in
  pipelines 1994 and 1995 · same symptom. Third sighting: #170 filed. Likely
  cause there: the limiter refills 50 tokens a second from the real clock,
  so a loop slower than about 20 ms gets one token back.

## e2e:agent-credentials:postgres -- step 3 (certificate_expired)

- 2026-09-27 · 7773730 (!84, frontend-only: trace label placement) ·
  pipeline 1733 job 25050 · "not_delivering with certificate_expired never
  became true ... within 300s (E2E_CLIENT_CERT_TTL=4m)". Passed on retry
  (job 25216) against the same commit. The runner was carrying three
  pipelines at once; not diagnosed. First sighting.

## e2e:enrol-and-hit:postgres -- lifecycle.sh step 6 (rotation)

- 2026-09-27 · 7773730 (!84, frontend-only: trace label placement) ·
  pipeline 1733 job 25048 · "the old-token request could not be sent".
  Passed on retry (job 25217) against the same commit, under the same
  three-pipeline load. Not diagnosed. First sighting. Distinct from #146,
  which fails lifecycle.sh step 1.

## Dependency proxy answers 502 on an image pull (build:images)

- 2026-09-30 · 0c3e368 · pipeline 1845 / build:images · the job's own image
  pull from GitLab's dependency proxy failed "502 Bad Gateway" after 5s,
  before any script ran; the job does not touch the code this batch changed.

## gitleaks release download answers 504 (lint:gitleaks)

- 2026-10-01 · 0b5eb09 · pipeline 1916 (!95) / lint:gitleaks, job 28440 ·
  `scripts/ensure-gitleaks.sh` got "curl: (22) The requested URL returned
  error: 504" from github.com before any scan ran. Retried as job 28489.

## golangci-lint build: module downloads cut off (lint:go)

- 2026-11-21 · e1f21a7 · pipeline 5166 (!187) / lint:go, job 61870 ·
  building the linter, every module fetch from the Go module proxy ended
  "unexpected EOF" before any lint ran. Retried as job 62001.

## startup-refusals.sh -- first refusal outlived its 15 s bound (local)

- 2026-10-10 · 2cbda6f plus the uncommitted #8 slice C journeys · local
  `scripts/e2e/startup-refusals.sh` on a shared host · step 1 (sign-in key
  unset) was killed by its 15 s `timeout` although the container had
  already logged the refusal; the same image exits in about a second when
  run alone, and the rerun straight after passed all five steps. Cause
  unknown: a slow first `docker run` on a busy daemon would fit, but so
  would a real hang -- birdcage logging its refusal and then not exiting
  -- so a refusal outliving the 15 s bound again is not to be waved off as
  this flake without looking.

## Runner disk full during the Go tests (test:go) (host)

- 2026-11-15 · 6dcffab · pipeline 4240 (!122) / test:go, job 51839 ·
  two trusted-proxy tests failed at db.Migrate with "database or disk is
  full (13)"; the runner also warned of a disconnected postgres service
  container. Retried as job 51896, which passed.

## TestSessionCookieSecureAttributeFollowsConfig (internal/auth) (host)

- 2026-11-18 · d49652a · local
  `go test ./... -race` against a throwaway Postgres on a shared host (load
  average about 56) · SecureCookie_false: "POST .../api/auth/totp/confirm:
  context deadline exceeded"; the package took 607 s. Passed alone straight
  after (16 s) and in the full Postgres rerun on the same code.

## portscan step 3, the rate cap holds (e2e:portscan)

- 2026-11-18 · bafbcfe · pipeline 4681 (!154) / e2e:portscan, job 56419 ·
  "alert count climbed to 2": the second alert came from another address on
  the e2e network (5 ports), not the sweeper, and the helper counts alerts
  per canary rather than per source. The product's per-source cooldown held.
  Retried as job 56773, which passed.
- 2026-11-21 · f647bda (batch-a) · pipeline 5115 / e2e:portscan · the same
  message and cause: a second alert from another address on the e2e network.
  Passed in pipeline 5128 on unchanged product code.

## TestCheckStartupAuthContinuityAllowsAUsedDatabaseWithAccounts (cmd/birdcage)

- 2026-11-21 · 2090fe6 · pipeline 5140 (!187) / test:go, job 61454 ·
  subtest a_user.register_audit_row: "register first admin: status 500,
  want 201", with "no such table: audit_log" and "no such table: approvals"
  logged nearby; the package took 580 s. The test is unchanged since #164
  and passed in pipeline 5128; three local runs straight after passed.
