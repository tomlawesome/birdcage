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
