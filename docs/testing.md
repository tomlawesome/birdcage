# Testing

How birdcage is tested, what the gates measure, and the rules a change has
to meet. The rules themselves are in [CONTRIBUTING.md](../CONTRIBUTING.md)
("Testing expectations"); this page records how they are enforced.

## Layers

| Layer | What runs | Where |
| --- | --- | --- |
| Go unit and package tests | `go test ./... -race`, against SQLite and a real Postgres (`BIRDCAGE_TEST_DATABASE_URL`) | `test:go` |
| Frontend unit tests | Vitest with coverage | `test:frontend` |
| Dashboard smoke and pixel checks | Playwright journeys in `frontend/e2e/`, band comparisons | `test:smoke`, `test:smoke:postgres` |
| Image tests | Each built image started and probed on its own | `test:image:*` |
| Live end-to-end journeys | The real images, stack and agents under `scripts/e2e/` | `e2e:*` |

Which jobs run at which hop, and why the `dev` gate is lighter than
`preview`'s, is in [ci-hops.md](ci-hops.md).

## Live testing is not optional

Owner, 2026-09-19: "Every piece of the security infrastructure should be
live tested every single time a change is made that affects it."

A unit test against a fake proves the code agrees with our own assumptions.
Only a live check disagrees with us, which is the whole reason to have one:
#65's packet filter passed every unit test while matching no packets at all,
and only running the real image found it.

CI enforces this; nobody has to remember it. The `e2e` stage (#78) deploys
the real stack -- birdcage, an enrolled Mockingbird container -- and
exercises the real functions, on every merge request and on `dev`. Its jobs
are never `allow_failure`, never `when: manual` and never moved to a
schedule; `lint:ci` (`scripts/ci-e2e-guard.py`) refuses `allow_failure`,
`when: manual` and rules that leave the gate's anchors (which never run on a
schedule): a
change cannot reach `dev` without the live checks having run. The project
also refuses a merge unless the pipeline succeeds.

`preview` and `main` carry a higher bar than `dev`, not the same one (#91):
the journeys run again there against Postgres. Which check sits at which hop,
and why, is [ci-hops.md](ci-hops.md); read it before changing
`.gitlab-ci.yml`, because `lint:ci` enforces that shape and refuses an `e2e`
job whose rules match neither hop's anchor.

So a change to enrolment, credentials, the ingest path, the images or
anything else the live checks cover lands with its journey in the same merge
request, not a follow-up issue.

Browser journeys run in Firefox, which is what the owner uses (#83). Safari
and Edge are added at the `preview` -> `main` promotion, not on every change.
A check that looks enforced and is not is the thing this rule exists to
prevent.

## Attack-tool fixtures

Owner, 2026-09-24: attack tooling used by the live checks -- Responder for
#86, and anything like it later -- is never built in this repository. Its
mirror is public, and a ready-to-run recipe for a poisoner is not something
this project publishes. Such a fixture is built, scanned and kept current in
the private fixtures project on GitLab (`ai/birdcage-fixtures`, #127) and
pulled here by digest; the pin in `.gitlab-ci.yml` is the whole of what lives
in this repository, and moving it is the version check. Never a Dockerfile,
entrypoint or run recipe for such a tool here, not even under `build/e2e-*`.

## Coverage is a ratchet, not a target

Coverage is measured on every merge request and never allowed to fall.

**Go.** `test:go` writes a profile and `scripts/coverage-floor.py` checks it
against `supply-chain/coverage-floors.yml`, one floor per package. A package
fails below its floor, and also fails more than 5 points *above* it: that
means the floor is stale, and the fix is to raise it, never to leave the
headroom. Floors only ever go up. The band the owner set (2026-09-20, issue
#74) is 70–85% statement coverage: a package inside it is done, and effort
belongs on packages below 70%, each of which carries its reason in the yml.
Go measures statements, not branches; a 100% package means every line ran,
not that every condition was tried both ways.

Measure the way CI does or the numbers are wrong in both directions: with
`-race`, and with Postgres up, otherwise `internal/db`'s Postgres paths read
as uncovered. The header of `coverage-floors.yml` has the commands.

**Frontend.** `npm run test:coverage` enforces the thresholds in
`frontend/vitest.config.ts` (statements 85, branches 70 at the time of
writing), set at measured values and never lowered. The report is attached to
the merge request as Cobertura so coverage shows on the diff.

## What a test has to prove

- New behaviour needs a test that would fail without it; prefer what a caller
  or user sees over internal detail.
- A bug fix carries a regression test that reproduces the bug first. A test
  that has never failed proves nothing; if shipping without one, say so on the
  issue.
- Anything that writes the audit log, or could take a mitigation action,
  needs a test proving the audit entry is written.
- A refusal is behaviour: startup checks, authentication and validation paths
  get negative tests, not only the happy path.
- A check that fails and passes again on unchanged code is a flake: record it
  in [flakes.md](flakes.md), and file an issue on its third sighting.
