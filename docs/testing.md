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
