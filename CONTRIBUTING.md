# Contributing

Birdcage is a small, solo-maintained project. This document records how the
maintainer works in this repository, so expectations are explicit.

**Outside pull requests are not accepted.** Bug reports and issues are
welcome and read, but they are information for the maintainer rather than
work items, and changes are not taken from outside contributors.

## Branching

See [ADR-0002](docs/adr/0002-gitflow-branching.md). In short: branch from
and target `dev` for issue work. `preview` and `main` are protected and
reached only via PR promotion, not direct pushes or direct feature PRs.

## Before starting work

- Check [docs/v1-scope.md](docs/v1-scope.md) and the relevant epic
  (`epic` label) to see where a piece of work fits and what it depends on.
- If what you want to do isn't already an issue, open one first -- decisions
  and scope belong in the repo (issues/docs), not left implicit in a PR
  description or a commit message.

## Testing expectations

- New behavior needs a test that would fail without it -- prefer testing
  observable behavior (what a caller/user sees) over internal
  implementation details.
- A bug fix should include a regression test reproducing the bug where
  practical.
- `dev`'s CI gate is deliberately light (build/vet/test/lint, no container
  build) for fast feedback -- see [ADR-0002](docs/adr/0002-gitflow-branching.md).
  The heavier container/integration gate runs on promotion to `preview`.
- Any code path that writes to the audit log, or that could take an
  automated mitigation action, needs a test proving it actually writes the
  audit entry -- not just that the mitigation logic itself runs. See
  [ADR-0001](docs/adr/0001-stack-and-storage.md) on why the audit trail is
  required, not optional.

## Secrets

Never commit credentials (CrowdSec, RouterOS service account, or anything
else) to the repository, including in test fixtures or example configs.
See [SECURITY.md](SECURITY.md).

## Security tooling

The gate in `.gitlab-ci.yml` runs on every merge request and on `dev`:
Go build/vet/lint (`lint:go`), licence gates for Go, npm and Python
dependencies (`lint:licences`, `lint:licences-python`, and the npm
check that runs inside `test:frontend`), the full `scripts/*.test.sh`
suite (`lint:scripts`), a guard on this CI shape itself (`lint:ci`), a
Go vulnerability scan (`lint:govulncheck`), a secret scan
(`lint:gitleaks`), and the `e2e` stage's live checks against the real
stack. `preview` and `main` carry a higher bar than `dev`, not the same
one -- see [docs/ci-hops.md](docs/ci-hops.md) for which check sits at
which hop and why.

The GitHub mirror (`tomlawesome/birdcage`) is read-only and keeps only
CodeQL, dependency review and Dependabot -- no issues, no pull requests
there.

Secret scanning is a local gitleaks pre-commit gate plus the
`lint:gitleaks` job, since GitHub's non-provider secret-scanning
patterns aren't available on this plan.

A change to any of this lands with its live check in the same merge
request, not a follow-up issue (AGENTS.md, "Live testing is not
optional").

## Security by design

New features are researched before they are designed — including an
explicit CVE search and a comparison against known secure and insecure
implementations. See
[docs/security-by-design.md](docs/security-by-design.md) for what that
requires and why.
