# Contributing

Birdcage is a small, currently solo-maintained project. This document exists
so expectations are explicit even before there are external contributors,
not because a heavy process is needed yet.

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
