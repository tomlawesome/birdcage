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

## Security tooling (set this up alongside the first real code, not deferred further)

There's no `.github/workflows/` or `.github/dependabot.yml` yet -- CodeQL
and Dependabot would have nothing to scan against docs alone, so adding
them now would be dead weight. **Whoever lands the first implementation
PR (any wave-1 issue) should set these up as part of that PR**, not push
it further down the road:

- **CodeQL**: Go + JS/TS matrix, PRs into `preview`/`main` (not `dev`) +
  a weekly full scan -- mirror `tomlawesome/mikroview`'s
  `.github/workflows/codeql.yml`. Check
  `gh api repos/tomlawesome/birdcage/code-scanning/default-setup` first
  and disable it via `gh api --method PATCH .../default-setup -f
  state=not-configured` if GitHub's own default setup is already
  enabled -- it conflicts with a custom/advanced workflow otherwise.
- **Dependabot**: `gomod`, `npm` (once the frontend exists), `docker`,
  `github-actions` ecosystems, weekly, targeting `dev`.
- Given birdcage holds live credentials and can take automated action
  (a materially higher blast radius than mikroview's read-only model --
  see SECURITY.md), consider requiring these checks on `dev` too, not
  just `preview`/`main` -- `tomlawesome/threadbeam` does this and it's
  a reasonable bar to match here.

## Security by design

New features are researched before they are designed — including an
explicit CVE search and a comparison against known secure and insecure
implementations. See
[docs/security-by-design.md](docs/security-by-design.md) for what that
requires and why.
