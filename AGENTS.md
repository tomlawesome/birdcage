# Birdcage agent instructions

Outside pull requests are not accepted at all — see `CONTRIBUTING.md`.

## Delivery host

GitLab-first: `gitlab.tomlawson.io/ai/birdcage` (project 51, default branch
`dev`) holds branches, merge requests, issues and the gate
(`.gitlab-ci.yml`). Remote `gitlab` is primary; `origin` is the read-only GitHub
mirror `tomlawesome/birdcage`, which keeps CodeQL, dependency review and the manual
countersigning workflow (#90). It has no issues and no pull requests.
Countersigning runs only on GitHub, because Sigstore's issuer list has no
self-hosted GitLab; the owner starts it by hand after a release. No GitHub credential on this
host may have Actions write, so no agent can start it (#169;
`docs/releasing.md`).

## Security by design

Research a feature before designing it, including an explicit CVE search;
reproduce a finding before acting on it, including findings from
automated research, which has produced wrong version numbers and inflated
severity scores. See
[docs/security-by-design.md](docs/security-by-design.md).

## Third-party modules

A new third-party module needs the owner's approval on its issue, with
provenance. `supply-chain/dependency-inventory.md` is the approved list.

## Releasing

Procedure: `docs/releasing.md`. Two rules, enforced by
`scripts/ci-release-guard.py`: no job both judges an artefact and ships it,
and exactly one job may sign. The version lives in `VERSION` and is read
only through `scripts/release-version.sh`. Licence gates:
`scripts/licence-check.sh` (Go), `-npm.sh`, `-python.sh` (OpenCanary image);
policy and owner-accepted exceptions in `supply-chain/licence-policy.yml`.

The Python gate also looks inside each package (#179): vendored packages
(a `.dist-info` below the top level) face the same rules, and every image,
web page, stylesheet, script, feed or font a package installs must sit
under a reviewed `python-bundled-assets:` entry -- those files carry no
licence field, which is how OpenCanary's Synology skin passed as "BSD".

## Live testing is not optional

Owner, 2026-09-19: "Every piece of the security infrastructure should be live
tested every single time a change is made that affects it."

- `e2e` jobs are never `allow_failure`, `when: manual` or scheduled.
- A change to enrolment, credentials, ingest or the images lands with its
  journey in the same merge request.
- Browser journeys run in Firefox; Safari and Edge only at promotion.

Reasoning: `docs/testing.md`; which check sits at which hop: `docs/ci-hops.md`.

## Attack-tool fixtures

Owner, 2026-09-24: the mirror is public, so attack tooling is never built
here: no Dockerfile, entrypoint or run recipe, not even under `build/e2e-*`.
It lives in the private `ai/birdcage-fixtures` (#127); only the pin in
`.gitlab-ci.yml` lives here.

## Worktrees

Run `npm ci` in a worktree's `frontend/`; never symlink `node_modules`
(Vitest resolves through the link and fails; owner, 2026-10-01).
