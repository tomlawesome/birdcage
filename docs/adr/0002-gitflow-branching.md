# ADR-0002: Gitflow branching with a preview promotion gate

**Status:** Accepted
**Date:** 2026-08-05

## Context

Birdcage needs a branch/release model decided before any code lands, so the
first commits establish the real structure rather than being retrofitted
later. `tomlawesome/orbit` already runs a working Gitflow-with-preview model
(its ADR-0003: `develop` -> `release/*` publishes digest-tagged previews ->
exact-digest promotion to `main` behind a protected environment). Birdcage
is much earlier-stage and doesn't have versioned releases yet, so this
adopts the same shape at a scale that matches where birdcage actually is,
rather than importing Orbit's full release/hotfix-branch machinery
unchanged.

## Decision

- **`dev`** is the integration branch. All issue work targets `dev`.
  Pushes to `dev` run a **light** CI gate only: `go build`/`go vet`/`go
  test`, frontend lint/typecheck/build. No container build, no image
  publish. Fast feedback is the point -- this is where most iteration
  happens.
- **`preview`** is protected: no direct pushes, PR-only, source must be
  `dev`. A merge into `preview` builds and publishes a uniquely
  digest-tagged container image (labeled as a preview build, mirroring
  Orbit's `release-stage=preview` convention) and runs the heavier gate:
  container smoke test against the real distroless image (healthcheck,
  as established in mikroview's CI pattern), and whatever
  integration/acceptance tests exist by then.
- **`main`** is protected: no direct pushes, PR-only, source must be
  `preview`. Merging into `main` does not rebuild anything -- a promotion
  step retags the *exact* digest that was already built and tested from
  `preview`, gated behind a protected GitHub Environment requiring manual
  approval. `main` never runs its own build; it only ever carries bytes that
  already passed the `preview` gate.
- **Deferred, not adopted yet:** Orbit's versioned `release/vMAJOR.MINOR.PATCH`
  and `hotfix/*` branches. Birdcage has no released version to protect or
  hotfix against yet -- `dev` -> `preview` -> `main` is sufficient until
  there's an actual release to version. Revisit this ADR (not a new issue)
  once that becomes relevant.

## Consequences

- Three long-lived branches (`dev`, `preview`, `main`) instead of mikroview's
  two (`dev`, `main`) -- more branches to keep in sync, in exchange for a
  real gate between "compiles and passes unit tests" and "the exact
  container image that will run in production has been smoke-tested."
- `main`'s protection can't just be "require PR" the way mikroview's is --
  it specifically must reject anything that isn't a promotion of an
  already-`preview`-tested digest. This needs a required status check (or
  equivalent workflow gate) on the promotion PR, not branch protection
  settings alone, since GitHub branch protection has no native "must come
  from this specific branch" rule.
- Slower to get a change into `main` than mikroview's direct-to-`dev`-then-PR
  workflow -- acceptable given birdcage's higher blast radius (it can take
  automated action against real infrastructure); mikroview's read-only
  nature doesn't carry the same risk.
