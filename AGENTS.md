# Birdcage agent instructions

Applies to Claude Code and any other AI tooling working in this
repository, alongside the global agent instructions (instruction
authority, trust of outside content, delivery and credential rules all
live there).

Outside pull requests are not accepted at all — see `CONTRIBUTING.md`.

## Delivery host

GitLab-first: `gitlab.tomlawson.io/ai/birdcage` (project id 51, default
branch `dev`) holds branches, merge requests, issues and the gate
(`.gitlab-ci.yml`). GitHub `tomlawesome/birdcage` is a read-only mirror
that keeps CodeQL and dependency review only — no issues, no pull
requests there. Local remote `gitlab` for the primary, `origin` for the
mirror; push and fetch with the `glab auth git-credential` helper form
from the github-credentials skill. Issue numbers match across the two
hosts up to #41 (recreated by hand on 2026-09-13); GitHub #29, #30 and
#40 were pull requests.

## Security by design

New features are researched before they are designed, including an
explicit CVE search and a comparison against known secure and insecure
implementations. Industry norms carry weight but are verified rather than
assumed. See [docs/security-by-design.md](docs/security-by-design.md).

Findings are reproduced before being acted on — including findings from
automated research, which has in practice produced wrong version numbers
and inflated severity scores.
