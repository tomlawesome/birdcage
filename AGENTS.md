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
that keeps CodeQL, dependency review, and the manual countersigning
workflow (#90) — no issues, no pull requests there. Countersigning is the
one thing the mirror does that GitLab cannot: Sigstore's trusted issuer
list has no entry for a self-hosted GitLab, so keyless signing is only
available on GitHub, and the owner starts it by hand after a release. Local remote `gitlab` for the primary, `origin` for the
mirror; push and fetch with the `glab auth git-credential` helper form
from the github-credentials skill. Issue numbers match across the two
hosts up to #41 (recreated by hand on 2026-09-13); GitLab #29, #30 and
#40 are closed placeholders holding the numbers of GitHub pull requests.

## Closing issues from commits

GitLab's issue-closing pattern counts `Implements` alongside `Closes` and
`Fixes`, and it ignores that a reference is possessive: a subject of the form
`Implements #N's HTTP client` shuts the whole of issue N while naming only a
part of it. Issue 48 was shut this way twice on 2026-09-17 -- once by such a
commit subject, and once by a merge-request body that quoted that subject in
order to warn about it.

So the rule is not only to write `Refs #N` on a commit that does not finish an
issue. It is that a closing keyword must never sit next to a real issue number
anywhere GitLab parses -- commit messages and merge-request descriptions alike,
including prose explaining this trap. Use a placeholder such as `#N`.

## Security by design

New features are researched before they are designed, including an
explicit CVE search and a comparison against known secure and insecure
implementations. Industry norms carry weight but are verified rather than
assumed. See [docs/security-by-design.md](docs/security-by-design.md).

Findings are reproduced before being acted on — including findings from
automated research, which has in practice produced wrong version numbers
and inflated severity scores.

## Approved third-party modules

The global rule (dependencies-and-data skill) is: no third-party module
without the owner's explicit approval. Approved for this project, with the
issue that records the decision:

- `golang.org/x/net` (bpf) and `golang.org/x/sys` — Go team; #65, 2026-09-19.
- `github.com/emersion/go-imap/v2` — approval mailbox; #54, 2026-09-19.
- `github.com/emersion/go-msgauth` (dkim) — agent-side signature check;
  #54, 2026-09-19. Brings `emersion/go-message`, `emersion/go-sasl`,
  `emersion/go-milter` (module only, never linked) as the same author.
- `github.com/jackc/pgx/v5`, `modernc.org/sqlite` — predate the rule; listed
  for the owner's review on #73.

Shipped as a binary in an agent image, never linked into birdcage:

- `grype` (Anchore) — the scanner agent's engine, Apache-2.0; owner,
  2026-09-22, #108. Chosen over Trivy against a verified comparison; the
  reasoning is in ADR-0010, "Engine: Grype". Its vulnerability database is
  fetched at runtime and cached, never vendored.
- `samba-server` (Samba Team, via Alpine) — the SMB lure's whole reason to
  exist, GPL-3.0-or-later; owner, 2026-09-23, #87 decision 1 ("Real Samba on
  Alpine"). Pinned to an exact apk version in `build/smb-lure/Dockerfile` and
  rebuilt on every Alpine security update to it. No apk licence gate exists,
  so this entry and `supply-chain/dependency-inventory.md` row 226 are the
  record; GPLv3 in a shipped image has the owner's precedent in
  `hpfeeds@3.0.0`.

Frontend (`frontend/package.json`), dev-only, never shipped:

- `@vitest/coverage-v8` -- the coverage plugin of the test runner the
  project already uses, by the same team (vitest-dev) and peer-pinned to
  the exact vitest version, so not a new third party to trust. MIT.
  Owner, 2026-09-20: *"it's not really a third party. It's a plugin by
  the exact same team."* #74.

Anything else goes to the owner first, on the issue, with provenance.

## Releasing

`docs/releasing.md` is the procedure and the setup the owner has to do
once. The shape in one line: build the images once, judge those exact
bytes, sign the digest on a runner that holds the key and does nothing
else, verify that signature before any name is put on the digest, and
promote the tested digest rather than rebuilding it.

Two rules hold the whole thing up, and `scripts/ci-release-guard.py`
fails the pipeline when either is undone: **no job both judges an
artefact and ships it**, and **exactly one job may sign**. The version
lives in the tracked `VERSION` file and is read only through
`scripts/release-version.sh`; nothing else computes a version or a build
stamp.

Licence gating by ecosystem: `scripts/licence-check.sh` covers Go modules,
`scripts/licence-check-npm.sh` covers npm (#92), and
`scripts/licence-check-python.sh` covers the pip packages installed into
the mockingbird image (#95). A package whose own metadata names a licence
outside `supply-chain/licence-policy.yml`'s allow-list, or names none at
all, fails the gate unless it has a named, version-pinned exception under
that file's `allow-python-package-licenses:` key -- `hpfeeds@3.0.0`
(GPLv3, owner-accepted for shipping), `setuptools@78.1.1` and
`ordereddict@1.1` (undeclared, read from their own bundled MIT LICENSE
files) are the three currently recorded. A version bump drops the
exception and the gate fires again on the new version.

## Live testing is not optional

Owner, 2026-09-19: "Every piece of the security infrastructure should be
live tested every single time a change is made that affects it."

A unit test against a fake proves the code agrees with our own
assumptions. Only a live check disagrees with us, which is the whole
reason to have one: #65's packet filter passed every unit test while
matching no packets at all, and only running the real image found it.

This is enforced by CI, not by anyone remembering it. The `e2e` stage
(#78) deploys the real stack -- birdcage, an enrolled Mockingbird
container -- and exercises the real functions, on every merge request
and on `dev`. Its jobs are never `allow_failure`, never `when: manual`
and never moved to a schedule, and `lint:ci` fails if they are: the
point is that a change cannot reach `dev` without the live checks
having run. The project already refuses a merge unless the pipeline
succeeds.

`preview` and `main` carry a higher bar than `dev`, not the same one
(#91): the journeys above run again there against Postgres. Which check
sits at which hop, and why, is `docs/ci-hops.md` -- read it before
changing `.gitlab-ci.yml`, because `lint:ci` enforces that shape and
refuses an `e2e` job whose rules match neither hop's anchor.

So a change to enrolment, credentials, the ingest path, the images or
anything else in that list lands with its journey in the same merge
request -- not a follow-up issue.

Browser journeys run in Firefox, which is what the owner uses (#83).
Safari and Edge are added at the `preview` -> `main` promotion, not on
every change.
