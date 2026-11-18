# Release record template

One record per release, not one per promotion. Copy this file to
`docs/releases/vX.Y.Z.md` before step 1 of
[docs/releasing.md](../releasing.md), replace every `<...>`, and commit it on
a `release/vX.Y.Z` branch cut from `dev`, with
`git commit --trailer "Signed-off-by: <your name>"` (a name only, no email;
`git commit -s` would add one). The same branch renames the change log's
Unreleased section; nothing else may change on it (`policy:release-record`).
See "The release record" in the guide for the route.

What each line must say:

- `version:` the release, `v` plus the contents of `VERSION`.
- `guide-commit:` the full sha of a commit on `dev` that has the guide you
  followed: `git log -1 --format=%H -- docs/releasing.md`.
- `guide-blob:` that guide's content, `git rev-parse <guide-commit>:docs/releasing.md`.
  If the guide changes before the promotion, the check fails: re-read it and
  redo the record.
- `review:` the review issues that cover what this release ships, such as
  `#206, #213`. Each must be closed before a promotion opens.
- `step N:` one line per numbered step of "Cutting a release", in the guide's
  order, no step missing or doubled. Each says one of:
  - `done: <link or job id>`
  - `not-needed: <the owner decision that says so>`
  - `after-merge` (the step comes after this promotion)

  An empty value or a `<...>` placeholder fails the check.
- `Signed-off-by:` exactly one, a name only, the same as the author and the
  `Signed-off-by` trailer of the last commit that touches the record.

The sign-off is an attestation in the style of the Developer Certificate of
Origin: the person named says they followed the guide named above. It is not
a signature. Nothing here proves who wrote it; the check only makes the name,
the commit and the guide agree. Key-based signing is not set up.

The record is written once and not edited after its release MR merges.
What the release then did -- the step 2 evidence, the `release:promote`
job, the six digests, the countersigning run -- goes on the GitLab Release
at step 6, not here.

---

version: vX.Y.Z
guide-commit: <full sha: git log -1 --format=%H -- docs/releasing.md>
guide-blob: <git rev-parse <guide-commit>:docs/releasing.md>
review: <#issue, #issue>

step 1: after-merge
step 2: after-merge
step 3: after-merge
step 4: after-merge
step 5: after-merge
step 6: after-merge

Signed-off-by: <your name, as git config user.name>
