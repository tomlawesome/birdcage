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

Everything from a `post-release:` line to the end of the file is ignored by
the check. It is filled in at the step 6 back-merge, so the repository, not
only the main merge request, carries the step 2 evidence and what the release
actually did.

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

post-release:
step 2 evidence: <what the production-like test on preview covered, and its result>
released: <the release:promote job id and the six digests>
countersigned: <the GitHub workflow run>
