# Releasing birdcage

Issue #90, note 22233; extended to four images by #125, to five by #126,
and to six by #132. Six images are published and promoted in this
project's own GitLab container registry —
`$CI_REGISTRY_IMAGE/birdcage`, the server;
`.../mockingbird`, the agent; `.../opencanary`, the honeypot itself, its
own container since #132; `.../nightjar`, the scanner; `.../smb-lure`;
and `.../holder`, the do-nothing container that owns the network address
every one of them shares. The validation evidence is bound to the digest
there, and that is where `release:push`/`release:promote` publish and
promote it. GHCR is a public mirror of the same digest, pushed after
GitLab publication succeeds and verified byte-for-byte before it is
trusted: `ghcr.io/tomlawesome/birdcage`, `.../mockingbird`,
`.../opencanary`, `.../nightjar`, `.../smb-lure` and `.../holder` are
where users are told to pull from, and where the GitHub countersignature
(step 5 below) is added. Nothing in validation or promotion reads from
GHCR; if the mirror push fails, the GitLab release stands and the mirror
is retried on its own. All six images are published **by digest**: the
digest is the identity, and a tag is only a readable label pointing at
one.

The shape in one sentence: build the images once, judge those exact bytes,
sign the digest on a runner that holds the key and does nothing else,
verify that signature before any name is put on the digest, and promote the
tested digest rather than rebuilding it.

## Why it is split into four jobs

The house rule is that **no job both judges an artefact and ships it**, and
**exactly one job may sign**. `.gitlab-ci.yml`'s `release` stage is that
rule as four jobs, and `scripts/ci-release-guard.py` fails the pipeline if
the split is ever quietly undone:

| job | what it does | what it holds |
| --- | --- | --- |
| `release:push` | pushes the anchor tag `sha-<commit>`, then pulls the digest back and refuses unless it is the image that was tested | the CI job token |
| `release:attest` | mints the validation evidence over that digest | the signing key, and nothing else |
| `release:preview` | verifies the evidence, then gives the digest the `preview` name | the CI job token |
| `release:promote` | the manual button; verifies again, then moves the tested digest to `v<version>` | the CI job token |

An attacker who takes the signing runner gets a key but no push path. One
who takes the publishing credential gets a push path but cannot mint
evidence the verifier accepts. Neither alone is a release.

The job token is scoped to this project by GitLab itself, needs no CI/CD
variable and no owner setup — unlike the credential the countersigning
workflow needs on the other host (setup step 1 below).

The registry's own cleanup policy (#112) removes only tags matching
`ci-.*` — the `build:images` transport tags — on a daily sweep. The
`sha-<commit>` anchor, `preview`, `latest` and every version tag this stage
creates are never candidates; a release tag is never swept.

## Mirroring to GHCR

Two more jobs, `release:mirror-preview` and `release:mirror-release`, run
after `release:preview` and `release:promote` respectively. Each resolves
the digest the tag GitLab just published now points at, copies it to the
matching tag on `ghcr.io/tomlawesome/<name>` with
`docker buildx imagetools create` (a registry-to-registry manifest-and-blob
copy — no rebuild, no local image ever tagged with a name a caller might
push by hand), then re-resolves the GHCR tag and refuses if it does not
match. `scripts/mirror-image.sh` is the shared implementation; its tests
are `scripts/mirror-image.test.sh`.

The cosign attestation `release:attest` minted is not part of the image
manifest. cosign v3 stores it as a Sigstore bundle attached to the digest
as an OCI referrer, listed under the fallback tag `sha256-<digest-hex>` (no
`.att` suffix: that was cosign v2's layout, #162). Both mirror jobs copy that
tag too, using the same script, right after the image tag. Without it the
countersigning workflow would find an image on GHCR with no evidence beside
it to verify.

That tag is a single index listing every referrer of the digest. The GitHub
countersign adds its own bundle to GHCR's copy, so mirroring the same digest
again after the countersign would overwrite GHCR's index and drop the
countersignature. The order below (promote, then countersign) never does
that; re-running a mirror job after a countersign would.

Neither mirror job judges anything: the digest was already named by
`release:preview` or `release:promote`, which already verified the
evidence, so mirroring never calls `scripts/verify-validation-evidence.sh`
and cannot become a second job judging the same evidence. That is why the
release guard's "no job both judges and ships" rule does not apply to
them — there is no judging in either job to collide with the copying.

The mirror jobs hold `GHCR_TOKEN`/`GHCR_USER` (setup step 1 below), scoped
to that push alone; no other release job touches GHCR at all. Neither is
`allow_failure` or manual: a failed mirror turns the pipeline red so it
gets noticed and retried, but it cannot undo or block the GitLab publish
that already happened — `release:push`, `release:attest` and
`release:preview`/`release:promote` keep whatever result they already
reached regardless of what a mirror job does afterwards.

## Allowed tags

Owner, 2026-09-25 (#90). The release path puts these names on a digest,
and no others:

- `vX.Y.Z`, digits only -- the version tag; never moves.
- `preview`, `latest` -- channel names; they move, and are the only names
  `publish-channel.sh` will move.
- `sha-<40 lowercase hex>` -- the per-commit anchor.
- `ci-<pipeline id>` -- `build:images` transport tags; GitLab registry only, never
  mirrored to GHCR.
- `sha256-<hex>` -- cosign v3's referrers fallback tag, holding the
  attestation bundle; named by cosign; only `scripts/mirror-image.sh` may
  copy it.

Anything else is refused, exit non-zero, before a registry is touched.
The list lives in `scripts/image-tag-policy.sh`; `publish-image.sh`,
`publish-channel.sh`, `promote-release.sh` and `mirror-image.sh` each call
it.

## The version

`VERSION` at the repository root holds it — one line, e.g. `0.1.0` —
and `scripts/release-version.sh` is the only thing that reads it or builds
a stamp from it. Images are stamped `<version>+<first 8 of commit>`, so
every build says which commit it came from and two preview builds of one
version are still told apart by what the binary reports.

The version cannot come from the git tag, and this is worth being clear
about because it looks like it should. The version has to be inside the
bytes, which are built on `preview`; the tag is created afterwards, at
promotion, and promotion moves that exact digest rather than rebuilding it.
So the tag is checked *against* the file at promotion — `release:promote`
refuses a tag that does not match `VERSION` — rather than being its source.

Bumping the version is therefore an ordinary reviewed commit.

A forgotten bump fails early rather than at the cut: `release:push`
refuses, before publishing anything, if the registry already carries
`v<version>`. So the first `preview` merge after a release fails until
`VERSION` moves. That is the discipline working — a preview build stamped
with a version that has already shipped is claiming candidacy for a
release that has closed.

### No pre-release suffixes

Owner, 2026-09-25: versions are plain `MAJOR.MINOR.PATCH` -- no `-beta`,
no `-rc`. The pre-release stage is the `preview` branch and its `preview`
image tag; a version name does not repeat that claim. `0.x` already says
the interfaces may still move. `scripts/release-version.sh` refuses a
suffix, or a leading `v`, in `VERSION`.

A version whose cut failed after anything carried its name is burnt. Take
the next patch version rather than reusing it -- `promote-release.sh`
refuses to repoint an existing version tag anyway, so reuse fails closed;
this is just saying do not fight it.

## The `latest` tag

Published, and moved on every release. Whether a `0.x` release
is the right thing to run is the decision of whoever pulls it, not this
project's.

What the release path is responsible for is narrower: `latest` cannot
point at an unapproved build. It is moved by `release:promote` through
`scripts/publish-channel.sh` — the same code that creates the `preview`
tag — which re-verifies the validation evidence before it moves any name
at all. Nobody moves it by hand. A tag that moves is not a weaker promise
when the moving is gated.

Separately, and regardless of `latest`: the `docker run` line that
`birdcage canary enrol` prints should pin the server's own stamped version
when that is wired to the release registry (#69). A canary has to match the
server that issued it, so it names a version rather than a moving tag.

## Cutting a release

1. `dev` -> `preview` by merge request, as usual. The merge's push pipeline
   runs the full gate, then the release jobs: the six published images are pushed under
   `sha-<commit>`, attested, given the `preview` tag on GitLab, and mirrored
   to the `preview` tag on GHCR.
2. Do the production-like manual test on `preview`. That test is the point
   of the hop, not a formality.
3. `preview` -> `main` by merge request.
4. **Press the button.** On `main`'s pipeline, play the manual
   `release:promote` job. That press is what authorises the release.

   It refuses unless the commit has an anchor from a validated build, the
   evidence still verifies, the birdcage image reports the right stamp, and
   the registry does not already carry this version. Then it moves the
   tested digest onto the version tag, mirrors that tag to GHCR, and
   `release:gitlab` creates the annotated tag and the release note from
   `VERSION`.

   The tag is an output, not an input — you do not type a version
   anywhere, and there is no local checkout to get wrong.
5. **Countersign, on GitHub.** Run the "Countersign a released digest"
   workflow once, giving all six digests and the commit. It verifies the
   key-based evidence for each image against the GHCR mirror and signs
   keyless only if that passes. The run then waits in the `countersign`
   GitHub Environment until you approve it on the run page ("Review
   deployments"); nothing is signed before that click. Only the owner can
   start it and only the owner can approve it: no GitHub credential on the
   shared runner host has Actions write, and the Environment's required
   reviewer is you (#169; setup steps 5 to 7).

Two buttons for a complete release: one on GitLab, one on GitHub. The
second cannot be folded into the first without giving away what it is
for — a second signer that fires from the same trigger as the first stops
nothing.
6. Back-merge after each promotion, or the next one reports `BEHIND`.

Evidence expires after seven days, so step 1 to step 4 has to happen inside
a week. If it does not, merge to `preview` again and start from a fresh
build — that is the rule working, not a nuisance to route around.

## Verifying a published image

GHCR is the public mirror, and this is what a user actually pulls, so
verification is against it — no credential needed, the same as any public
GHCR package. The public half of the signing key is committed as
`cosign.pub`. Anyone can check a release; the commands below use `birdcage`
as the example, and are identical for `mockingbird`, `opencanary`,
`nightjar`, `smb-lure` and `holder` with the repository name swapped:

```sh
scripts/ensure-cosign.sh ~/.local/bin
cosign verify-attestation \
  --key cosign.pub \
  --type https://github.com/tomlawesome/birdcage/attestations/birdcage-validation/v1 \
  --insecure-ignore-tlog=true \
  ghcr.io/tomlawesome/birdcage@sha256:<digest>
```

Evidence made before the predicate type changed verifies through `scripts/verify-validation-evidence.sh`, which also accepts the earlier type.

And the keyless countersignature, which is in the public transparency log:

```sh
cosign verify \
  --certificate-identity https://github.com/tomlawesome/birdcage/.github/workflows/countersign.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-trigger workflow_dispatch \
  ghcr.io/tomlawesome/birdcage@sha256:<digest>
```

The identity is exact: that one workflow file, run from `main`, started
by hand (`workflow_dispatch`), and the GitHub Actions issuer. The trigger
pin matters: a `countersign.yml` pushed to `main` with an `on: push`
trigger and no `environment:` would carry the same identity, and only the
trigger tells its signature apart. Never loosen it to an identity regular expression
over the repository: that accepts a signature from any workflow on any
ref, which is exactly what a rogue branch pushed to the mirror would
produce (#169). `scripts/verify-identity-pin.test.sh` fails if any verify
command in the docs, scripts or CI config stops being pinned.

A consumer should require **both**. One signature is a runner host; two are
two independent compromises on two hosts. Both checks are against the GHCR
mirror; the digest is identical to the one GitLab published and promoted —
`release:mirror-preview`/`release:mirror-release` refuse rather than let it
drift (Mirroring to GHCR, above).

## What the evidence does not say

The evidence binds a digest to a commit and to the policy version that
judged it. Read plainly, "this digest passed the full bar" is true of the
image checks — `build:images` builds every shipped image once and `test:image:*`
tests those exact bytes — and, since #98, true of the live journeys too:
the `e2e:*` jobs that call `scripts/e2e/stack.sh` point it at the same
tags via `E2E_BIRDCAGE_IMAGE`/`E2E_MOCKINGBIRD_IMAGE`/`E2E_NIGHTJAR_IMAGE`/
`E2E_SMB_LURE_IMAGE`/`E2E_HOLDER_IMAGE`, and `stack.sh` (or, for the
lure and the holder, `smb-lure-stack.sh`) refuses rather than quietly
building a substitute if an override names an image that is not there.

The one job this does not cover is `e2e:postgres-requires-tls`: it builds
its own single image directly, without `stack.sh`, to watch a start-up
refusal fire before any stack exists to point images at. It proves a
different thing than the other journeys — a check, not a running
deployment — so it is not part of the claim this section makes.

## Setup the owner does once

Nothing below can be done by an assistant: GitLab CI/CD variables are
refused by the safety hook, and the `gh` credential here gets 403 on GitHub
repository secrets.

### 1. The two CI/CD variables, for the GHCR mirror

`release:push`, `release:preview` and `release:promote` need no owner-set
variable: they authenticate with the CI job token GitLab already gives
every job (`CI_REGISTRY_USER`/`CI_REGISTRY_PASSWORD`), scoped to this
project alone. Only the two mirror jobs need anything from you. Settings >
CI/CD > Variables, both **protected** (so they are reachable only from
protected branches and tags — `preview`, `main`, `v*`):

| variable | masked? | value |
| --- | --- | --- |
| `GHCR_TOKEN` | masked | a GitHub **classic** PAT, **`write:packages` only** (it adds `read:packages` itself). No `repo`, no `delete:packages`. Classic, because GitHub Packages accepts no fine-grained token ([GitHub Docs](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)); a classic token cannot be scoped to one repository, which is why it gets nothing but `write:packages`. |
| `GHCR_USER` | not masked | the literal login `tomlawesome`. Masking it only makes the logs unreadable; it is not a secret. |

The countersigning workflow, on GitHub, needs nothing new: it reads and
signs the GHCR mirror with the built-in `GITHUB_TOKEN`, the same as before
GHCR was briefly dropped (note 22222) and restored (note 22233).

Never give a GitHub credential on the runner host **Actions** write: the
agents' `gh` token, `GHCR_TOKEN`, and anything else stored on that host or
reachable from a CI job (this GitLab is CE, so every protected variable is
readable by every protected-branch job). The countersignature is worth
something only because forging a release needs both that host and the
owner's GitHub account; a host credential that can start the workflow
makes it one compromise (#169). The mirror's SSH key is not a token and
has no Actions setting; what it may do is setup steps 6 and 7.

The check is `scripts/check-no-actions-write.sh`. It dispatches
`countersign.yml` against a fresh random ref it has first proved absent,
so it never starts a run: exit 0 "no Actions write" (HTTP 403/404), exit 1
when the credential can dispatch (422) or a run may have started (2xx),
exit 2 when inconclusive, which is never a pass. The credential goes in
the environment, never an argument:

```sh
GITHUB_REPOSITORY=tomlawesome/birdcage GH_TOKEN="$(cat /path/to/token-file)" \
  scripts/check-no-actions-write.sh
```

No credential on the runner host, or readable by a CI job, may hold
**Deployments write** either, for the same reason as Actions write: a token
with Deployments write can approve the run waiting in the `countersign`
Environment through the API, so no human is involved. Never grant either
permission to such a credential.

`scripts/check-no-actions-write.sh` does not test Deployments write.
Probing it would mean creating or approving a real deployment, which is a
side effect this check must never have, so Deployments write stays a rule
you keep when making a token, not something the script proves.

No token on the owner's account (classic or fine-grained) may hold
**contents** write or **workflows** write, and such a token must never be stored on
the runner host or in GitLab: such a token acts as you, so it passes the
`main` ruleset's admin bypass (setup step 7) and can change
`countersign.yml` on GitHub without you.

Run it after **any** change to a GitHub credential or its token scopes, for
each credential above, and record the result on the issue for that change.
For `GHCR_TOKEN`, run it from a pipeline where the token is the masked
variable; do not copy it out.

### 2. The cosign key, on the runner host and never in GitLab

This GitLab is CE, which has no protected environments and no
environment-scoped variables, so a protected CI/CD variable is readable by
**every** job in a protected-branch pipeline. That is why the key is not
one. It lives as files on the runner host, mounted read-only into the one
signing job.

Generate the pair somewhere private, with a password:

```sh
cosign generate-key-pair
```

Commit `cosign.pub` — the public half — at the repository root. It is not a
secret and verification needs it. The private key and the password never
enter the repository or chat.

On the runner host, as root, place the key where the signing runner will
mount it, owned by the runner's user:

```sh
install -d -m 0700 -o gitlab-runner -g gitlab-runner /etc/birdcage-signing
install -m 0600 -o gitlab-runner -g gitlab-runner /path/to/cosign.key /etc/birdcage-signing/cosign.key
( umask 077 && IFS= read -r -s -p 'key password: ' p && \
  printf '%s' "$p" > /etc/birdcage-signing/password ); echo
chown gitlab-runner:gitlab-runner /etc/birdcage-signing/password
```

`read -s` keeps the password off the command line and out of shell history.

The runner's Docker is rootless and run by `gitlab-runner`, so root inside
the job container is that user on the host: root-owned `0600` files would
read as `nobody` and be unreadable. Rootless Docker also snapshots `/etc`
when its daemon starts, so a directory created under `/etc` afterwards is
invisible to it — the job sees an empty mount and fails with "no password
file" although the file is plainly there. After creating the directory,
restart that user's Docker once (this kills any job running on the host):

```sh
sudo -u gitlab-runner XDG_RUNTIME_DIR=/run/user/$(id -u gitlab-runner) \
  DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u gitlab-runner)/bus \
  systemctl --user restart docker
```

Later reboots need nothing: the directory exists before Docker starts.
(Both traps were found the hard way on orbit, 2026-09-09.)

### 3. A second runner, tagged `birdcage-signing`

Register a second project runner on that host, docker executor, tag
`birdcage-signing`, **protected** (so it refuses jobs from unprotected
refs), **locked to this project**, "run untagged jobs" off. In its
`config.toml` entry, add the mount and the rootless socket:

```toml
[runners.docker]
  host = "unix:///run/user/988/docker.sock"
  volumes = ["/etc/birdcage-signing:/etc/birdcage-signing:ro", "/cache"]
```

Use the runner user's real uid in place of `988` if it differs. Without the
`host` line the executor looks for `/var/run/docker.sock`, which does not
exist on a rootless host.

The fence is this runner, not `.gitlab-ci.yml`: a job without the tag never
sees the key, and a job with the tag on an unprotected ref never runs.

### 4. Check the GHCR packages name the repository

Every image carries `org.opencontainers.image.source` (set once, on the
`docker build` in `build:images`), which is what links a GHCR package to
this repository; no manual linking is needed. Do check it: after the first
`release:mirror-preview`, the package page for each of
`ghcr.io/tomlawesome/birdcage`, `.../mockingbird`, `.../opencanary`,
`.../nightjar`, `.../smb-lure` and `.../holder` must name this repository.
Without that link the countersigning workflow's `GITHUB_TOKEN` cannot write
the signature beside the image.

### 5. The `countersign` GitHub Environment (the approval step)

`countersign.yml` runs its job in the Environment `countersign`
(`scripts/countersign-shape.test.sh` fails if that line goes). Until the
Environment exists with these rules, GitHub creates an empty one on the
first run and the approval step does nothing. On the GitHub repository:

1. Settings > Environments > New environment, name `countersign`
   (exactly), Configure environment.
2. Tick **Required reviewers** and add yourself. Leave "Prevent self-review"
   unticked: you are the only reviewer and the one who dispatches.
3. **Deployment branches and tags**: choose **Selected branches and tags**,
   Add deployment branch or tag rule, type Branch, pattern `main`.
4. Save protection rules. Add no environment secrets: the workflow needs
   none.

Check it: a dispatch of the workflow on `main` must stop at "Waiting for
review"; reject it there if you only wanted to see it wait.

### 6. Report what the mirror's SSH key can do

The mirror job pushes with the key in the protected GitLab variable
`GITHUB_MIRROR_SSH_KEY`. On the GitHub repository, Settings > Deploy keys:
note whether that key is listed there (and not on a user account), and
whether **Allow write access** is ticked. Write both answers on #169.

### 7. A ruleset on `main` (least privilege for the mirror key)

The mirror writes `main`, so a holder of its key could push a changed
`countersign.yml` to `main` itself, which the pinned identity would accept.
A ruleset closes that by making workflow changes on GitHub need you:

1. Settings > Rules > Rulesets > New ruleset > New branch ruleset. Name
   `main`, Enforcement status **Active**. Target branches > Add target >
   Include by pattern `main`.
2. Tick **Restrict deletions** and **Block force pushes**. Leave the
   bypass list empty. Create.
3. Settings > Rules > Rulesets > New ruleset > New push ruleset (if GitHub
   offers it for this repository). Name `workflows`, Enforcement status
   **Active**. Tick **Restrict file paths**, add `.github/**`. Bypass list:
   add **Repository admin** only, so the mirror key cannot push a change
   under `.github/` and you push one by hand after reviewing it. Create.
4. If push rulesets are not offered, say so on #169. Without one, steps 5
   and 6 do **not** protect the workflow: whoever holds the mirror key can
   push a changed `countersign.yml` to `main` (drop `environment:`, change
   what it signs), and your next dispatch runs that version with the
   pinned identity and trigger. Until it is closed, read the history of
   `.github/workflows/countersign.yml` on GitHub's `main` before every
   dispatch.

A normal mirror push of `dev`, `preview` and `main` still succeeds. A failed
`sync:mirror-to-github` job is expected whenever the commits being mirrored
change a workflow file under `.github/`: the push ruleset refuses that push
for every branch and tag, by design. Review the change, then push it to
GitHub by hand from a trusted checkout of the GitLab branch, as yourself
(an admin, so the ruleset's bypass applies), and re-run the job:

```sh
git fetch gitlab dev
git push git@github.com:tomlawesome/birdcage.git refs/remotes/gitlab/dev:refs/heads/dev
```

Swap `dev` for `preview` or `main` as needed; the re-run job then finds
GitHub up to date and passes.

### The one-person gap

The Environment's only required reviewer is you, and you are also the one
who dispatches the run: you both start and approve it. That is one person,
not the SLSA two-person rule; the approval step protects against a host
credential or a pushed workflow, not against your own account being
compromised. Adding a second approver account as a required reviewer would
close it; whether to do that is your open choice (#169).

## What has not been run yet

The whole path above has never executed. The scripts have unit tests — 100
or so across `scripts/*.test.sh`, every refusal ground covered — but every
one of them stubs the registry, so no call has ever been made to a real
registry. In particular, the functions that resolve a tag to a digest have
never seen a registry's actual output.

Four things in particular to watch on the first cut:

- Whether `release-cli`, acting with `CI_JOB_TOKEN`, can create a
  protected `v*` tag on this CE instance. If it cannot, the fallback is
  the tag-push flow this replaced — you push the annotated tag by hand and
  the rest is unchanged.
- What `release:gitlab` does on a `main` pipeline where nobody presses the
  button. It should end up skipped once the pipeline finishes, since the
  job it needs was never played. If it instead sits pending and holds the
  pipeline open, give it its own `when: manual` and press both.
- Whether the attestation reaches GHCR intact. The first real run
  (pipeline 1900) found no `.att` tag: cosign v3 had written the bundle as a
  referrer under `sha256-<digest-hex>` instead (#162). Copying that tag with
  `imagetools create --prefer-index=false`, then `cosign verify-attestation`
  against the copy, passed on a local registry; GitLab to GHCR has not yet
  run. If `cosign verify-attestation` finds nothing on the GHCR side, this
  is the first place to look.
- Setup step 4 above (each GHCR package page names the repository) is unchecked
  until the first `preview` merge actually pushes through
  `release:mirror-preview` and the countersigning workflow is run against
  it.

A release path that has never run is not a release path. The
first `preview` merge after the setup above is the run that proves it, and
until then this document describes an intention.
