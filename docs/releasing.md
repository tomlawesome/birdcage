# Releasing birdcage

Issue #90. Two images are published — `ghcr.io/tomlawesome/birdcage`, the
server, and `ghcr.io/tomlawesome/mockingbird`, the canary. Both are
published **by digest**: the digest is the identity, and a tag is only a
readable label pointing at one.

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
| `release:push` | pushes the anchor tag `sha-<commit>`, then pulls the digest back and refuses unless it is the image that was tested | a registry credential |
| `release:attest` | mints the validation evidence over that digest | the signing key, and nothing else |
| `release:preview` | verifies the evidence, then gives the digest the `preview` name | a registry credential |
| `release:promote` | the manual button; verifies again, then moves the tested digest to `v<version>` | a registry credential |

An attacker who takes the signing runner gets a key but no push path. One
who takes the publishing credential gets a push path but cannot mint
evidence the verifier accepts. Neither alone is a release.

## The version

`VERSION` at the repository root holds it — one line, e.g. `0.1.0-beta` —
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

### Pre-release suffixes

`-beta` and its successors are editorial. No automation adds, advances or
removes one, because nothing in the pipeline knows whether a claim about
maturity is true.

- Successors are dot-separated, so semver orders them correctly: `-beta`,
  then `-beta.2`, then `-rc.1` if wanted, then the bare version. Never
  `-beta2`.
- A version whose cut failed after anything carried its name is burnt.
  Take the next suffix rather than reusing it — `promote-release.sh`
  refuses to repoint an existing version tag anyway, so reuse fails
  closed; this is just saying do not fight it.
- `0.1.0-beta` is a double hedge, deliberately: `0.x` says the interfaces
  may move, `-beta` says this particular cut is a trial. The commit that
  drops the suffix is the statement that the second is no longer meant.

## The `latest` tag

Published, and moved on every release — pre-release or not. Whether a beta
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
when that is wired to GHCR (#69). A canary has to match the server that
issued it, so it names a version rather than a moving tag.

## Cutting a release

1. `dev` -> `preview` by merge request, as usual. The merge's push pipeline
   runs the full gate, then the four release jobs: both images are pushed
   under `sha-<commit>`, attested, and given the `preview` tag.
2. Do the production-like manual test on `preview`. That test is the point
   of the hop, not a formality.
3. `preview` -> `main` by merge request.
4. **Press the button.** On `main`'s pipeline, play the manual
   `release:promote` job. That press is what authorises the release.

   It refuses unless the commit has an anchor from a validated build, the
   evidence still verifies, the birdcage image reports the right stamp, and
   the registry does not already carry this version. Then it moves the
   tested digest onto the version tag, and `release:gitlab` creates the
   annotated tag and the release note from `VERSION`.

   The tag is an output, not an input — you do not type a version
   anywhere, and there is no local checkout to get wrong.
5. **Countersign, on GitHub.** Run the "Countersign a released digest"
   workflow once, giving both digests and the commit. It verifies the
   key-based evidence for each image and signs keyless only if that passes.

Two buttons for a complete release: one on GitLab, one on GitHub. The
second cannot be folded into the first without giving away what it is
for — a second signer that fires from the same trigger as the first stops
nothing.
6. Back-merge after each promotion, or the next one reports `BEHIND`.

Evidence expires after seven days, so step 1 to step 4 has to happen inside
a week. If it does not, merge to `preview` again and start from a fresh
build — that is the rule working, not a nuisance to route around.

## Verifying a published image

The public half of the signing key is committed as `cosign.pub`. Anyone can
check a release:

```sh
scripts/ensure-cosign.sh ~/.local/bin
cosign verify-attestation \
  --key cosign.pub \
  --type https://tomlawson.io/attestations/birdcage-validation/v1 \
  --insecure-ignore-tlog=true \
  ghcr.io/tomlawesome/birdcage@sha256:<digest>
```

And the keyless countersignature, which is in the public transparency log:

```sh
cosign verify \
  --certificate-identity-regexp '^https://github.com/tomlawesome/birdcage/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/tomlawesome/birdcage@sha256:<digest>
```

A consumer should require **both**. One signature is a runner host; two are
two independent compromises on two hosts.

## What the evidence does not say

The evidence binds a digest to a commit and to the policy version that
judged it. Read plainly, "this digest passed the full bar" is true of the
image checks — `build:images` builds both images once and `test:image:*`
tests those exact bytes — and, since #98, true of the live journeys too:
the `e2e:*` jobs that call `scripts/e2e/stack.sh` point it at the same
tags via `E2E_BIRDCAGE_IMAGE`/`E2E_MOCKINGBIRD_IMAGE`, and `stack.sh`
refuses rather than quietly building a substitute if either override
names an image that is not there.

The one job this does not cover is `e2e:postgres-requires-tls`: it builds
its own single image directly, without `stack.sh`, to watch a start-up
refusal fire before any stack exists to point images at. It proves a
different thing than the other journeys — a check, not a running
deployment — so it is not part of the claim this section makes.

## Setup the owner does once

Nothing below can be done by an assistant: GitLab CI/CD variables are
refused by the safety hook, and the `gh` credential here gets 403 on GitHub
repository secrets.

### 1. The two CI/CD variables

Settings > CI/CD > Variables, both **protected** (so they are reachable
only from protected branches and tags — `preview`, `main`, `v*`):

| variable | masked? | value |
| --- | --- | --- |
| `GHCR_TOKEN` | masked | a GitHub fine-grained PAT, **`write:packages` only**, scoped to `tomlawesome/birdcage` alone. No `repo`, no `delete:packages`. |
| `GHCR_USER` | not masked | the literal login `tomlawesome`. Masking it only makes the logs unreadable; it is not a secret. |

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

### 4. Link the GHCR packages to the repository

**Verify this rather than assuming it.** The images are pushed from GitLab
with `GHCR_TOKEN`, not by Actions. A package pushed that way is not
necessarily linked to the repository, and if it is not, the countersigning
workflow's built-in `GITHUB_TOKEN` has no write access to it — and cosign
needs that write to store the signature beside the image.

Prove it on a throwaway tag before the first real release: push something
to `ghcr.io/tomlawesome/birdcage:scratch`, check the package page lists
this repository, and run the countersigning workflow against that digest.
Then delete the tag.

## What has not been run yet

The whole path above has never executed. The scripts have unit tests — 100
or so across `scripts/*.test.sh`, every refusal ground covered — but every
one of them stubs the registry, so no call has ever been made to a real
GHCR. In particular, the functions that resolve a tag to a digest have
never seen a registry's actual output.

Two things in particular to watch on the first cut:

- Whether `release-cli`, acting with `CI_JOB_TOKEN`, can create a
  protected `v*` tag on this CE instance. If it cannot, the fallback is
  the tag-push flow this replaced — you push the annotated tag by hand and
  the rest is unchanged.
- What `release:gitlab` does on a `main` pipeline where nobody presses the
  button. It should end up skipped once the pipeline finishes, since the
  job it needs was never played. If it instead sits pending and holds the
  pipeline open, give it its own `when: manual` and press both.

Per AGENTS.md, a release path that has never run is not a release path. The
first `preview` merge after the setup above is the run that proves it, and
until then this document describes an intention.
