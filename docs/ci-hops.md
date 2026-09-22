# Which checks run at which hop

Issue #91. The delivery flow is `dev -> preview -> main`, and the CI
burden across those hops is deliberately uneven: `dev` runs a gate fast
enough that nobody wants to skip it, and `preview` carries the higher
bar that makes a revision releasable.

This file is the record of which check sits where and why. Change
`.gitlab-ci.yml` and change this with it; `scripts/ci-e2e-guard.py`
refuses a config that does not match the shape described here.

## What the measurements said

The premise worth testing was that the live journeys are what make the
gate slow. Two pipelines say they are not. Run times in seconds, 1330
on `dev` and 1334 on merge request !43:

| job | 1330 | 1334 |
| --- | --- | --- |
| `test:go` | 233 | 218 |
| `lint:go` | 168 | 206 |
| `test:smoke` | 105 | 128 |
| `test:frontend` | 109 | 121 |
| `e2e:enrol-and-hit` | 58 | 129 |
| `e2e:enrol-and-hit:postgres` | 60 | 64 |
| `e2e:smb` | 53 | 59 |
| `e2e:dashboard-own-ca` | 40 | 33 |
| `e2e:snmp` | 34 | 37 |
| **all five journeys** | **245** | **323** |
| whole pipeline, work across both lanes | ~1000 | ~1300 |

Note the spread: the same job varies by a third between two runs, and
in 1334 the five journeys together cost more than `test:go` did. Any
claim resting on a single run is worth less than it looks, which is why
two are given here.

What holds across both is the proportion. The live journeys are about a
quarter of the pipeline's total work, and they run on the `big` lane,
which nothing else uses -- so dropping them frees capacity that the long
chain on the `light` lane cannot use anyway. A quarter of the runner
budget to prove the product actually detects an intruder is
proportionate, and this is the only stage that proves it at all.

So the answer to "which journeys should move off the merge-request
gate" is **none of them**. Run times are stable enough to conclude
that much: they measure work, not waiting.

Wall clock is a different matter, and it is worth being careful here.
`test:frontend` had no `needs:` key, so it waited for the whole `lint`
stage before starting, and `test:smoke` waits on its artifacts in turn
-- the longest chain in the pipeline, scheduled last. It has been given
`needs: []`, because it consumes nothing any lint job produces and a
dependency that is not real can only cost time.

**No figure is claimed for that saving.** The first attempt to measure
one did not survive checking. Across the last fourteen pipelines, wall
clock for essentially the same gate ranged from 330 to 1620 seconds:

| pipeline | wall |
| --- | --- |
| 1297 `dev` | 330 s |
| 1302 MR !39 | 367 s |
| 1328 MR !42 | 409 s |
| 1330 `dev` | 790 s |
| 1334 MR !43 | 1620 s |

The runner is shared with every other project on this host, so a single
pipeline's wall clock mostly measures what else was running at the time.
The spread between two identical gates is larger than any ordering
change could plausibly buy, which means one pipeline cannot show the
effect of one -- 1334 above is this very change, and it was the slowest
of the fourteen because the host was busy.

So: `needs: []` on `test:frontend` is correct on its own terms, and
unquantified on purpose. Anyone wanting the real number needs many runs
compared like for like, or per-job queue time tracked over time -- not a
before-and-after pair. Do not quote a saving from one pipeline; that is
the mistake this paragraph exists to prevent.

## Hop 1 -- every merge request, and `dev`

The baseline gate, in `.gitlab-ci.yml` as the `gate` anchor. Every lint
job, every test job and every live journey. Nothing has been taken out
of it by this issue.

| check | why it is here |
| --- | --- |
| `lint:go` | Go source changes on nearly every branch. |
| `lint:licences` | A dependency can arrive on any branch; a licence found late is found after it shipped. |
| `lint:ci` | Guards this arrangement. Cheapest job in the pipeline. |
| `lint:agent-deps` | ADR-0008 decision 4 -- no server package may reach the agent image. Broken by an ordinary import. |
| `lint:scripts` | Every `scripts/*.test.sh`. Ten of them ran nowhere until #100; they test the release path, which has the least other coverage. |
| `test:frontend` | Unit tests and the two pixel gates. Head of the longest chain, so it starts immediately. |
| `test:go` | The unit suite, against SQLite and a real Postgres. |
| `test:smoke` | The real binary driven by a browser, in Firefox (#83) -- the owner's browser, so it is the bar every change has to clear. #81 widened its journeys past the hero sentence and four tiles: every section rendering with no console error, the range picker actually re-querying, a live event over the real ingest path reaching the page by SSE, the status strip including the mail item, and a killed birdcage read as a message rather than a blank page. |
| `test:image:birdcage` | Proves the shipped image starts and answers. |
| `test:image:mockingbird` | Proves nothing in the agent image runs as root. |
| `e2e:enrol-and-hit` | Enrolment and the ingest path change often and are the product's spine. |
| `e2e:enrol-and-hit:postgres` | The same spine against the other engine birdcage ships. |
| `e2e:smb` | The OpenCanary `full_audit` parse is brittle by nature -- a fixed-index read of a third-party log line. |
| `e2e:dashboard-own-ca` | The minted-certificate default. TLS setup is easy to break and hard to notice. |
| `e2e:snmp` | Our own UDP parser, not a third party's. Parser changes are source changes. |
| `e2e:portscan` | The capability and the BPF filter only prove anything against the real image -- #65's own trap was a filter that passed every unit test and matched nothing. `test:image:mockingbird` deliberately cannot cover this: it keeps `--security-opt no-new-privileges`, which is exactly what turns the feature off. |
| `e2e:postgres-requires-tls` | #84's refusal, watched fire against the real binary. Needs no Postgres server, so it is cheap enough for every merge request. |

## Hop 2 -- entering and sitting on `preview` and `main`

The baseline gate again, plus the `higher_bar` anchor: the journeys
above re-run against Postgres, which the merge-request gate exercises
only for `enrol-and-hit`.

| check | why it is here and not at hop 1 |
| --- | --- |
| `e2e:smb:postgres` | Storage-engine differences show up in how an alert is written, not in how it is detected. Proving every journey against both engines is worth a release pipeline and not worth every branch. |
| `e2e:snmp:postgres` | As above. |
| `e2e:dashboard-own-ca:postgres` | As above. |
| `test:smoke:safari` | Browser coverage widens here (#83): Safari (WebKit in Playwright) is worth a release pipeline and not worth every branch. `test:smoke` itself stays at hop 1 too -- this adds to it, nothing moved off Firefox. |
| `test:smoke:edge` | As above, Edge (Chromium with the `msedge` channel). |
| `test:smoke:postgres` | #81: the same seeded story, the same journeys, against Postgres instead of a fresh SQLite file -- the same "storage engine, not detection" reasoning as the `e2e:*:postgres` rows above. Firefox stays the bar; this widens the database, not the browser. |

Pixel-comparison decision (#83, owner, 2026-09-19): `compare:band` and
`compare:below-band` (in `test:frontend`, hop 1) stay on Chromium at
every hop. They check rendering fidelity against the round-6 design
references, which were captured in Chromium -- a drawing, not a browser
compatibility question -- so re-taking them in another engine would buy
nothing and make every future diff against the design harder to read.
The reference shots themselves are unchanged by this issue.

These cost nothing on a merge request. They run on the promotion merge
request -- so a problem is visible *before* the promotion lands -- and
again on the branch itself.

`policy:promotion-hop` also lives at this hop: it refuses a merge
request into `preview` from anything but `dev`, and into `main` from
anything but `preview`.

## Hop 3 -- publishing, on `preview` and on a `v*` tag

Added by #90. These jobs are not checks and do not belong in the table
above: they are what happens *after* the bar has been cleared. They are
recorded here because `.gitlab-ci.yml` and this file move together.

| job | when | what it is |
| --- | --- | --- |
| `build:images` | hop 1 -- every merge request and `dev` too | builds both images once, so `test:image:*` judges the bytes that later ship, and pushes each to this project's own registry (#112, below) so a later job can recover its tag if a concurrent pipeline's prune got to it first. Not a check itself; it is what makes the checks mean something. |
| `release:push` | push to `preview` | publishes the anchor `sha-<commit>` and proves the registry holds what was tested |
| `release:attest` | push to `preview` | mints the validation evidence. The only job that may sign, fenced by the `birdcage-signing` runner |
| `release:preview` | push to `preview` | verifies that evidence, then creates the `preview` tag |
| `release:promote` | `main`, manual | the single button that cuts a release: verifies again, then moves the tested digest to the version tag |
| `release:gitlab` | `main`, after the button | creates the annotated tag and the release note from `VERSION` |

`release:push` deliberately has no `needs:`, which is what makes it wait
for every job in every earlier stage. A list of jobs there would be a
second copy of the gate, free to drift from the real one.

`scripts/ci-release-guard.py` enforces the shape -- one signer, tagged, and
no job both judging and shipping -- and `lint:ci` runs it. The procedure
and the owner's one-time setup are `docs/releasing.md`.

### Handing an image from `build:images` to a later job (#112)

`build:images` builds both images once so every later job judges the same
bytes; that only works if the bytes are still there when a later job looks.
Every job on this host talks to the same Docker daemon (this runner has one
host, one daemon), which used to be read as "so an image `build:images`
built just sits in that daemon's store for the rest of the pipeline" -- true
for one pipeline at a time, false the moment two overlap. This host runs
several pipelines at once on that one shared daemon, and `build:images`'
own prune (self-healing by design: it deletes every build tag except its
own pipeline's, so whatever a cancelled pipeline left behind is cleared by
the next one) cannot tell a leftover apart from a tag a *different*,
still-running pipeline is using right now. Two pipelines running close
together can each prune the other's image, and whichever one loses the
race gets an e2e or image-test failure that has nothing to do with the
code under test -- see issue #112 for the incident that first showed this.

The fix leaves that prune exactly as it was and makes deletion harmless
instead of forbidden. `build:images` now also pushes each image to this
project's own container registry and records the resulting `repo@digest`
in `release.env`, alongside the local tag it already recorded. Every job
that consumes one of these images -- `test:image:*`, every `e2e:*` job
that uses `build:images`' output, and `release:push` -- calls
`scripts/ci-ensure-image.sh` first: it checks the local tag is still
there, and if a concurrent pipeline's prune got to it first, pulls the
recorded digest back down and retags it, logging that it did. Whoever
prunes, and whenever, the worst case is now one extra pull instead of a
failed job. (`e2e:postgres-requires-tls` is not a consumer of this kind --
it builds and immediately uses its own throwaway image under a
job-specific name, never the shared `birdcage-build`/`mockingbird-build`
tags, so it was never exposed to this race and calls nothing new.)

This registry push is transport between this pipeline's own jobs, not a
release -- it never replaces `release:push`'s publication to
`$GHCR_BIRDCAGE_REPO` / `$GHCR_MOCKINGBIRD_REPO`, which is still the only
place a consumer, or an attacker's search engine, would ever find these
images by name.

The internal registry needs its own cleanup policy -- deleting `ci-.*`
tags older than about a week is plenty, since nothing here is ever read
after its pipeline finishes. That is a project setting (Settings >
Packages and registries > Container registry, on this GitLab) that only
the project owner can set; an assistant cannot set it. Left unset, the
registry keeps every pipeline's pushed images forever: that is growth,
not breakage, since no job here ever reads an old tag, but it is disk the
project pays for indefinitely until the policy is set.

## What the guard enforces

`scripts/ci-e2e-guard.py` already refused an `e2e` stage that was
missing, empty, `allow_failure: true`, `when: manual` or ruled out of
merge requests. Issue #91 adds the shape above to what it enforces, so
the arrangement cannot decay quietly:

1. Every `e2e` job's rules are **exactly** one of the two anchors,
   `gate` or `higher_bar`. A job with hand-written rules of any other
   shape is refused rather than guessed at -- an unrecognised shape
   fails red, the same way an unreadable file does.
2. At least one `e2e` job is at hop 1, and at least one is at hop 2.
   The second half is the point: without it, `preview` carries the same
   bar as `dev` and "the higher bar" is a sentence in a document.
3. A hop-2 job cannot be the only thing proving something, because
   every hop-1 journey stays at hop 1. Nothing moved; the higher bar is
   additive.

Rule 1 is what makes this durable. "Runs later" decaying into "runs
never" needs a rule edit that the guard names, rather than a plausible
`if:` nobody reads twice.
