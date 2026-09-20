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
gate slow. Pipeline 1330 on `dev` (commit `97fbb17b`) says they are not.
Run times, in seconds:

| lint            |     | test                  |     | e2e                        |    |
| --------------- | --- | --------------------- | --- | -------------------------- | -- |
| `lint:go`       | 168 | `test:go`             | 233 | `e2e:enrol-and-hit`        | 58 |
| `lint:licences` |  51 | `test:frontend`       | 109 | `e2e:enrol-and-hit:postgres` | 60 |
| `lint:ci`       |  19 | `test:smoke`          | 105 | `e2e:smb`                  | 53 |
| `lint:agent-deps` | 11 | `test:image:mockingbird` | 31 | `e2e:dashboard-own-ca`   | 40 |
|                 |     | `test:image:birdcage` |  15 | `e2e:snmp`                 | 34 |

All five journeys together run in 245 seconds -- less than `test:go`
alone. Dropping every one of them from the merge-request gate would not
have made that pipeline finish sooner, because they do not sit on its
critical path.

What does sit on it is lane contention and job ordering. The runner
lanes are narrow (`big` runs one job at a time, `light` about three), so
queueing, not work, is most of the wall clock: that pipeline took 788
seconds end to end to do 977 seconds of work across two lanes. And
`test:frontend` had no `needs:` key, so it waited for the whole `lint`
stage -- 168 seconds of `lint:go` -- before starting, and `test:smoke`
waits on its artifacts in turn. The longest chain in the pipeline was
therefore scheduled last.

So the answer to "which journeys should move off the merge-request
gate" is **none of them**. The saving is in ordering, and it is larger
than anything moving a journey could buy.

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
| `test:frontend` | Unit tests and the two pixel gates. Head of the longest chain, so it starts immediately. |
| `test:go` | The unit suite, against SQLite and a real Postgres. |
| `test:smoke` | The real binary driven by a browser. |
| `test:image:birdcage` | Proves the shipped image starts and answers. |
| `test:image:mockingbird` | Proves nothing in the agent image runs as root. |
| `e2e:enrol-and-hit` | Enrolment and the ingest path change often and are the product's spine. |
| `e2e:enrol-and-hit:postgres` | The same spine against the other engine birdcage ships. |
| `e2e:smb` | The OpenCanary `full_audit` parse is brittle by nature -- a fixed-index read of a third-party log line. |
| `e2e:dashboard-own-ca` | The minted-certificate default. TLS setup is easy to break and hard to notice. |
| `e2e:snmp` | Our own UDP parser, not a third party's. Parser changes are source changes. |

## Hop 2 -- entering and sitting on `preview` and `main`

The baseline gate again, plus the `higher_bar` anchor: the journeys
above re-run against Postgres, which the merge-request gate exercises
only for `enrol-and-hit`.

| check | why it is here and not at hop 1 |
| --- | --- |
| `e2e:smb:postgres` | Storage-engine differences show up in how an alert is written, not in how it is detected. Proving every journey against both engines is worth a release pipeline and not worth every branch. |
| `e2e:snmp:postgres` | As above. |
| `e2e:dashboard-own-ca:postgres` | As above. |

These cost nothing on a merge request. They run on the promotion merge
request -- so a problem is visible *before* the promotion lands -- and
again on the branch itself.

`policy:promotion-hop` also lives at this hop: it refuses a merge
request into `preview` from anything but `dev`, and into `main` from
anything but `preview`.

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
