# ADR-0014: Birdcage publishes permanent ban decisions into CrowdSec's Local API, as a machine, add-only, over the stdlib

**Status:** Accepted
**Date:** 2026-10-01
**Relates to:** #4 (CrowdSec integration), #5 (RouterOS pull lists; the
owner's 2026-09-27 blocking decisions live there), #6 (the trigger and
decision engine, later), #33 (`internal/neverblock`), #10 (epic),
ADR-0001 ("audit trail is required, not optional"; its "official Go
client libraries" sentence is amended below).
**Amends:** ADR-0001's backend decision, where it says CrowdSec is reached
through `crowdsecurity/crowdsec/pkg/apiclient` and `go-cs-bouncer`. Those
modules are not approved and, for what this ADR builds, not needed.

## Context

The owner decided on 2026-09-27 (recorded on #5 and #4) that automated
blocking goes through a CrowdSec blocklist rather than a RouterOS
account: blocks never expire, add-only is the lean (not final), every
add is written to `audit_log`, `internal/neverblock` is checked before
anything is published, and birdcage builds the plumbing without any
automatic trigger -- "building it does not mean using it". On 2026-10-01
the owner asked for the design and the build together, research first,
and reaffirmed that any new third-party module needs approval before it
is used.

#4 left birdcage's role open: a *bouncer* (consuming CrowdSec decisions
and enforcing them), a *signal source* (feeding CrowdSec what the canary
fleet saw), or a *blocklist publisher* (a list CrowdSec pulls). This ADR
settles the role and the trust model, and records the research that
shaped them, per `docs/security-by-design.md`.

## Research

Everything below was read from the authoritative record at the
`v1.8.1` tag of `crowdsecurity/crowdsec` (the current release,
2026-09-03) or from NVD and GitHub's advisory database, not from
secondary coverage. File paths are relative to that repository.

### How CrowdSec accepts a decision from outside

- The Local API (LAPI) has two credential classes, wired as two router
  groups in `pkg/apiserver/controllers/controller.go`. A **machine**
  (watcher) logs in at `POST /v1/watchers/login` with `machine_id` and
  `password` and receives a JWT valid for one hour
  (`pkg/apiserver/middlewares/v1/jwt.go`, `Timeout: time.Hour`). The JWT
  group holds `POST /v1/alerts`, `GET /v1/alerts`, `DELETE /v1/alerts`,
  `DELETE /v1/decisions` and the allowlist routes. A **bouncer** API key
  reaches only `GET /v1/decisions` and `GET /v1/decisions/stream`.
- There is no machine credential that can add but not delete. A machine
  that can `POST /v1/alerts` can also `DELETE /v1/decisions`. CrowdSec
  has no per-machine permission model.
- A ban is created by posting an alert that carries a decision. This is
  exactly what `cscli decisions add` does
  (`cmd/crowdsec-cli/clidecision/decisions.go`, `add`): one
  `models.Alert` with `Capacity`, `EventsCount`, `Leakspeed`, `Message`,
  `Scenario`, `ScenarioHash`, `ScenarioVersion`, `Simulated`, `Source`,
  `StartAt`/`StopAt` as RFC 3339, `Remediation: true`, `Kind: cscli`,
  and one `Decision` with `Duration`, `Scope`, `Value`, `Type`,
  `Scenario`, `Origin`. The LAPI validates against the swagger
  (`pkg/models/localapi_swagger.yaml`; required alert fields are
  `scenario, scenario_hash, scenario_version, message, events_count,
  start_at, stop_at, capacity, leakspeed, simulated, events, source`,
  required decision fields `origin, type, scope, value, duration,
  scenario`) and answers `201` with the new alert ids as an array of
  strings (`CreateAlert` in `pkg/apiserver/controllers/v1/alerts.go`,
  returning `DBClient.CreateAlert`'s `[]string`).
- **Duration has no upper bound.** `createDecisionBatch` in
  `pkg/database/alerts.go` parses it with `cstime.ParseDurationWithDays`
  and stores `until = stop_at + duration`. Nothing caps it.
- **The alert flush does not take a live decision with it.**
  `pkg/database/flush.go`'s `alertWithoutActiveDecision` predicate
  (`alert.Not(alert.HasDecisionsWith(decision.UntilGTE(now)))`) is
  applied by both the `max_age` and the `max_items` flush paths, with
  the comment "flushing must never remove an alert that still carries an
  active decision". That the guard needed a comment is a hint that the
  earlier behaviour was otherwise, so the live journey asserts the
  far-future `until` rather than trusting the code comment.
- **The LAPI skips its own allowlist when the alert carries
  decisions.** `isAllowListed` in `controllers/v1/alerts.go`: "If we
  have decisions, it comes from cscli that already checked the
  allowlist" -- it returns false without looking. The check cscli does
  is `GET /v1/allowlists/check/{ip}` (JWT group; `{"allowlisted":
  bool, "reason": string}`). A caller that posts a decision without
  making that call bypasses the operator's CrowdSec allowlist entirely.
- **Decision origin decides whether the ban leaves the operator's
  network.** `pkg/apiserver/apic.go`'s `getScenarioTrustOfAlert` labels
  an alert "manual" only when its first decision's origin is exactly
  `cscli`; anything else with an empty `scenario_hash` is "custom".
  `shouldShareAlert` then consults the console config, whose defaults
  (`pkg/csconfig/console.go`) are `share_manual_decisions: false` and
  `share_custom: true`. So a decision with an origin of birdcage's own
  choosing would, on a LAPI enrolled with CrowdSec's central API, be
  reported upstream by default; one with origin `cscli` would not.
- **No decision is deduplicated server-side.** Posting the same ban
  twice creates two decision rows.
- `cscli decisions import` reads a file or stdin only (`-i`,
  `cmd/crowdsec-cli/clidecision/import.go`); the open-source engine has
  no first-party "pull a blocklist from this URL" feature. A pull model
  would mean a cron job and a shell script on the CrowdSec host.
- LAPI TLS: `api.server.tls.{cert_file,key_file,ca_cert_path}` with
  optional client-certificate authentication for machines
  (`agents_allowed_ou`). The official image enables it with
  `USE_TLS=true`, `LAPI_CERT_FILE`, `LAPI_KEY_FILE`, `CACERT_FILE`, and
  registers a password machine from `AGENT_USERNAME`/`AGENT_PASSWORD`
  (`build/docker/docker_start.sh`, `cscli machines add ... --password
  ... -f /dev/null --force`).

### CVEs and advisories

Searched NVD (`keywordSearch=crowdsec`) and the repository's advisory
list on 2026-10-01. Everything found is server-side; none is in the
client path this ADR uses, and none is in `go-cs-bouncer` (no
advisories at all) -- which birdcage does not use anyway.

| Record | What it is | Versions | Relevance here |
| --- | --- | --- | --- |
| CVE-2026-44981 / GHSA-273h-gvwr-c3qj | LAPI decompresses gzip request bodies without a size cap; `/v1/watchers` and `/v1/watchers/login` need no auth, so a small body can exhaust memory. The advisory itself notes it is not reachable in the default configuration, where LAPI listens on localhost. GitHub records no CVSS; NVD scores it 8.2 (v4). Recorded as both, not inflated to either. | 1.7.0 -- 1.7.7, fixed 1.7.8 | An operator who exposes LAPI to birdcage over the network has made it reachable. Birdcage never sends a compressed body; the fix for the operator is to run >= 1.7.8. |
| CVE-2026-44982 / GHSA-rw47-hm26-6wr7 | AppSec drops the body of chunked / HTTP/2 requests, so WAF body rules never match. CVSS 7.2. | 1.5.0 -- 1.7.7, fixed 1.7.8 | AppSec component; not touched. |
| GHSA-rh69-4vqj-9gj8 | kubernetes-audit acquisition webhook reads an unbounded body. CVSS 6.5. | <= 1.7.8, fixed 1.8.0 | Log acquisition; not touched. |
| GHSA-g2x2-jgfg-pg7g | HTTP acquisition datasource trusts `Content-Length` and has no decompressed-body cap. CVSS 6.5. | <= 1.7.8, fixed 1.8.0 | Log acquisition; not touched. |

What they say together: every recent LAPI flaw is an unbounded read on
an unauthenticated or low-privilege input. Birdcage's own client bounds
every response body it reads (64 KiB) and every request it sends, and
the live journey pins the fixture at 1.8.1 so the e2e never runs against
a version with a known LAPI flaw.

### Prior art: secure and insecure

Known-good shapes this design copies:

- **`cscli decisions add` itself.** Same wire path, same payload shape,
  same allowlist pre-check, same `cscli` origin. If the payload birdcage
  sends is byte-for-byte the shape cscli sends, every LAPI that accepts
  cscli accepts birdcage, and every future LAPI validation change that
  breaks birdcage breaks cscli first.
- **CrowdSec's own credential handling.** `local_api_credentials.yaml`
  and bouncer configs are root-only files on disk, never environment
  variables. Matches this project's `BIRDCAGE_MAIL_PASSWORD_FILE`
  pattern (`internal/startcheck.SecretFile`).
- **mikroview's RouterOS decision** (`docs/security-by-design.md`): the
  app holds no router credential at all. The pull-list route on #5 keeps
  that property for the router. For CrowdSec it is not available
  without a cron job on the CrowdSec host (above), so the credential
  birdcage holds is instead made as narrow as CrowdSec permits and its
  one capability birdcage must not use (delete) is absent from
  birdcage's code by construction -- see the contested point below.

Known-bad shapes this design refuses:

- **LAPI on plain HTTP across a network.** The official image's default
  `LOCAL_API_URL` is `http://0.0.0.0:8080`, and the common deployment
  is exactly that, exposed on a LAN. A machine password crosses in the
  clear on every login. Birdcage refuses an `http://` LAPI URL
  outright; there is no override.
- **The machine password in an environment variable.** The official
  image's own documented `AGENT_PASSWORD` is an env var every child
  process inherits and `docker inspect` prints. Birdcage reads the
  password only from a mounted file.
- **Trusting the server's allowlist to protect the operator's own
  addresses.** It is skipped for alerts that carry decisions (above),
  and the discourse thread already cited in `internal/neverblock`'s
  package comment shows a whitelist that was wired into the wrong stage
  and never consulted. Birdcage checks its own floor first and asks the
  LAPI's allowlist second, and refuses if either says no or either
  cannot be asked.
- **IP comparison on strings** (Mattermost CVE-2026-2455, IPv4-mapped
  IPv6 literals sailing past an IPv4 range check) and **a partially
  parsed allowlist treated as "no match"** (fail2ban #2706). Both
  already guarded in `internal/neverblock`; the target birdcage sends to
  CrowdSec is the canonical `net/netip` form, never the operator's
  typed string.

### What the research changed

- The role. The issue's framing ("via the official Go client
  libraries") assumed a library and left the role open. Three JSON
  calls over `net/http` are the whole client; a module would add two
  dependency trees for no behaviour. The pull model, attractive on #5,
  does not exist first-party on the CrowdSec side.
- The origin. Birdcage's natural choice -- an origin of `birdcage`, so
  `cscli decisions list --origin birdcage` would find its rows -- would
  have shipped every blocked honeypot visitor to CrowdSec's central API
  by default on any enrolled LAPI. Origin is `cscli`; birdcage's
  identity is the machine the alert is recorded against and the
  `birdcage: ` prefix on the scenario.
- The allowlist call. Not in the first sketch; added once it was clear
  the LAPI does not make it for us.
- The idempotence check. CrowdSec keeps duplicates, so birdcage asks
  before it adds.

## Decision

**1. Role: birdcage is a decision publisher into the LAPI, as a
registered machine.** Not a bouncer -- birdcage enforces nothing and
holds no router credential, so there is nothing for it to consume a
decision *for*. Not a raw signal source -- feeding every canary hit to
CrowdSec as an alert would be #6's decision engine running inside
CrowdSec's, and the owner has not scoped #6. Not a pulled blocklist --
CrowdSec cannot pull one without a script on its own host, and the
owner's words on #5 were "give access to crowdsec's blocklist". What
birdcage does is the one thing a human does with `cscli decisions
add`: post one permanent ban, on request, and record that it did.

**2. One operator door, no automatic trigger.** `birdcage crowdsec add
<ip> --reason "<why>"`, run on the birdcage host, is the only caller
today. There is no dashboard route (the API stays read-only until #8's
login lands, as #124 settled) and no scheduler. The Go entry point
`internal/crowdsec.Blocker.Block` is what #6 will call when there is
something to call it with.

**3. Add-only, by construction, in birdcage.** The client type has no
delete method, the CLI has no delete verb, and no HTTP route reaches
either. Removal is a human action with `cscli` on the CrowdSec host,
outside birdcage, which is the owner's stated reason for the lean: an
attacker who takes over birdcage's functionality cannot unblock
themselves through it.

*Contested, recorded, not resolved here:* the machine credential
birdcage holds is not add-only on the CrowdSec side; CrowdSec has no
such credential. An attacker who steals the password file (not merely
birdcage's functionality) can delete decisions with it. Two mitigations
are available to the operator and documented in
`docs/configuration.md`: put the LAPI behind a reverse proxy that
allows birdcage's address only `POST /v1/watchers/login`,
`POST /v1/alerts`, `GET /v1/alerts` and `GET /v1/allowlists/check/`;
and give birdcage its own machine (never the LAPI's local one), so the
credential can be revoked alone. The alternative that would make
add-only a CrowdSec property -- birdcage publishes a list, a cron job on
the CrowdSec host imports it, birdcage holds at most a read-only bouncer
key to confirm -- is a different owner decision from the one on #5 and
is left for the owner; if taken, it replaces `internal/crowdsec`'s
client and keeps the floor check, audit rows and CLI as they are.

**4. Never expires, as far as CrowdSec can express it.** CrowdSec
requires a duration; birdcage sends `876000h` (one hundred years).
That is not infinity, and the ADR says so rather than pretending: the
decision carries an `until` timestamp in 2126. Verified above: no cap
on duration, and the flush never removes an alert with a live decision.

**5. The payload is `cscli decisions add`'s.** Origin `cscli` (so the
LAPI treats it as a manual decision, and does not share it with
CrowdSec's central API unless the operator has turned
`share_manual_decisions` on), type `ban`, scope `ip`, scenario
`birdcage: <reason>`, message the same, `Remediation: true`, `Kind:
cscli`, zero events, `simulated: false`. Bare IPv4 or IPv6 addresses
only; CIDR ranges are refused (a range is a different blast radius and a
different decision, see out of scope).

**6. Order of checks, every one fail-closed.** For `Block(target)`:
parse the target as a bare address with `net/netip` (refuse anything
else, including a range); `neverblock.Floor.Check` (writes its own
refusal row); log in; `GET /v1/allowlists/check/{ip}` -- refuse if
allowlisted, refuse if the call fails; `GET /v1/alerts?ip=...&
has_active_decision=true&decision_type=ban` -- if a live `cscli`-origin
ban whose scenario starts `birdcage: ` already covers the address,
stop, record `crowdsec.block_exists`, and succeed without posting;
`POST /v1/alerts`; record `crowdsec.block_added` with the LAPI's alert
id and the `until`. Any failure after the floor check is recorded as
`crowdsec.block_failed` with the stage that failed and a scrubbed
reason. A failed audit write after a successful post is reported as an
error naming both facts; it never turns a landed block into a reported
failure silently, and it never suppresses the error.

**7. Trust model.**

| Who | Authenticates to | With | Stored where |
| --- | --- | --- | --- |
| birdcage | the LAPI | `machine_id` + password, exchanged for a one-hour JWT per command run; the JWT lives in memory for the length of one `Block` call and is never written anywhere | `BIRDCAGE_CROWDSEC_MACHINE_ID` (not secret) and `BIRDCAGE_CROWDSEC_PASSWORD_FILE`, a mounted file read with `startcheck.SecretFile`; there is deliberately no `_PASSWORD` env-var form |
| the LAPI | birdcage | its TLS server certificate, verified against the system roots or `BIRDCAGE_CROWDSEC_CA_FILE` (a PEM bundle, for the private CA most self-hosted LAPIs use) | the CA file is a mounted read-only file |

`BIRDCAGE_CROWDSEC_LAPI_URL` must be `https://`; `http://` is refused,
as is a URL carrying userinfo, a query or a fragment. TLS 1.2 minimum,
HTTP/1.1 only (as `internal/agent/enrol/transport.go` already does),
10-second dial, handshake, header and per-call timeouts, response bodies
bounded at 64 KiB. The configuration is all-or-nothing like the
approval mailbox: any of the three required variables set without the
others refuses at startup and at the CLI, naming the missing one.
Nothing set means CrowdSec is off, logged as such once at startup.

Neither the password, the JWT, nor the raw body of any LAPI response is
ever logged, printed or written to `audit_log`. Audit reasons carry
the HTTP status and the LAPI's `message` field only, bounded and with
control characters stripped.

**8. Audit actions.** `crowdsec.block_added`, `crowdsec.block_exists`,
`crowdsec.block_refused` (the CrowdSec allowlist said no),
`crowdsec.block_failed`, plus `neverblock`'s own `refused: never-block
floor`. Target is the canonical address; `triggered_by` names the
caller (`cli`), as #6 will name itself later.

**9. No new module, no new table.** The client is `net/http`,
`crypto/tls`, `encoding/json` and `net/netip`. The audit row is the
record of what birdcage pushed; the LAPI is the record of what is
blocked, and birdcage asks it rather than keeping a second copy that
could disagree.

**10. Minimum LAPI version 1.6.8**, where the allowlist routes arrived;
on an older LAPI the allowlist check 404s and birdcage refuses to post.
Operators are told to run >= 1.8.0 (every advisory above fixed).

**11. Live journey.** `scripts/e2e/crowdsec-stack.sh` runs the official
`crowdsecurity/crowdsec` image pinned by digest (1.8.1,
`sha256:0f2523fa61ef507f15d953045cface490cc880670c62f2755ced17524107f71a`,
MIT) LAPI-only, over TLS from a throwaway CA, with a password machine
registered for birdcage. `scripts/e2e/crowdsec.sh` proves: a real add
lands as a `ban` on the real LAPI with `until` at least 99 years out
and the audit row written; the same add again creates no second
decision; a floor address is refused with its audit row and no
decision; a wrong CA, an `http://` URL and a wrong password each fail
closed with nothing added. Jobs `e2e:crowdsec` (gate) and
`e2e:crowdsec:postgres` (higher bar), per `docs/ci-hops.md`. The
CrowdSec image is a CI-only fixture, never shipped and never linked;
it is listed for the owner in `AGENTS.md` under CI-only tools.

## Failure modes

| Failure | Behaviour |
| --- | --- |
| Config half-set, `http://`, userinfo in URL, unreadable or empty password file, CA file that holds no certificate | Refused at startup (server) and at the CLI, naming the variable. Nothing is contacted. |
| Target is not a bare address (hostname, CIDR, garbage) | Refused before the floor check; no audit row, nothing contacted. |
| Target on the never-block floor | Refused; `refused: never-block floor` row written by `neverblock`; nothing contacted. |
| LAPI unreachable, TLS verification fails, timeout | `crowdsec.block_failed`; non-zero exit; no retry (a retry loop is #6's concern, with its own backoff). |
| Login `401` | `crowdsec.block_failed` ("LAPI refused the machine credential"); the password is not in the message. |
| Allowlist check: allowlisted / error / `404` (LAPI too old) | `crowdsec.block_refused` with CrowdSec's reason / `crowdsec.block_failed`; nothing posted. |
| Existing live birdcage ban | `crowdsec.block_exists`; exit 0; nothing posted. |
| `POST /v1/alerts` non-201 | `crowdsec.block_failed` with status and LAPI `message`. |
| `201` without an id in the body | `crowdsec.block_added` with "alert id not returned" -- the decision exists; the record says what is known. |
| Audit write fails after a `201` | Error returned naming both; exit non-zero. |

## Out of scope

- Consuming decisions (the bouncer role) and showing CrowdSec's view on
  the dashboard. Worth doing for #6's "combined picture"; a read-only
  bouncer key is the right credential for it, and it is a separate
  decision.
- Deleting, shortening or re-adding after a human deleted. Add-only.
- CIDR ranges, and scopes other than `ip`.
- Any automatic caller. #6.
- TLS client-certificate authentication to the LAPI (birdcage has a CA
  that could issue one). It would remove the password but hands the
  LAPI a whole CA to trust, and a machine authenticated that way still
  has every machine right; no gain on the contested point.
- The RouterOS pull list and its allow list. #5.
- Retries, queues and reconciliation. A one-shot CLI reports its
  failure to the operator who ran it.

## Consequences

- ADR-0001's "official Go client libraries" sentence no longer
  describes the plan; this ADR amends it. `docs/architecture.md`'s
  CrowdSec row changes with it.
- A new mounted secret (`BIRDCAGE_CROWDSEC_PASSWORD_FILE`) joins the
  mail password in `docs/configuration.md` and `SECURITY.md`.
- The operator must register a machine for birdcage on the CrowdSec
  host (`cscli machines add birdcage --password ... -f /dev/null`) and
  put the LAPI behind TLS. Both steps are in `docs/configuration.md`.
- The contested point in decision 3 stays on #4 for the owner, with the
  pull alternative spelled out, and is not quietly resolved here.
- #6, when it arrives, calls `internal/crowdsec.Blocker.Block` with its
  own `triggered_by`; nothing in this ADR needs reopening for that.
