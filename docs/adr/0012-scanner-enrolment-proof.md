# ADR-0012: A scanner proves its enrolment by answering an ordered scan, over the same road as a honeypot's self-test

**Status:** Proposed (owner review pending)
**Date:** 2026-09-24
**Relates to:** #116 (this proof), #47 (enrolment; pending until the first
self-test passes), #46 (self-test), #45 (canary health states), #105,
#108 (Nightjar slice 1), #8 (dashboard authentication, deferred),
ADR-0005, ADR-0009, ADR-0010, ADR-0011.

## Context

`store.Provision` (`internal/store/provision.go:186`) inserts a node with
`Pending: found.Kind == agentkind.Honeypot`. A honeypot stays pending
(`canaries.registered_at` NULL) until a minted self-test run passes:
`selftestsched.Scheduler.FirstContact` mints the run on the credential's
first use, `retryPending` re-mints every ten minutes while it stays
pending, and `store.SettlePending` (`internal/store/pending.go`) is the
one place `registered_at` is ever written. A scanner has none of this: it
registers on provisioning, and "installs cleanly and never reports" looks
like a healthy quiet node until its heartbeat goes silent -- the exact
failure #47's principle exists to prevent.

Two facts about the scanner decide the shape of the answer:

- **Nightjar scans a filesystem, not a network.** It runs pinned Grype
  over a read-only bind of the host root at `/host`, after
  `internal/hostmask.Check` proves every secret-bearing path is covered
  (`cmd/nightjar/scanner.go`). It has no listener, no capability and no
  network tool; its only outbound calls are `/enrol/*`, `/ingest/scans`,
  `/ingest/heartbeat` and `/ingest/rotate`. Issue #116's candidate --
  "a bounded scan of a birdcage-named target" -- assumes a port scanner.
  Nightjar is not one, and making it one is a new capability, not a
  proof.
- **Nightjar re-scans every six hours** (`defaultScanIntervalS`,
  `cmd/nightjar/config.go:85`). Left to itself, a scanner whose first
  scan fails retries six hours later. Birdcage needs to own the retry.

Two owner decisions on the first draft (2026-09-24) widen it:

- On ordering scans after registration: *"the whole point is that the
  scanner periodically runs and reports but birdcage should be able to
  initiate a manual scan with a forced reauth event for the admin."*
  Decisions 7 and 8.
- On the proof window: *"Arbitrary time is likely just to fail, yes. A
  30 minute cap but we should establish birdcage connection first and
  then report back as the enrolment process develops, so we know where
  it likely failed."* Decision 3 and decision 9.

One fact about the dashboard decides where the second lands: it has no
login. `requireAuth` (`internal/api/api.go:136`) is a no-op placeholder,
`dashboardRoutes` is eleven GETs and the agent heartbeat, and #8 --
"OIDC/Authentik support (deferred)", milestone M3 -- is where sessions
arrive, through ADR-0005's `gauntlet` module. A forced re-authentication
needs a session to re-authenticate; there is nothing to bind it to
today.

## Research

Done before the design, per `docs/security-by-design.md`. Reproduced
means read from the authoritative record (the GitHub Advisory Database
via its API, NVD's API, or the vendor's own text); a lead is something
secondary coverage reported that could not be reproduced and is not
relied on.

Enrolment proof:

- **Grype CVE-2025-65965** (GHSA-6gxw-85q2-q646, High): registry
  credentials copied unsanitised into JSON output, `>= 0.68.0, < 0.104.1`,
  fixed 0.104.1. Reproduced. Nightjar pins 0.119.0
  (`build/nightjar/Dockerfile:36`) and configures no registry credential;
  not affected. Relevant again when #113 scans images.
- **Fleet (osquery) CVE-2026-46370** (GHSA-vxm7-9x8v-8gm4, 6.5): a sort
  oracle on a list endpoint let the lowest-privilege role reconstruct
  hosts' long-lived `node_key` and impersonate them. Reproduced. Lesson
  applied: the proof's run id never appears in any `/api` response.
- **Wazuh authd CVE-2026-34150 and CVE-2026-39359** (unauthenticated
  enrolment yields a valid agent id; path traversal via the
  agent-chosen group at enrolment). Leads only: neither is in the GitHub
  Advisory Database and NVD's page could not be fetched here. Both are
  the class #47's single-use deploy token and server-chosen identity
  already close; this ADR adds nothing an agent chooses at enrolment.
- **ACME, RFC 8555 §6.5** (secure reference): every request carries a
  server-issued, single-use nonce; a stale one is refused with a fresh one
  offered. The proof's run id follows the same shape -- server-minted,
  single-use, refused when spent or expired, fresh one re-minted.
- **#46's own settled rule**: "when in doubt, it is real" -- a self-test
  never discards data. Applied: a proof scan is a real snapshot and is
  stored whether or not it proves anything.
- **Could not verify:** whether Syft's SBOM-file cataloger is in the
  default image cataloger set (its docs list no default set). This only
  matters for the rejected canned-SBOM option below.

Step-up re-authentication (decision 8):

- **NIST SP 800-63B-4** (final, 2025-07-31; Rev 3's numbers are the
  ones still repeated in most secondary coverage). Reproduced from
  `pages.nist.gov/800-63-4`: AAL2's overall timeout "SHOULD be no more
  than 24 hours", inactivity "SHOULD be no more than 1 hour", and after
  inactivity a verifier "MAY allow the subscriber to reauthenticate using
  only a successful password". These are session-continuation rules; the
  text says nothing about confirming a single sensitive action. Applied:
  the owner's "forced reauth" is not a session timeout and is not
  designed as one -- it is a per-action confirmation.
- **OWASP Authentication Cheat Sheet** (reproduced): "Require the current
  credentials for an account ... before sensitive transactions." No
  duration given. **OWASP ASVS 5.0** requirement text could not be
  fetched; not relied on.
- **GitHub sudo mode** (reproduced, docs.github.com): a confirmation
  lasts two hours, per session, and any sensitive action resets the
  timer. Rejected below as a shape: a window is a convenience for many
  actions in a row; birdcage has one action.
- **Pocket ID GHSA-hp74-gm6m-2qm5** (no CVE, CVSS 4.0 6.0, fixed
  `0.0.0-20260419162744-978ac87deffe`). Reproduced. The reauthentication
  endpoint's fallback "only checks JWT freshness (`IssuedAt` within 60
  seconds), not the authentication method used", and the session check
  accepted "any arbitrary cookie value". Lesson: freshness of a token is
  not proof of a credential; the grant must be bound to a server-side
  session and minted only by an actual credential check.
- **Nextcloud CVE-2023-49791** (NVD 5.4): password confirmation "shown
  in the UI" was bypassed "by sending calls directly to the API".
  **Nextcloud CVE-2023-25820** (NVD 4.2): the confirmation endpoint had
  no rate limit, so a session holder could brute-force the password.
  Both reproduced from NVD. The GHSA ids the automated search reported
  for them were wrong (both 404) -- the class of error AGENTS.md warns
  about. Lessons: the check lives on the action's handler, never only in
  the modal; the confirmation endpoint shares the login limiter.
- **Keycloak CVE-2023-3597** (GHSA-4f53-xh3v-g8x4, 5.0; `< 22.0.10`,
  `>= 23.0.0, < 24.0.3`). Reproduced. Step-up accepted a second factor
  the attacker had just registered. Lesson for when birdcage has a second
  factor: step-up uses the factor the account already had, never one
  enrolled inside the confirmation flow.

What the research changed: the target (the issue's port-scan candidate
is dropped, because the agent cannot do it and should not be taught to);
and the confirmation's shape (a one-shot grant bound to session, action
and target, not a timed sudo window).

## Options considered

- **Bounded network scan of birdcage's own address** (the issue's
  candidate). Rejected: Nightjar has no network scanner and no capability
  to run one; adding one puts a probing tool in a privileged host-reading
  image (AGENTS.md forbids building attack tooling here); and a service
  that invites its own agents to scan it is a signal the honeypot side
  must then learn to ignore.
- **Operator-chosen safe target.** Rejected: everything above, plus a
  target the operator does not own is a legal hazard birdcage would be
  encouraging by having the flag at all.
- **Canned known-vulnerable SBOM shipped in the image, scanned as a
  marker.** Rejected: proves Grype and its database, not the host mount
  -- the mount is what actually breaks (#108's mask flags and Docker 25
  requirement). It also plants a "vulnerable" fixture inside an image the
  release pipeline scans, and whether Grype's own cataloger would flag
  it could not be verified.
- **First `status: ok` snapshot settles pending, no order.** Rejected:
  birdcage chooses neither the moment nor the retry -- a scanner whose
  first scan fails on a stale database sits pending six hours; nothing
  expresses "self-test failed" with a reason; and it forks #47's
  pending machinery instead of reusing it.
- **Carry the order on the heartbeat response** instead of a command
  poll. Rejected: a second order channel beside `canary_commands` and
  `ClaimNextCanaryCommand`, and a heartbeat response that starts
  carrying state. Fewer requests is not worth two roads.
- **A new `/ingest/progress` route for stage reports.** Rejected: a new
  route, kind gate and limiter for one small field the scanner's
  heartbeat body -- already per kind by ADR-0009 -- can carry. The
  events batch is honeypot-only and stays so.
- **A separate "manual scan" command kind and table.** Rejected: an
  order is an order; one `scan` command, one run row, one matcher, with
  a trigger column saying who asked.
- **A timed sudo window (GitHub's two hours).** Rejected: the owner
  asked for a re-auth event per manual scan, and one action needs no
  window. A window is also more to get wrong (the Pocket ID class).
- **Ship the manual scan before the dashboard has a login**, confirming
  nothing. Rejected: a button anyone reaching the dashboard can press to
  make a host run a full scan is the opposite of the decision. The route
  does not exist until a session does.

## Decision

**1. The proof is an ordered scan of the host Nightjar already mounts.**
Birdcage mints a `scan` command (a second `canary_commands.kind` beside
`selftest`) carrying only a server-minted `run_id`; Nightjar does its
ordinary job -- mount check, database refresh, Grype over `/host` -- and
posts the resulting snapshot to `POST /ingest/scans` with that `run_id`
in the body. Nothing new is scanned, no target is named, no capability is
added. What is proved is the whole chain the operator will rely on:
credential, command road, mount and masks, database fetch, engine,
snapshot ingest.

**2. The order travels on the existing command road.** `POST
/ingest/commands` widens to `{Honeypot, Scanner}` (`internal/ingest/
http.go:104`, whose comment already reserves this widening for "the same
commit that ever mints a scanner command"). Nightjar gains a poll loop
shaped like `cmd/mockingbird/command.go`, jittered the same way. This is
an outbound request over the same mTLS channel as its heartbeat, so
ADR-0010 decision 3 ("no listener") stands. `ClaimNextCanaryCommand`
is per node, so a scanner can only ever claim its own commands; each
agent ignores a command kind it does not implement, logging once.

**3. The run reuses #47's tables and lifecycle, not a parallel set.** A
scanner run is a `self_test_runs` row with one `self_test_targets` row,
service `scan`, no marker (like `portscan` and `poisoner`, which already
carry none). `FirstContact` mints it on the credential's first use;
`retryPending` re-mints while pending; `SweepExpiredSelfTestRuns` fails
it at the deadline; the pass calls the same `SettlePending`. Per-kind
differences live in one place, `mintForCanary`, which today already
branches on kind-specific targets:

   - **30 minutes is the outer cap, not the signal** (`scanRunWindow`,
     against the honeypot's 10-minute `selfTestWindow`). A first run
     can include Grype's cold database download (roughly a gigabyte,
     `docs/enrolment.md`), so a shorter cap fails honest scanners; but
     the cap is only reached by a run that went silent. Everything
     before it is reported stage by stage (decision 9), and a snapshot
     answering with a failed status closes the run at once, so a broken
     mount shows within a minute, not thirty. The pending-retry guard
     equals the cap, so at most one run is open per scanner and a
     silent scanner is re-ordered every 30 minutes until one passes.

**4. `POST /ingest/scans` takes an optional `run_id`.** Absent, the
snapshot is an ordinary timer scan, exactly as today. Present, the
handler resolves the run and settles it, all inside the snapshot's own
transaction:

   - The run must exist and belong to the posting node (identity from
     the bearer token, kind already proved by ADR-0011). Otherwise the
     whole request is refused `400 unknown run`, nothing stored, and
     audited through the existing coalescer.
   - A run already completed or past its deadline: the snapshot is
     stored (it is real data) and does not settle anything; one audit
     entry, `selftest.run_stale`.
   - `taken_at` must be at or after the run's `issued_at`. Earlier
     means the agent answered with a scan it had already done; stored,
     not a pass.
   - `status: ok` with `engine.db_built_at` within Grype's own five-day
     rule (re-checked server side; today `scans.go` parses the field
     but does not bound it) and `masked_paths` equal to the full
     `hostmask.Masks` set: the run passes. For a proof run
     `SettlePending` fires; for a manual run (decision 7) it does not.
   - `status: failed`: the run completes with `passed = 0` at once; the
     failure `reason` is already on the snapshot row.
   - The snapshot row records which run it answered
     (`scan_snapshots.self_test_run_id`, nullable, migration 0021 in
     both schemas), so the dashboard can point at the proving scan.

**5. `store.Provision` sets `Pending` for every kind.** The
`found.Kind == agentkind.Honeypot` test goes; a kind with no proof
minter is a bug, not a grandfather clause, and `mintForCanary` refuses
to mint for an unknown kind with an error rather than silently doing
nothing.

**6. What the operator sees.** The scanner tile uses #45's existing
states: `pending` until the first ordered scan passes, with the run's
current stage and how long it has sat there in the sentence
(decision 9); `self_test_failed` naming the `scan` target and the last
stage reached when a run fails or expires, with the failure reason
readable on the newest snapshot in `GET /api/scans`. For a scanner,
`self_test_failed` clears on the next `status: ok` snapshot from that
node, ordered or timer -- a scanner's six-hourly snapshot is the same
evidence an ordered one is, so a node that has since scanned cleanly is
not left wearing an old failure. The daily self-test schedule remains
honeypot-only (`ListHoneypotCanariesForSelfTest`): birdcage never
re-runs the proof on its own; it re-scans a registered scanner only when
the admin asks (decision 7).

**7. An admin can order a scan of a registered scanner, on the same
road.** `POST /api/canaries/{id}/scan` mints the same `scan` command and
the same run row, `trigger = 'manual'` (new column on `self_test_runs`,
default `'proof'`; existing honeypot rows keep the default, which for
them reads as "scheduled or first-contact"). Nightjar cannot tell the
two apart and does not need to. Differences, all server side:

   - **Never touches `registered_at`.** A manual run's pass or fail is
     recorded on the run and shown as decision 6 says; a failed one
     never re-pends the node, because pending means "never proved", and
     this node did. Refused `409 pending` on a node still pending -- its
     proof run is already open, and the retry guard owns the cadence.
   - **One run in flight per scanner**, proof or manual: a second order
     while one is open is `409 run in progress`, with the current stage
     in the body. **Five-minute cooldown** (`manualScanCooldown`) from
     the last completed manual run, `429 too soon`. So one node scans at
     most once per cap while silent, and roughly every five minutes
     when answering -- a bounded cost an admin chose, not a flood a
     session can produce. There is no fleet-wide "scan all".
   - Same cap as the proof. A registered scanner's database is warm, so
     the stages will normally run out in a minute or two; the cap is
     for the case where they do not.
   - The button and its outcome live on the scanner's canary page
     (`frontend/src/CanaryPage.svelte`): "Scan now" is disabled with the
     current stage while a run is open; a completed run shows pass with a
     link to its snapshot, or fail with the reason and last stage; an
     expired one reads "no result after 30 minutes; last stage: ...".

**8. Ordering a scan forces the admin to re-authenticate, then and
there.** This is built on ADR-0005's session model (opaque server-side
sessions, Argon2id local accounts, login rate limiting) and ships with or
after it, never before (options considered). The shape:

   - `POST /api/auth/reauth` `{password, action: "canary.scan", target:
     <canary id>}`. Verifies the password with the login path's own
     function, under the login path's own per-account and per-address
     limiter and lockout -- the confirmation endpoint is a password
     oracle held by whoever holds the session (Nextcloud CVE-2023-25820)
     and gets no cheaper limiter than the front door. Reaching the
     lockout ends the session as well: a hijacked session does not get
     unlimited guesses at the password.
   - Success mints a **grant**: 128-bit random id, stored server side
     against `(session id, account id, action, target, expires_at,
     used_at)`; `expires_at` two minutes out. Returned in the body, never
     as a cookie, never stored client side beyond the request that spends
     it. Nothing about the grant's existence is inferable from any other
     response.
   - `POST /api/canaries/{id}/scan` `{grant}`. The handler -- not the
     modal (Nextcloud CVE-2023-49791) -- loads the grant and refuses
     `403 reauth_required` unless every field matches: this session,
     this account, `canary.scan`, this canary id, unexpired, unused. It
     marks `used_at` in the same transaction that mints the command, so
     a replayed grant and a doubled click both lose the race. The
     frontend treats `403 reauth_required` as "open the password modal",
     which is also how a grant that expired mid-modal recovers.
   - **What counts as fresh is the credential, not the clock.** A
     session that logged in ten seconds ago is still asked. Password is
     the floor; when the account has a stronger factor (none exists
     today, in birdcage or in gauntlet's reference), step-up uses the
     factor the account already had before the flow began (Keycloak
     CVE-2023-3597). An OIDC-only account (ADR-0003's `(issuer,
     subject)` identity, no local password) re-authenticates by a
     provider round trip with `prompt=login` and `max_age=0`, and the
     returned `auth_time` must be later than the grant request; the
     grant is minted on that callback. This is the one branch not
     designed to a running implementation; it is a consequence for #8.
   - CSRF: the same protection every mutating dashboard route gets when
     sessions arrive (ADR-0005 leaves that to gauntlet), plus the grant
     itself, which a cross-site page cannot obtain. The grant is a
     second wall, not the first.
   - Audit, every path, actor from the session: `auth.reauth_ok`,
     `auth.reauth_failed` (with the action asked for), `auth.reauth_
     lockout`, `canary.scan_ordered`, `canary.scan_refused` (with the
     reason: pending, in progress, too soon, reauth). Target is the
     canary id; the run id stays out of the audit log as it stays out of
     `/api` (Fleet's oracle).

**9. The scanner reports where it is, stage by stage, on its
heartbeat.** The scanner's heartbeat body is already per kind
(ADR-0009: "the small common part is shared; the rest belongs to the
kind"; `ingestCommonHeartbeat`). It gains one optional object, `run:
{run_id, stage}`. Nightjar posts a heartbeat the moment a stage changes,
outside the 60-second tick, and repeats the current stage on every
ordinary tick until the run is answered. Bound and authenticated the
same way everything on that route is: bearer token gives the node, the
run must belong to it and be open, otherwise the field is ignored and
`selftest.stage_stale` is audited through the coalescer. Stages only
move forward; a report for an earlier stage is ignored; an unknown stage
string is `400`.

   The stages, in order, and who sets them:

   | stage | set by | what it means if the run stops here |
   |---|---|---|
   | `ordered` | birdcage, at mint | the scanner has connected (its first authenticated request is what mints a proof run; a manual one is refused unless it heartbeated within the last two intervals) but has not collected the order: the poll loop is not reaching `/ingest/commands`, or the build predates it |
   | `collected` | birdcage, on claim | the order was collected and nothing came back: the agent died, or is on a build that ignores `scan` |
   | `mounts_checked` | Nightjar | `hostmask.Check` passed; the database step is running (a cold download can sit here for many minutes -- the honest reason for the cap) |
   | `db_ready` | Nightjar | `grype db update` finished; Grype itself has not reported |
   | `scanning` | Nightjar | Grype is running over `/host` |
   | `answered` | birdcage, on the snapshot | the result landed; the verdict is on the run |

   A failure Nightjar can see (mask flag missing, Grype exits non-zero)
   is still posted as a `status: failed` snapshot at once, as today, and
   the run fails with the reason; stages add nothing there. Stages are
   for the run that goes quiet -- what the owner asked for -- and for
   the pending sentence while it runs. `self_test_runs` gains `stage`
   and `stage_at` (migration 0021); the dashboard reads both on the
   canary page and the tile sentence, never the run id. Manual runs show
   the same stages, from the same columns. `grype db update` becomes a
   separate step before the scan so that `db_ready` is a fact, not a
   guess. Reaching a later stage does not extend the cap.

## Security analysis

- **Threat model, proof.** A compromised or impersonated scanner holds
  a scanner-kind credential. The proof does not defend against an agent
  that lies -- neither does the honeypot's, whose `portscan` claim is
  the agent's word -- and does not try to: a forged `ok` snapshot with
  a valid `run_id` buys the attacker a node marked registered that they
  could already post snapshots as. What the proof defends against is
  the honest failure class (#116's actual bug) and the cheap dishonest
  ones: replaying an old snapshot (spent or stale `run_id` never
  settles), answering with pre-recorded output (`taken_at` before
  `issued_at`), a "clean" result from an engine that did not run
  (`status: failed` and the stale-database bound never pass), and a
  scan through an uncovered mount (`masked_paths` must be complete).
- **Threat model, stages.** A stage is the agent's word and is used
  only to describe an unanswered run to the operator; nothing settles
  on it. A lying agent can misdescribe where it stalled, not pass. Bound
  to an open run of its own node, monotonic, closed vocabulary, inside
  the heartbeat's 4 KiB body bound and its existing limiter; an extra
  heartbeat per stage change is at most five per run.
- **Threat model, manual scan.** The attacker is whoever holds an
  admin session: a stolen cookie, a walked-away browser, a cross-site
  page. What they can gain is one full host scan per node per five
  minutes, and a password guess per limiter step -- and the guesses end
  the session. The grant is bound to session, account, action and
  target, single use, two minutes; the check is on the handler. What
  the design does not defend against is an attacker who holds the
  password too; that is the account, not this feature.
- **No credential widens.** The command route is claim-only and per
  node; a scanner sees its own commands and nothing about any other
  node. ADR-0011's kind checks apply unchanged. A honeypot credential
  still cannot reach `/ingest/scans`.
- **The run id is not a secret**, but it is treated as one where it
  costs nothing (Fleet's oracle): it is never exposed on `/api` or in
  the audit log, and a run's `run_id` is only ever sent to the node it
  was minted for.
- **Fail closed, every path.** Unknown run: refused, nothing stored.
  Spent or expired run: stored, never a pass. Failed status: run fails
  immediately, reason kept. Nothing arrives: sweep fails the run at the
  cap with the last stage on it, retry re-mints (proof only). Unknown
  kind at mint time: error, node stays pending. Missing, wrong, used or
  expired grant: `403`, nothing minted, audited. Stage for a run not
  this node's or not open: ignored, audited.
- **Cost of a pending scanner:** one full host scan every 30 minutes
  until a pass. Cost of an admin: one per node per five minutes, at
  most. Both bounded by guards, not by trust.
- **Deliberately not done.** No host-content evidence (a distro name,
  a package count) in the pass condition: the mount check already
  fails an unmounted `/host`, and the e2e fixture and some hosts carry no
  `os-release`. No automatic re-proof after registration. No
  agent-chosen anything. No sudo window. No cancel button: the cap ends
  a run, and a cancel is a second admin action to secure for no gain. No
  manual scan without a session.

## Consequences

- Every scanner enrolled before this ships is already registered and is
  unaffected; new scanners show `pending` with a stage for a minute or
  two, or longer on a first cold database download, and the operator can
  see which.
- `docs/enrolment.md`'s "A scanner has no self-test yet" paragraph is
  replaced by the scanner's proof, and its `--kind scanner` section says
  what pending, the stages and self-test failed mean for it.
- Nightjar gains one loop (the command poll), one split (`grype db
  update` before the scan) and stage reports on its heartbeat. #113's
  image scanning inherits an order road that already exists.
- The manual scan and its re-authentication wait for a session to bind
  to. #8 is deferred to M3, so today the "scan now" button has no
  earliest date; decision 8 is the design gauntlet's birdcage wiring
  must satisfy when it lands. The owner decides the order (open
  question).
- The daily self-test stays a honeypot concept. Nothing schedules
  scanner runs after registration; only an admin orders one.

## Implementation outline

Two MRs, each with its live journey (AGENTS.md: a change to enrolment
lands with its journey). Commit messages `Refs #116`.

**MR 1 -- proof, cap and stages** (no dependency on #8):

- [ ] `internal/store/command.go` (or wherever `CommandSelfTest` lives):
      add `CommandScan = "scan"`; params `{run_id}` only.
- [ ] `internal/store/selftest.go`: `MintScanCommand(ctx, db, canaryID,
      trigger, now, deadline)` -- one transaction: `canary_commands`,
      `self_test_runs` (`trigger`, `stage = 'ordered'`), one
      `self_test_targets` row (`service = "scan"`, `dest_port = 0`,
      empty marker hash, grade as `gradeForService` decides). Refuses
      when a run is open for the node. Add `MatchScanRun(ctx, tx,
      canaryID, runID, takenAt, snapshot)` returning pass / fail / stale
      / unknown, completing the run and calling `SettlePending` only
      for `trigger = 'proof'`. Add `AdvanceRunStage(ctx, db, canaryID,
      runID, stage, now)`: own node, open, forward only.
- [ ] Migration `0021_scan_runs.sql` (sqlite and postgres):
      `scan_snapshots.self_test_run_id TEXT NULL`; `self_test_runs`
      gains `trigger TEXT NOT NULL DEFAULT 'proof'`, `stage TEXT NULL`,
      `stage_at TEXT NULL`.
- [ ] `internal/store/provision.go:186`: `Pending: true`.
- [ ] `internal/selftestsched/scheduler.go`: `scanRunWindow = 30m`;
      `mintForCanary` branches on `c.Kind`; `retryPending` lists pending
      nodes of every kind (new `ListPendingCanaries` or widen the
      existing query); unknown kind logs an error and mints nothing.
      `FirstContact` unchanged in shape. The sweep leaves `stage` as it
      found it, so an expired run says where it stopped.
- [ ] `internal/ingest/http.go:104`: `/ingest/commands` kinds
      `{Honeypot, Scanner}`. `handleCommands`: a scanner may claim only
      `scan` commands (kind-to-command allow-list, fail closed); a
      claimed `scan` advances its run to `collected`.
- [ ] `internal/ingest/heartbeat.go`: `ingestCommonHeartbeat.Run
      *struct{RunID, Stage}`; closed stage vocabulary; calls
      `AdvanceRunStage`; audit `selftest.stage_stale` through the
      coalescer.
- [ ] `internal/ingest/scans.go`: `RunID string json:"run_id,omitempty"`;
      decision 4's checks and the five-day `db_built_at` bound; sets
      `answered`; audit actions `selftest.run_unknown` (refusal) and
      `selftest.run_stale`, both through the coalescer.
- [ ] `internal/store/health.go` / `selftest.go` (`applySelfTestState`):
      for a scanner, `self_test_failed` clears when a later `ok`
      snapshot exists. Stage and `stage_at` on the canary read model.
- [ ] `cmd/nightjar/command.go` (new): jittered poll of
      `/ingest/commands`, modelled on `cmd/mockingbird/command.go`; a
      `scan` command triggers one immediate scan tagged with `run_id`;
      the scan loop serialises ordered and timer scans; unknown command
      kinds logged and skipped. `client.Snapshot` gains `RunID`.
- [ ] `cmd/nightjar/scanner.go` + `internal/scan`: `grype db update`
      as its own step; an ordered scan reports `mounts_checked`,
      `db_ready`, `scanning` through the heartbeat sender
      (`client.CommonHeartbeat` gains `Run`), immediately on each.
- [ ] `scripts/agent-deps-check.sh`: confirm the new file imports nothing
      forbidden (it must not import `internal/store` for the command
      kind string -- duplicate the constant as mockingbird does).
- [ ] `internal/api` + `frontend/src/lib/sentence/tileStatus.ts`: the
      `pending` sentence carries stage and minutes; `self_test_failed`
      names the `scan` target and last stage; no run id in any API
      response. Canary page shows the run's stage timeline.
- [ ] `docs/enrolment.md`: replace the "no self-test yet" paragraph;
      add pending, the stage table and self-test failed to the Nightjar
      section.
- [ ] Unit tests: `Provision` pending for scanner; mint and match
      (pass, failed status, stale db, incomplete masks, `taken_at`
      before `issued_at`, spent run, expired run, wrong node -> 400;
      manual pass never calls `SettlePending`); mint refused while a run
      is open; stage advance (forward only, wrong node, closed run,
      unknown string); scheduler retry mints for a pending scanner and
      respects the 30-minute cap; sweep keeps the last stage; handler
      `run_id` and heartbeat `run` paths; nightjar poll claims `scan`
      and ignores `selftest`; nightjar emits the three stages in order.
- [ ] Live journey, `scripts/e2e/scanner.sh`: after enrol, node reads
      `pending`; assert the stage sequence advances through `collected`
      and at least `scanning` on the read model; poll until `ok` (bound 5
      minutes -- the runner's Grype database volume is warm, #108);
      assert the newest snapshot carries `self_test_run_id`. Leg 2
      (dropped mask flag) now also asserts `self_test_failed` with last
      stage `collected` and a `pending` node, never `ok`. Runs at both
      hops (`docs/ci-hops.md`), Postgres included.

**MR 2 -- admin-ordered scan behind re-authentication** (after the
session model from #8 / ADR-0005 is wired; the first mutating admin
route in `internal/api`):

- [ ] `internal/api/reauth.go` (new): `POST /api/auth/reauth`; login's
      verify function and limiter; `reauth_grants` table (migration
      with #8's schema): id, session id, account id, action, target,
      expires_at, used_at; lockout ends the session.
- [ ] `internal/api/canary_scan.go` (new): `POST /api/canaries/{id}/scan`
      `{grant}`; grant check and `used_at` in the mint transaction;
      `409 pending` / `409 run in progress` / `429 too soon` /
      `403 reauth_required`; `manualScanCooldown = 5m`; the node must
      have heartbeated within two intervals.
- [ ] Audit: `auth.reauth_ok`, `auth.reauth_failed`,
      `auth.reauth_lockout`, `canary.scan_ordered`, `canary.scan_refused`.
- [ ] `frontend/src/lib/api.ts`: first mutating call; password modal
      component; "Scan now" on `CanaryPage.svelte` with the states in
      decision 7; `403 reauth_required` re-opens the modal.
- [ ] Unit tests: grant bound to each of session, account, action,
      target; expiry; single use under concurrent spend; wrong password
      counts against the login limiter and lockout ends the session;
      handler refuses without a grant even with a valid session (the
      Nextcloud case as a test); cooldown; in-flight refusal; pending
      refusal.
- [ ] Live journey, `scripts/e2e/scanner.sh` leg 3 and a Firefox leg
      (#83): log in; wrong password on reauth -> `403` and
      `auth.reauth_failed`; correct password -> grant; scan without grant
      -> `403`; with grant -> `202`; same grant again -> `403`; second
      order while open -> `409`; run passes with stages recorded and
      `registered_at` unchanged; browser leg drives the modal.

## Open questions for the owner

- Sequencing: #8 (dashboard authentication) sits in M3 "Deferred". The
  manual scan cannot ship before it. Either the auth-module wiring from
  ADR-0005 moves earlier so MR 2 has a milestone, or "scan now" waits
  for M3. Which?
