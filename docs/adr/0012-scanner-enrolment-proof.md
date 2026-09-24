# ADR-0012: A scanner proves its enrolment by answering an ordered scan, over the same road as a honeypot's self-test

**Status:** Accepted by the owner, 2026-09-24 (after one review round)
**Date:** 2026-09-24
**Relates to:** #116 (this proof), #129 (manual scan, M3), #47
(enrolment; pending until the first self-test passes), #46 (self-test),
#45 (canary health states), #56 (state history), #72 (certificate
renewal), #105, #108 (Nightjar slice 1), #8 (dashboard authentication,
deferred), ADR-0005, ADR-0006, ADR-0007, ADR-0009, ADR-0010, ADR-0011.

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

The owner's first review (2026-09-24) added four points, each answered
below and named where it lands:

- *"vulnerability lists should be pulled immediately before a scan, if
  pulling fails for more than 24hr the scanner should report the error
  to birdcage to flag."* Decision 10; the pass rule in decision 4 and
  the stage table in decision 9 change with it.
- *"stolen scanner keys, there's ways to protect from this for both
  honeypots and scanners."* Part B, a fleet-wide design for both kinds;
  the proof's own threat model is restated against it.
- *"all failures get reported to birdcage who keeps track of the fails
  so self resetting is fine."* Decision 11: the tile still clears, and
  every failure -- proof, manual, timer, database refresh -- is a row
  the operator can go back to.
- *"try again on the research."* Every id is now read from NVD or the
  GitHub Advisory Database directly; the research section says what was
  corrected.

Two facts about how agent credentials work today, read from the code,
shape Part B:

- **Birdcage makes the agent's private key and posts it to the agent.**
  `ca.IssueClient` (`internal/ca/ca.go:359`) generates an ECDSA P-256
  key and `POST /enrol/provision` returns key, certificate and bearer
  token together (`internal/enrol/provision.go:86`). The agent writes
  them to its state volume at mode 0600
  (`internal/agent/enrolment/enrolment.go:199`). The certificate is
  valid for a year (`clientCertTTL`, `provision.go:25`) and nothing
  renews it (#72). The bearer token rotates every 24 hours, agent-driven
  (`cmd/mockingbird/rotate.go`); the old token stays valid until the
  new one's first use, when `completeRotation` revokes it
  (`internal/ingest/auth.go:395`). A revoked token presented while its
  successor is live is already audited as `ingest.token_conflict` and
  is #45's `token_conflict` state.
- **Every ingest request needs both halves.** mTLS with the client
  certificate whose CN is the node id, plus the bearer token that
  resolves the node (`internal/ingest/auth.go:87-139`); kind is checked
  twice (ADR-0011). The peer address is recorded (`last_seen_addr`,
  migration 0015) but nothing authorises on it. Revocation is a CLI
  (`birdcage canary revoke <token_id>`); there is no dashboard path and
  no certificate revocation at all.

## Research

Done before the design, per `docs/security-by-design.md`, and redone in
full after the owner's first review ("try again on the research").
**How verified:** every GHSA id was read with `gh api /advisories/<id>`
and every CVE with NVD's JSON API (`services.nvd.nist.gov/rest/json/
cves/2.0?cveId=`), on 2026-09-24; standards text was read from the
publisher's own repository or site (OWASP/ASVS on GitHub, `5.0/en/`;
`pages.nist.gov/800-63-4`; `kubernetes/website`; `anchore/syft` and
`anchore/grype` source at the pinned tag). Scores quoted are the ones on
those records. Nothing below rests on secondary coverage. A previous
draft carried two Wazuh ids as "leads" and two items as "could not
verify"; all four now reproduce, and two of them changed what the ADR
says (marked *corrected*).

Enrolment proof:

- **Grype CVE-2025-65965** (GHSA-6gxw-85q2-q646; GitHub High, NVD
  CVSS 4.0 8.2): registry credentials copied unsanitised into JSON
  output written with `--file` or `--output json=<file>`, `>= 0.68.0,
  < 0.104.1`, fixed 0.104.1. Nightjar pins 0.119.0
  (`build/nightjar/Dockerfile:36`), configures no registry credential
  and reads Grype's stdout; not affected. Relevant again when #113
  scans images.
- **Fleet (osquery) CVE-2026-46370** (GHSA-vxm7-9x8v-8gm4, 6.5, `<=
  4.84.1`): an unvalidated `order_key` on the labels host-listing
  endpoint let the lowest-privilege Observer role binary-search hosts'
  long-lived `node_key` one character at a time and impersonate them.
  Lesson applied: the proof's run id never appears in any `/api`
  response or the audit log.
- **Wazuh CVE-2026-34150** (NVD 7.5, `< 4.14.5`) -- *corrected*: it is
  a heap overflow in `wazuh-analysisd` reachable because the default
  docker deployment lets anyone enrol with `authd` **without a
  password** and obtain a valid agent id and key. **Wazuh
  CVE-2026-39359** (NVD 7.5, `4.0.0-4.10.3`, `4.11.0-4.14.4`): the
  agent chooses its group at enrolment and `..` in the group name
  traverses out of the groups directory. Neither is in the GitHub
  Advisory Database (they are not Go/npm/... packages), which is why the
  first draft could not find them there. Both are the class #47's
  single-use deploy token and server-chosen identity already close;
  this ADR adds nothing an agent chooses at enrolment.
- **ACME, RFC 8555 section 6.5** (secure reference): every request
  carries a server-issued, single-use nonce; a stale one is refused with
  a fresh one offered. The proof's run id follows the same shape.
- **#46's own settled rule**: "when in doubt, it is real" -- a self-test
  never discards data. Applied: a proof scan is a real snapshot and is
  stored whether or not it proves anything.
- **Syft's SBOM cataloger is not default-on** -- *corrected* from
  "could not verify". In `internal/task/package_tasks.go` it is
  registered with the single tag `"sbom"` and the comment "not evidence
  of installed packages"; `syft/create_sbom_config.go`'s
  `findDefaultTags` selects `directory` + `file` for a directory source
  and `image` + `file` for an image. So a canned SBOM file on the host
  would not be catalogued by default at all: the rejected canned-SBOM
  option would have proved nothing, on top of its other faults.
- **Grype 0.119.0 database defaults** (`grype/db/v6/installation/
  curator.go` and `distribution/client.go` at tag `v0.119.0`, and
  `cmd/grype/cli/options/database.go`): `auto-update: true`,
  `validate-age: true`, `max-allowed-built-age: 120h` (five days),
  `max-update-check-frequency: 2h`, `require-update-check: false`. So
  today a scan checks for a new database at most once every two hours,
  and a failed check does not fail the scan while the cached database
  is under five days old. The `grype db update` subcommand sets
  `RequireUpdateCheck = true` (`database_command.go:18`), so it fails
  loudly when the check fails. This is what decision 10 builds on.

Step-up re-authentication (decision 8):

- **NIST SP 800-63B-4** (final; page dated 2025-08-26). Section
  numbers now confirmed from the document's own cross-references
  ("Detailed requirements for each AAL are given in Sec. 2.1.3, Sec.
  2.2.3, and Sec. 2.3.3"; "as described in Sec. 5.2"). **Section
  2.2.3, AAL2 Reauthentication**: overall timeout "SHOULD be no more
  than 24 hours", inactivity "SHOULD be no more than 1 hour", and after
  inactivity the verifier "MAY allow the subscriber to reauthenticate
  using only a successful password or biometric comparison in
  conjunction with the session secret". **Section 5.2,
  Reauthentication**: periodic reauthentication "to confirm the
  subscriber's continued presence", two timeouts, both reset by a
  successful reauthentication. Neither section says anything about
  confirming a single sensitive action. Applied: the owner's "forced
  reauth" is not a session timeout and is not designed as one.
- **OWASP ASVS 5.0** (read from `OWASP/ASVS`, `5.0/en/0x16-V7-Session-
  Management.md` and `0x15-V6-Authentication.md`) -- *now verified*.
  **7.5.3** (L3): "Verify that the application requires further
  authentication with at least one factor or secondary verification
  before performing highly sensitive transactions or operations."
  **7.5.1** (L2): full re-authentication before changing attributes
  that affect authentication. **7.2.4** (L1): a new session token on
  re-authentication. **6.8.4** (L2): when an IdP is used and specific
  recentness is expected, verify it from what the IdP returns --
  "validating ID Token claims such as 'acr', 'amr', and 'auth_time'".
  Applied: 7.5.3 is the requirement decision 8 meets; 6.8.4 is why the
  OIDC branch checks `auth_time` rather than trusting the redirect.
- **OWASP Authentication Cheat Sheet**: "Require the current
  credentials for an account ... before sensitive transactions." No
  duration given.
- **GitHub sudo mode** (docs.github.com): a confirmation lasts two
  hours, per session, and any sensitive action resets the timer.
  Rejected below as a shape: a window is a convenience for many actions
  in a row; birdcage has one action.
- **Pocket ID GHSA-hp74-gm6m-2qm5** (no CVE, GitHub Medium, fixed
  `0.0.0-20260419162744-978ac87deffe`): the passkey step-up requirement
  was "defeated by JWT freshness check that accepts any login method".
  Lesson: freshness of a token is not proof of a credential; the grant
  must be minted only by an actual credential check.
- **Nextcloud CVE-2023-49791** (NVD 5.4): with another user's active
  session, "sending calls directly to the API bypassing the password
  confirmation shown in the UI". **Nextcloud CVE-2023-25820** (NVD 4.2):
  with a logged-in session, "brute force the password on the
  confirmation endpoint". Neither has a GitHub advisory; the GHSA ids an
  earlier automated search offered for them were wrong and are not
  cited. Lessons: the check lives on the action's handler, never only in
  the modal; the confirmation endpoint shares the login limiter.
- **Keycloak CVE-2023-3597** (GHSA-4f53-xh3v-g8x4, 5.0; `< 22.0.10`,
  `>= 23.0.0, < 24.0.3`): a password-authenticated user could "register
  a false second authentication factor along with an existing one and
  bypass authentication". Lesson: step-up uses the factor the account
  already had, never one enrolled inside the confirmation flow.

Stolen agent credentials (Part B):

- **Kubernetes kubelet TLS bootstrapping** (secure reference,
  `kubernetes/website`, `kubelet-tls-bootstrapping.md`): the kubelet
  "creates a CSR for itself" -- the key never leaves the node -- the
  control plane signs it, the bootstrap token is bound to a role that
  limits it "strictly to client requests related to certificate
  provisioning", and with `rotateCertificates` the kubelet "automatically
  requests renewal of the certificate when it is close to expiry".
  Birdcage's deploy token already has the single-purpose shape; the
  agent-side key and the renewal are what Part B adds.
- **RFC 8705** (OAuth 2.0 certificate-bound access tokens): a token
  carries the SHA-256 thumbprint of the client certificate it was issued
  under (`cnf.x5t#S256`) and a resource "rejects the request if they do
  not match". Part B binds the bearer token to the certificate the same
  way, so neither half is usable without the other.
- **Fleet CVE-2026-23998** (NVD CVSS 4.0 8.2, `< 4.81.0`): the Windows
  MDM endpoint "relies on mutual TLS (mTLS) client certificates" but
  "requests that did not present a client certificate could be
  incorrectly treated as trusted", so a device could be impersonated
  from its identifier alone. Lesson: the certificate check is never
  optional per route; birdcage's `requireBearerToken` exemption for
  plain test requests (ADR-0011 decision 3) is the one place this class
  could enter, and the registry check stays outside it.
- **Keylime CVE-2025-13609** (NVD 8.2): "registering a new agent using
  a different Trusted Platform Module (TPM) device but claiming an
  existing agent's unique identifier (UUID)" overwrote the real agent's
  identity. Two lessons: even TPM-attested fleets fall to an identity
  that the agent names; and re-enrolment of an existing name must never
  silently replace the live credential. Birdcage's identity is
  server-minted (#47), and Part B makes a second enrolment under an
  existing name a new node, never a takeover.
- **What a TPM would add, and why it is not required.** A key that
  cannot leave the host (TPM-resident, non-exportable) is the only
  mechanism that stops a copied key working at all. ADR-0008 makes the
  agent a container; many hosts a canary runs on -- a Pi, a VM, a NAS --
  have no TPM, and a container cannot reach one without a device mount
  and privilege this project refuses to ask for. So Part B does not
  prevent copying; it makes a copy short-lived, makes two holders of
  the same credential collide within a minute, and gives the operator
  one action to end both.

What the research changed: the target (the issue's port-scan candidate
is dropped, because the agent cannot do it and should not be taught to);
the confirmation's shape (a one-shot grant bound to session, action and
target, not a timed sudo window); the database refresh (an explicit,
loud `grype db update` before every scan, because Grype's own defaults
would otherwise check at most two-hourly and fail silently); and the
credential model (agent-generated keys, short renewals, cert-bound
tokens, conflict detection -- Part B), which the first draft had left
at "the proof does not defend against a stolen credential".

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
- **Leave the database refresh to Grype's auto-update.** Rejected: its
  defaults check at most every two hours and carry on silently when the
  check fails (research); the owner asked for a pull immediately before
  every scan and a loud failure. `grype db update` as its own step gives
  both.
- **Stop scanning while the refresh is failing.** Rejected: a scanner
  that goes quiet because a mirror is down tells the operator nothing;
  a scan on a database Grype still accepts, marked with the refresh
  error, is real data (#46's rule). Past Grype's five-day cap it stops
  anyway, and says so.
- **TPM-bound or otherwise non-exportable agent keys.** Rejected for
  the baseline (research): not available on many canary hosts, and not
  reachable from an unprivileged container. Nothing in Part B prevents
  a later opt-in for hosts that have one.
- **Source-address pinning as authorisation.** Rejected: a canary
  behind NAT or DHCP would refuse itself, and an attacker on the same
  segment -- the honeypot's whole premise -- shares the address anyway.
  The address is evidence for conflict detection, never a credential.
- **Automatic revocation on a credential conflict.** Rejected: an
  attacker holding a copied key could then silence the real canary by
  presenting the copy once. A conflict flags loudly; the operator
  revokes. The one automatic cut that stays is the existing one-way
  rotation rule: whoever renews first wins, and the loser is refused
  and visible.
- **Keep one-year certificates and add a revocation list.** Rejected: a
  year is how long a copied key stays useful, and a revocation list only
  helps after the theft is noticed. Short lifetimes bound the useful
  life of a copy whether or not anyone notices.

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
   - `status: ok`, `engine.db_refreshed_at` at or after the run's
     `issued_at` (decision 10: an ordered run proves the database fetch
     too; a scan on a stale-but-accepted database is stored as real
     data but does not pass, reason `db_refresh_failed`),
     `engine.db_built_at` within Grype's own five-day rule (re-checked
     server side as the backstop for every snapshot; today `scans.go`
     parses the field but does not bound it) and `masked_paths` equal
     to the full `hostmask.Masks` set: the run passes. For a proof run
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
not left wearing an old failure. The tile clears; the record does not
(decision 11). The daily self-test schedule remains
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
   | `mounts_checked` | Nightjar | `hostmask.Check` passed; the database refresh is running (a cold download can sit here for many minutes -- the honest reason for the cap) |
   | `db_refreshed` | Nightjar | `grype db update` finished, with or without success (the snapshot says which, decision 10); Grype itself has not reported |
   | `scanning` | Nightjar | Grype is running over `/host` |
   | `answered` | birdcage, on the snapshot | the result landed; the verdict is on the run |

   A failure Nightjar can see (mask flag missing, Grype exits non-zero)
   is still posted as a `status: failed` snapshot at once, as today, and
   the run fails with the reason; stages add nothing there. Stages are
   for the run that goes quiet -- what the owner asked for -- and for
   the pending sentence while it runs. `self_test_runs` gains `stage`
   and `stage_at` (migration 0021); the dashboard reads both on the
   canary page and the tile sentence, never the run id. Manual runs show
   the same stages, from the same columns. Reaching a later stage does
   not extend the cap.

**10. The vulnerability database is refreshed immediately before every
scan, and a refresh that keeps failing is flagged.** Owner: *"pulled
immediately before a scan, if pulling fails for more than 24hr the
scanner should report the error to birdcage to flag."* Every scan --
timer, proof, manual -- starts with `grype db update` as its own step
(it fails loudly: research, `require-update-check` is forced on for
that subcommand), and the scan itself then runs with `db.auto-update:
false`, so what was fetched is what was scanned with and Grype's
two-hour check cap never applies. What follows a failed refresh:

   - **Under Grype's five-day age cap, the scan still runs** on the
     last good database, and the snapshot says so: `engine` gains
     `db_refreshed_at` (last successful refresh, persisted in Nightjar's
     state directory so a restart does not forget it) and
     `db_refresh_error` (the refresh's error text when this scan's
     refresh failed). A timer snapshot is `status: ok` with the error
     alongside; an ordered run does not pass (decision 4). Past the
     cap Grype refuses and the snapshot is `status: failed`, as today.
   - **Every failed refresh is reported at once**, not at 24 hours: the
     scanner's heartbeat gains `db_refresh: {last_ok_at, failing_since,
     last_error}`, present whenever a refresh has failed since the last
     success. Birdcage keeps the newest on the canary read model
     (`db_refresh_failing_since`, `db_refresh_error`; migration 0021)
     and the scanner page shows "database refresh failing since <time>:
     <error>" from the first failure.
   - **At 24 hours of failing it becomes a #45 state**, `db_stale`,
     ranked between `self_test_failed` and `throttled`, with the tile
     sentence "vulnerability database not refreshed for <n> hours". The
     scanner decides nothing here: birdcage compares `failing_since`
     with its own clock, so a wrong agent clock cannot hide or hasten
     the flag. The state clears on the next heartbeat or snapshot
     without a `db_refresh` failure and, like every #45 state, its span
     is recorded (decision 11).
   - The five-day `db_built_at` bound in decision 4 stays as the
     server-side backstop; a snapshot older than that never passes and
     is never `ok`, whatever the agent says.

**11. Every failure is recorded by birdcage as history; the tile may
clear, the record never does.** Owner: *"all failures get reported to
birdcage who keeps track of the fails so self resetting is fine."*
Nothing new is invented for this; each failure already has a row, and
this decision says which and where the operator finds it:

   - **Ordered runs, proof and manual**: one `self_test_runs` row each,
     with `trigger`, verdict, `stage`, `stage_at`, the deadline and the
     answering snapshot's id. Never deleted by the sweep; a scanner's
     first 30 minutes of retries are a list of failed runs the
     operator can read.
   - **Timer scans**: every `scan_snapshots` row, including `status:
     failed` ones with their `reason`, and `ok` ones carrying a
     `db_refresh_error`. Already kept; the newest is what the tile
     reads, the rest is history.
   - **State spans**: `self_test_failed`, `db_stale`, `pending` and
     every other #45 state a scanner enters is a `canary_state_periods`
     row from #56 (`internal/store/history.go`: `started_at`,
     `ended_at`, `flap_count`, `end_reason`), so a tile that is green
     now still shows "self-test failed three times this week, longest
     40 minutes" on the canary page's history, exactly as it does for a
     honeypot's `silent`.
   - **Refusals and stale answers**: the audit log, through the
     coalescer (`selftest.run_unknown`, `selftest.run_stale`,
     `selftest.stage_stale`).
   - The canary page for a scanner gets a **Runs** list (trigger, when,
     verdict, last stage, reason, link to the snapshot) beside #56's
     existing state history and the snapshot list. A flaky scanner is
     visible from either, whatever colour its tile is.

## Part B: stolen agent credentials, both kinds (fleet-wide)

Owner: *"stolen scanner keys, there's ways to protect from this for
both honeypots and scanners."* This part is wider than the proof: it
changes enrolment (#47), answers #72, and touches every agent. It is
decided here so the proof above is designed against the credential
model birdcage will actually have, and it is delivered as its own issue
(implementation outline, "proposed issue"). Nothing in it depends on
#8. It applies to honeypot and scanner alike; the kind never changes
anything below.

**What "stolen" means here.** The credential is two files on the
agent's state volume, key and certificate, plus the bearer token. Whoever
can read that volume -- root on the host, anyone with the Docker socket,
a backup of the volume -- has a working copy. A honeypot is *meant* to
be attacked, so its host is the likeliest place in the fleet for this to
happen; a scanner's volume sits on a host whose secrets it was carefully
masked from seeing. In neither case can birdcage stop the copy being
made. What it can do is make the copy short-lived, make two holders
collide, and give the operator one action to end both.

**B1. The agent makes its own key; birdcage never sees it.** `POST
/enrol/provision` takes a CSR (ECDSA P-256, generated in the container
into the state volume, as the kubelet does) and returns a certificate
and the bearer token. `IssueClient` becomes `SignClient(csr, canaryID,
kind, ttl)`: the subject is overwritten from the registry row -- CN is
the server-minted id, OU the registered kind (ADR-0011) -- and nothing
from the CSR but the public key survives. The private key exists in
exactly one place from the first second. A compromise of birdcage's
database, logs or a captured provision response yields no key; today it
yields every key ever issued.

**B2. Certificates live seven days and the agent renews them from
half-life, with a fresh key each time.** `clientCertTTL` drops from a
year to `7 * 24h`. From day 3.5 the agent tries `POST /ingest/renew`
on every heartbeat tick until one succeeds: a new key pair, a new CSR
over the existing mTLS channel, same subject re-read from the registry.
The old certificate stays valid until the new one's first use, when
birdcage revokes it -- the exact one-way rule `completeRotation`
already applies to bearer tokens. A copied key therefore stops working
by itself within seven days at most, and within 3.5 days on average,
whether or not anyone notices the theft; and a copy used to renew cuts
the real node off, which is loud (B4). The certificate is recorded:
`client_certs (canary_id, serial, fingerprint_sha256, not_before,
not_after, first_used_at, revoked_at)`; the ingest auth path checks the
presented certificate's fingerprint against a live row, so a
certificate birdcage did not issue or has revoked is `401` regardless
of its signature. (Today the check is signature + CN + OU only, with
no record of what was issued.) This answers #72: a renewal that fails
for 3.5 days shows first as `rotation_stalled`'s certificate twin,
`renewal_stalled`, and then as `not_delivering` when the certificate
expires -- visible before dark, which is what #72 asked for.

**B3. The bearer token is bound to the certificate it was minted
under** (RFC 8705's shape). `canary_tokens` gains `cert_fingerprint`;
a token presented over a connection whose client certificate has a
different fingerprint is `401` and audited `ingest.token_cert_mismatch`.
Token rotation (24h, unchanged) mints the new token under the current
certificate; certificate renewal (B2) carries the live token across to
the new fingerprint in the same transaction that records the
certificate, so honest renewal never trips the check. Effect: neither
half is worth anything alone, so a token that leaks by itself (a log
line, a captured request) is inert, and a copied key with a token from
a different rotation generation is inert.

**B4. Two holders of one credential are detected within a heartbeat
interval, flagged, and never auto-revoked.** Two signals, both
recorded per request from what the auth path already resolves:

   - **Superseded credential still in use.** A revoked token or
     certificate presented while its successor is live. Tokens already
     do this (`ingest.token_conflict`, #45's `token_conflict`);
     certificates get the same: `ingest.cert_conflict`, and the state
     widens to mean either.
   - **One live credential, two places at once.** The same certificate
     fingerprint seen from two source addresses within one heartbeat
     interval (60 seconds), or seen with two different agent build
     versions in that window. Audit `ingest.credential_dual_use`
     through the coalescer, state `credential_conflict` ranked with
     `token_conflict`, sentence "credential in use from two addresses:
     <a> and <b>". The peer address is evidence here, never
     authorisation (options considered); a canary whose address
     legitimately changes flaps this once and clears in a minute, and
     #56 records the flap.

   Neither signal revokes anything automatically: a copied key must not
   become a button that silences the real canary. Both put the node in
   a red state that names the next action.

**B5. One operator action ends both holders.** `birdcage canary revoke
<canary-id>` (today it takes a token id) revokes every token and every
certificate for the node in one transaction; from that moment every
request from either holder is `401`, and the honest agent's own log
says so. The same action reaches the dashboard as `POST
/api/canaries/{id}/revoke` behind decision 8's grant, action
`canary.revoke`, when #8 lands -- the grant design generalises to any
admin action, which is why it is bound to `action`. Recovery is
re-enrolment with a fresh deploy token: the name stays, the id and
credential do not. A second enrolment under an existing name never
replaces the live node's credential (Keylime CVE-2025-13609): it is a
new node id, and the old one keeps its history until the operator
removes it.

**What an attacker holding a copied key can and cannot do afterwards.**
Stated concretely, because the first draft did not:

- **Can, until the copy expires (7 days at most) or is revoked:** post
  as that one node -- fake findings or events, heartbeats, stage
  reports, an answer to that node's own `selftest` or `scan` command --
  and claim that node's pending commands. If they rotate the token or
  renew the certificate, they cut the real node off, which flags within
  one heartbeat (B4). If the real node is still running, every request
  from the copy lands beside the real node's and dual use flags within
  a minute.
- **Cannot:** change the node's kind (OU is rewritten from the registry
  at every issuance; ADR-0011's two checks stand); reach any other
  node's commands, data or credentials (claims and reads are per node
  id); enrol a node or mint a deploy token (the enrol listener is a
  different credential domain); read or change anything on the
  dashboard; approve or install an upgrade (ADR-0007: that needs the
  admin's mailbox, which no agent credential touches); keep the copy
  alive past the certificate's life without renewing, and renewing
  collides with the real node; or make a second, independent identity
  from the copy.
- **Cannot be told apart, and is deliberately not claimed:** an
  attacker who also controls the host, stops the real agent, and runs
  the copy from the same address with the same build. That is a
  compromised host running what looks like its own agent; only a
  hardware root of trust could distinguish it, and this project does
  not require one (options considered). For a honeypot the alarm has
  already sounded on the way in -- every touch of its services is an
  event, and its going `silent` while the intruder works is itself a
  red tile; for a scanner the loss is one host's findings, which the
  attacker already owns by owning the host. Both are bounded to that
  one node.

## Security analysis

- **Threat model, proof.** A compromised or impersonated scanner holds
  a scanner-kind credential, for as long as Part B lets it. The proof
  does not defend against an agent that lies -- neither does the
  honeypot's, whose `portscan` claim is the agent's word -- and does not
  try to: a forged `ok` snapshot with a valid `run_id` buys the attacker
  a node marked registered that they could already post snapshots as,
  and Part B is what bounds that credential's life and makes its dual
  use visible. What the proof defends against is the honest failure
  class (#116's actual bug) and the cheap dishonest ones: replaying an
  old snapshot (spent or stale `run_id` never settles), answering with
  pre-recorded output (`taken_at` before `issued_at`), a "clean" result
  from an engine that did not run (`status: failed`, the missing
  fresh-refresh and the stale-database bound never pass), and a scan
  through an uncovered mount (`masked_paths` must be complete).
- **Threat model, database refresh (decision 10).** A lying agent can
  claim a refresh it did not do; birdcage cannot check Grype's mirror
  from the agent's side, so `db_refreshed_at` is the agent's word like
  every engine field, bounded by the server-side `db_built_at` cap. A
  failing mirror is not an attack, but an attacker who can block the
  scanner's egress can freeze its database; decision 10 makes that
  visible in one heartbeat and a red state at 24 hours, rather than
  the silent staleness Grype's defaults allow today. The
  `failing_since` clock is birdcage's, so the agent's clock cannot
  move the flag.
- **Threat model, credentials (Part B).** The attacker holds a copy of
  one node's key, certificate and token. Bounded by expiry (7 days),
  collision (one-way renewal), detection (dual use within 60 seconds)
  and revocation (one action, both holders). The residual -- attacker
  owns the host and replaces the agent in place -- is named above and
  accepted. Birdcage's own compromise no longer yields agent keys (B1);
  it still yields the ability to mint commands and read everything,
  which #32's threat model already states and ADR-0006/0007 bound.
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
  this node's or not open: ignored, audited. Refresh failed: the scan
  runs only while Grype's own age cap allows, the snapshot carries the
  error, an ordered run never passes on it, and 24 hours of it is a red
  state. Certificate not on record or revoked, or token under the wrong
  certificate: `401`, audited (Part B).
- **Cost of a pending scanner:** one full host scan every 30 minutes
  until a pass. Cost of an admin: one per node per five minutes, at
  most. Both bounded by guards, not by trust.
- **Deliberately not done.** No host-content evidence (a distro name,
  a package count) in the pass condition: the mount check already
  fails an unmounted `/host`, and the e2e fixture and some hosts carry no
  `os-release`. No automatic re-proof after registration. No
  agent-chosen anything. No sudo window. No cancel button: the cap ends
  a run, and a cancel is a second admin action to secure for no gain. No
  manual scan without a session. No TPM requirement and no automatic
  revocation on conflict (Part B, options considered). No scan
  suppression while a refresh is failing under Grype's own cap. No
  scanner-side 24-hour judgement: birdcage's clock decides.

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
  to. #8 is deferred to M3, and the manual scan waits with it (owner,
  2026-09-24); decision 8 is the design gauntlet's birdcage wiring
  must satisfy when it lands.
- The daily self-test stays a honeypot concept. Nothing schedules
  scanner runs after registration; only an admin orders one.
- Every scan now begins with a network round trip to Grype's database
  mirror, and a scanner without egress to it is visibly degraded from
  its first failed refresh and red after a day. That is the owner's
  intent: a scanner on a stale database is a scanner giving wrong
  answers, and it should look like one.
- Part B changes enrolment for every kind: the provision response no
  longer carries a private key, certificates last a week instead of a
  year, and every node enrolled before it ships needs re-enrolling
  once (the same one-time cost ADR-0011 decision 5 took, for the same
  reason: nothing renews the old certificates, so there is no grace to
  give). #72 closes with it. `docs/enrolment.md` and `SECURITY.md`
  describe the new model, including what a copied key can and cannot
  do, in the words of Part B.
- Decision 8's grant is bound to an `action` so that `canary.revoke`
  (B5) and any later admin action reuse it unchanged.

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
      `scan_snapshots.self_test_run_id TEXT NULL`,
      `scan_snapshots.db_refreshed_at TEXT NULL`,
      `scan_snapshots.db_refresh_error TEXT NULL`; `self_test_runs`
      gains `trigger TEXT NOT NULL DEFAULT 'proof'`, `stage TEXT NULL`,
      `stage_at TEXT NULL`; `canaries` gains `db_refresh_failing_since
      TEXT NULL`, `db_refresh_error TEXT NULL`.
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
      *struct{RunID, Stage}` and `DBRefresh *struct{LastOKAt,
      FailingSince, LastError}` (scanner kind only; `400` from any
      other); closed stage vocabulary; calls `AdvanceRunStage`; writes
      the `db_refresh_*` columns, clearing them on a heartbeat without
      the field; audit `selftest.stage_stale` through the coalescer.
- [ ] `internal/ingest/scans.go`: `RunID string json:"run_id,omitempty"`;
      `Engine.DBRefreshedAt`, `Engine.DBRefreshError`; decision 4's
      checks -- fresh refresh (`db_refreshed_at >= issued_at`), the
      five-day `db_built_at` bound, complete masks; sets `answered`;
      audit actions `selftest.run_unknown` (refusal) and
      `selftest.run_stale`, both through the coalescer.
- [ ] `internal/store/health.go` / `selftest.go` (`applySelfTestState`):
      for a scanner, `self_test_failed` clears when a later `ok`
      snapshot exists. New state `db_stale` when
      `db_refresh_failing_since` is more than 24 hours before
      birdcage's now, ranked between `self_test_failed` and
      `throttled`; recorded by #56's period writer like every state.
      Stage and `stage_at` on the canary read model. Runs list query
      (`ListScannerRuns`) for the canary page: trigger, issued, ended,
      verdict, last stage, reason, snapshot id -- never the run id.
- [ ] `cmd/nightjar/command.go` (new): jittered poll of
      `/ingest/commands`, modelled on `cmd/mockingbird/command.go`; a
      `scan` command triggers one immediate scan tagged with `run_id`;
      the scan loop serialises ordered and timer scans; unknown command
      kinds logged and skipped. `client.Snapshot` gains `RunID`.
- [ ] `cmd/nightjar/scanner.go` + `internal/scan`: `grype db update`
      as its own step before every scan, timer or ordered, with the
      scan itself run under `GRYPE_DB_AUTO_UPDATE=false`; on success
      write `db-refreshed-at` to the state directory, on failure keep
      `db-refresh-failing-since` (first failure since the last success)
      and the error text; both go on the snapshot's `engine` and on
      every heartbeat while failing. An ordered scan reports
      `mounts_checked`, `db_refreshed`, `scanning` through the heartbeat
      sender (`client.CommonHeartbeat` gains `Run` and `DBRefresh`),
      immediately on each.
- [ ] `scripts/agent-deps-check.sh`: confirm the new file imports nothing
      forbidden (it must not import `internal/store` for the command
      kind string -- duplicate the constant as mockingbird does).
- [ ] `internal/api` + `frontend/src/lib/sentence/tileStatus.ts`: the
      `pending` sentence carries stage and minutes; `self_test_failed`
      names the `scan` target and last stage; `db_stale` sentence with
      the hours; no run id in any API response. Canary page for a
      scanner: stage timeline of the open run, the Runs list (decision
      11), "database refresh failing since" from the first failure,
      beside #56's state history and the snapshot list.
- [ ] `docs/enrolment.md`: replace the "no self-test yet" paragraph;
      add pending, the stage table, self-test failed and the database
      refresh rule (refreshed before every scan; failing shows at once,
      red after a day; stops at five days) to the Nightjar section.
- [ ] Unit tests: `Provision` pending for scanner; mint and match
      (pass, failed status, stale db, refresh not fresh -> stored not
      passed with reason `db_refresh_failed`, incomplete masks,
      `taken_at` before `issued_at`, spent run, expired run, wrong node
      -> 400; manual pass never calls `SettlePending`); mint refused
      while a run is open; stage advance (forward only, wrong node,
      closed run, unknown string); scheduler retry mints for a pending
      scanner and respects the 30-minute cap; sweep keeps the last
      stage; handler `run_id`, heartbeat `run` and `db_refresh` paths
      (non-scanner kind -> 400); `db_stale` at 24h by birdcage's clock,
      not the agent's `failing_since`, and clearing; state period rows
      written for `self_test_failed` and `db_stale`; nightjar poll
      claims `scan` and ignores `selftest`; nightjar emits the three
      stages in order; nightjar scans on a failed refresh under the cap
      and carries the error, and persists `failing_since` across a
      restart.
- [ ] Live journey, `scripts/e2e/scanner.sh`: after enrol, node reads
      `pending`; assert the stage sequence advances through `collected`
      and at least `scanning` on the read model; poll until `ok` (bound 5
      minutes -- the runner's Grype database volume is warm, #108);
      assert the newest snapshot carries `self_test_run_id` and a
      `db_refreshed_at` after the run was issued. Leg 2 (dropped mask
      flag) now also asserts `self_test_failed` with last stage
      `collected` and a `pending` node, never `ok`, and that the failed
      run is in the Runs list after the node later passes. Leg 4
      (mirror unreachable: point `GRYPE_DB_UPDATE_URL` at a closed port)
      asserts a `status: ok` snapshot carrying `db_refresh_error`, the
      heartbeat's `db_refresh` on the read model, and -- with
      `failing_since` set back 25 hours in the store by the test, since
      the journey cannot wait a day -- the `db_stale` state and its
      period row. Runs at both hops (`docs/ci-hops.md`), Postgres
      included.

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
- [ ] `internal/api/canary_revoke.go` (new): `POST
      /api/canaries/{id}/revoke` `{grant}`, action `canary.revoke`,
      calling Part B's `RevokeCanaryCredentials`; the grant helper is
      shared with the scan route, keyed on `action`.
- [ ] Audit: `auth.reauth_ok`, `auth.reauth_failed`,
      `auth.reauth_lockout`, `canary.scan_ordered`, `canary.scan_refused`,
      `canary.revoked`.
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

**Issue #130: "Agent credentials: agent-made keys,
seven-day certificates with renewal, cert-bound tokens, conflict
detection, one-action revocation" -- Part B.** Scope, one paragraph:
`POST /enrol/provision` takes a CSR and `IssueClient` becomes
`SignClient` with the subject rewritten from the registry;
`clientCertTTL` becomes seven days and both agents renew from half-life
over a new `POST /ingest/renew` (kinds `{Honeypot, Scanner}`), one-way
like token rotation; a `client_certs` table records every issued
certificate and the auth path refuses any fingerprint not live on it;
`canary_tokens.cert_fingerprint` binds each token to a certificate;
`ingest.cert_conflict`, `ingest.credential_dual_use` and the
`credential_conflict` and `renewal_stalled` states, all through #56's
period writer; `birdcage canary revoke` takes a canary id and revokes
everything for it; a second enrolment under an existing name is a new
node. Live journeys: enrol with a CSR and prove the provision response
carries no key; renew and prove the old certificate is refused after
the new one's first use; present a copied credential from a second
container and prove `credential_conflict` within 60 seconds and `401`
for both after revoke; expire a certificate (TTL overridden to minutes
in the fixture) and prove `renewal_stalled` then `not_delivering`.
Every node enrolled before it needs re-enrolling once; `docs/enrolment.md`
and `SECURITY.md` updated. Answers #72 and lands before MR 1 or
alongside it, so the proof is built once against the final credential
model; the owner put it in M1 on 2026-09-24. Filed as #130.

## Open questions for the owner

None; all settled by the owner on 2026-09-24:
- #8 (dashboard authentication) stays in M3, and MR 2 (the manual scan,
  #129) waits for it -- "Not everything needs to be in m1."
- Part B goes in M1, beside MR 1 (#130), so no node re-enrols after the
  first release; #72 moved to M1 with it.
