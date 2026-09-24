# ADR-0012: A scanner proves its enrolment by answering an ordered scan, over the same road as a honeypot's self-test

**Status:** Proposed (owner review pending)
**Date:** 2026-09-24
**Relates to:** #116 (this proof), #47 (enrolment; pending until the first
self-test passes), #46 (self-test), #45 (canary health states), #105,
#108 (Nightjar slice 1), ADR-0009, ADR-0010, ADR-0011.

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

## Research

Done before the design, per `docs/security-by-design.md`. Reproduced
means read from the authoritative record (the GitHub Advisory Database
via its API, or the vendor's own text); a lead is something secondary
coverage reported that could not be reproduced and is not relied on.

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

What the research changed: the target. The issue's candidate (a scan of
birdcage's address or an operator-chosen host) is dropped, because the
agent cannot do it and should not be taught to. The proof becomes the
scanner's ordinary work, ordered by birdcage.

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

   - **Window and cadence: 30 minutes for a scanner**, against the
     honeypot's 10 (`selfTestWindow`). A first run can include Grype's
     cold database download (roughly a gigabyte, `docs/enrolment.md`).
     The pending-retry guard equals the window, so at most one run is
     open per scanner and a silent scanner is re-ordered every 30
     minutes until one passes. A snapshot answering a failed status
     closes the run at once, so a broken mount shows within a minute,
     not thirty.

**4. `POST /ingest/scans` takes an optional `run_id`.** Absent, the
snapshot is an ordinary timer scan, exactly as today. Present, the
handler resolves the run and settles the proof, all inside the
snapshot's own transaction:

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
     `hostmask.Masks` set: the run passes, `SettlePending` fires.
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
states: `pending` until the first ordered scan passes; `self_test_failed`
naming the `scan` target when a run fails or expires, with the failure
reason readable on the newest snapshot in `GET /api/scans`. Registered
scanners never re-run the proof: the daily self-test schedule remains
honeypot-only (`ListHoneypotCanariesForSelfTest`), because a scanner's
six-hourly snapshot is already its ongoing liveness signal.

## Security analysis

- **Threat model.** A compromised or impersonated scanner holds a
  scanner-kind credential. The proof does not defend against an agent
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
- **No credential widens.** The command route is claim-only and per
  node; a scanner sees its own commands and nothing about any other
  node. ADR-0011's kind checks apply unchanged. A honeypot credential
  still cannot reach `/ingest/scans`.
- **The run id is not a secret**, but it is treated as one where it
  costs nothing (Fleet's oracle): it is never exposed on `/api`, and a
  run's `run_id` is only ever sent to the node it was minted for.
- **Fail closed, every path.** Unknown run: refused, nothing stored.
  Spent or expired run: stored, never a pass. Failed status: run fails
  immediately, reason kept. Nothing arrives: sweep fails the run at the
  deadline, retry re-mints. Unknown kind at mint time: error, node stays
  pending, which is loud rather than silent.
- **Cost of a pending scanner:** one full host scan every 30 minutes
  until a pass. Bounded by the guard; not a flood.
- **Deliberately not done.** No host-content evidence (a distro name,
  a package count) in the pass condition: the mount check already
  fails an unmounted `/host`, and the e2e fixture and some hosts carry no
  `os-release`. No re-proof after registration. No agent-chosen
  anything.

## Consequences

- Every scanner enrolled before this ships is already registered and is
  unaffected; new scanners show `pending` for a minute or two, or
  longer on a first cold database download.
- `docs/enrolment.md`'s "A scanner has no self-test yet" paragraph is
  replaced by the scanner's proof, and its `--kind scanner` section says
  what pending and self-test failed mean for it.
- Nightjar gains one loop (the command poll). #113's image scanning and
  any future "scan now" button inherit an order road that already
  exists.
- The daily self-test stays a honeypot concept. Nothing here schedules
  scanner runs after registration.

## Implementation outline

One MR, with the live journey (AGENTS.md: a change to enrolment lands
with its journey). Commit messages `Refs #116`.

- [ ] `internal/store/command.go` (or wherever `CommandSelfTest` lives):
      add `CommandScan = "scan"`; params `{run_id}` only.
- [ ] `internal/store/selftest.go`: `MintScanProofCommand(ctx, db, canaryID,
      now, deadline)` -- one transaction: `canary_commands`,
      `self_test_runs`, one `self_test_targets` row (`service = "scan"`,
      `dest_port = 0`, empty marker hash, grade as `gradeForService`
      decides). Add `MatchScanProof(ctx, tx, canaryID, runID, takenAt,
      snapshot)` returning pass / fail / stale / unknown, calling
      `recordSelfTestMatch`-equivalent completion and `SettlePending`.
- [ ] Migration `0021_scan_snapshot_self_test_run.sql` (sqlite and
      postgres): `ALTER TABLE scan_snapshots ADD COLUMN self_test_run_id
      TEXT NULL`.
- [ ] `internal/store/provision.go:186`: `Pending: true`.
- [ ] `internal/selftestsched/scheduler.go`: `scanProofWindow = 30m`;
      `mintForCanary` branches on `c.Kind`; `retryPending` lists pending
      nodes of every kind (new `ListPendingCanaries` or widen the
      existing query); unknown kind logs an error and mints nothing.
      `FirstContact` unchanged in shape.
- [ ] `internal/ingest/http.go:104`: `/ingest/commands` kinds
      `{Honeypot, Scanner}`. `handleCommands`: a scanner may claim only
      `scan` commands (kind-to-command allow-list, fail closed).
- [ ] `internal/ingest/scans.go`: `RunID string json:"run_id,omitempty"`;
      decision 4's checks and the five-day `db_built_at` bound; audit
      actions `selftest.run_unknown` (refusal) and `selftest.run_stale`,
      both through the coalescer.
- [ ] `cmd/nightjar/command.go` (new): jittered poll of
      `/ingest/commands`, modelled on `cmd/mockingbird/command.go`; a
      `scan` command triggers one immediate scan tagged with `run_id`;
      the scan loop serialises ordered and timer scans; unknown command
      kinds logged and skipped. `client.Snapshot` gains `RunID`.
- [ ] `scripts/agent-deps-check.sh`: confirm the new file imports nothing
      forbidden (it must not import `internal/store` for the command
      kind string -- duplicate the constant as mockingbird does).
- [ ] `internal/api` + `frontend/src/lib/sentence/tileStatus.ts`: the
      `pending` and `self_test_failed` sentences read correctly for a
      scanner (`scan` target); no run id in any API response.
- [ ] `docs/enrolment.md`: replace the "no self-test yet" paragraph;
      add pending / self-test failed to the Nightjar section.
- [ ] Unit tests: `Provision` pending for scanner; mint and match
      (pass, failed status, stale db, incomplete masks, `taken_at`
      before `issued_at`, spent run, expired run, wrong node -> 400);
      scheduler retry mints for a pending scanner and respects the
      30-minute guard; handler `run_id` paths; nightjar poll claims
      `scan` and ignores `selftest`.
- [ ] Live journey, `scripts/e2e/scanner.sh`: after enrol, node reads
      `pending`; poll until `ok` (bound 5 minutes -- the runner's Grype
      database volume is warm, #108); assert the newest snapshot carries
      `self_test_run_id`. Leg 2 (dropped mask flag) now also asserts
      `self_test_failed` and a `pending` node, never `ok`. Runs at both
      hops (`docs/ci-hops.md`), Postgres included.

## Open questions for the owner

- The 30-minute window for a scanner run against the honeypot's 10: is
  a slower first verdict acceptable for the sake of a cold database
  download, or should the window be 10 with the first cold fetch left
  to fail and retry?
- Whether to keep the daily self-test honeypot-only (decision 6) or
  also re-order a scan when a scanner has missed its interval -- not
  needed for #116 and left out here.
