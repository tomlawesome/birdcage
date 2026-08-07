# Security by design

**Policy for mikroview, threadbeam and birdcage.**

Every new feature is **researched before it is designed** — not designed
and then reviewed. A security review at the end can only find flaws in
the architecture you already chose. Research done first changes which
architecture you choose, which is a different and much better outcome.

## What "researched" means here

Four things, all required, before an implementation plan is written.

### 1. Research first, plan second

The output of research is not a sign-off. It is expected to change the
design, and if it never does, the research wasn't real.

### 2. Search CVEs explicitly

For every component, protocol, library and pattern the feature touches.
Not a general "is this safe" — a specific search against NVD, GitHub
advisories, and the vendor's own security pages.

Read the **authoritative record**, not the summary. Secondary coverage of
a CVE is frequently wrong (see below).

### 3. Compare against known secure and insecure architectures

Find who has built this before and what went wrong for them. Both halves
matter: the insecure examples tell you which mistakes are easy to make,
and the secure ones tell you what the settled answer looks like.

### 4. Treat industry norms as direction, not proof

Best practice exists because it encodes hard-won experience, and it
should carry real weight in a decision. But it is a starting point to
verify, not a conclusion to accept. Norms go stale, get misremembered,
and get repeated long after they stopped being true.

## Why point 4 is not paranoia

Every one of these came out of applying this policy to a single planning
round, and every one would have produced a worse design if taken at face
value:

- **"lib/pq is deprecated, use pgx."** Repeated everywhere. No longer
  true — lib/pq was revived under a new maintainer with an active 2026
  release history. Still the right call to choose pgx, but not for that
  reason.
- **A CVE's press coverage contradicted its NVD record.** Widely-ranking
  articles described a RouterOS flaw as extracting WireGuard private
  keys from *low-privilege* API access. The NVD entry specifies
  `PR:H` — privileges required **high** — and never mentions WireGuard.
  Designing against the article would have chased a threat that does not
  exist while missing the real one.
- **`sslmode=require` is widely assumed to verify certificates.** It sets
  `InsecureSkipVerify = true`. Any self-signed certificate is accepted.
- **The obvious RouterOS choice is the wrong one.** The stock `read`
  group looks like the minimal read-only option and carries `sensitive`
  (unmasks private keys and PSKs) plus `sniff` (packet capture).
- **"Exclude credentials from backups" sounds safer.** It produces a
  backup that cannot restore a working system — a correctness failure
  discovered at disaster-recovery time, which is the worst possible
  moment.

## What this changes in practice

Applying the policy to one planning round produced these outcomes, none
of which a design-then-review process would have reached:

| Feature | Design before research | After |
|---|---|---|
| RouterOS integration | Pull, with a stored router credential and a sidecar to contain it | **Push** — the app holds no router credential at all, so the escalation path is removed rather than contained |
| Backup format | `tar.gz`, defended against traversal | **JSON envelope** — no filenames, typeflags or link entries, so the attack class cannot occur |
| VPN/VPS identification | Confidence signal | **Display-first** — the feed matches 10.58% of routable IPv4, so scoring on it is noise |
| Colocation on the router | Preferred deployment | **Removed** — grants no privileged API path, and converts credential theft into code execution on the router |

It also found a **live vulnerability in already-shipped code**: an
unauthenticated memory-exhaustion and brute-force bypass on login,
surfaced by research into a feature that had not been built yet.

## Minimum bar for a feature issue

Before implementation starts, the issue must record:

- the **threat model** — what an attacker gains if this component is
  compromised, stated concretely
- **CVEs and prior incidents** found, with links to the authoritative
  records
- **what the research changed** about the design, or an explicit note
  that it confirmed it
- **fail-closed behaviour** for every error path
- **what is deliberately not being done**, and why

Anything that turns out to be contested or uncertain is written down as
contested, not silently resolved in one direction.

## Verification standard

A finding is not acted on until it is reproduced. Research — including
research produced by an automated agent — is a lead, not a conclusion.
In the same planning round, agent reports contained a wrong Go toolchain
version, an inflated CVSS score, and a "check this" that turned out to be
already correct in our code. Each was caught by checking.

Where a fix is made, a test proves the flaw existed first.
