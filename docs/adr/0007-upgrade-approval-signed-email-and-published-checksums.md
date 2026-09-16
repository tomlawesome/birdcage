# ADR-0007: Agent upgrades need a DKIM-signed email from the admin and a published checksum

**Status:** Accepted
**Date:** 2026-09-16
**Relates to:** #54 (the design and everything rejected on the way),
#47 (enrolment pins the admin address and release address), #48 (the
agent verifies), #32 (the `upgrade` command kind), ADR-0006.

## Context

ADR-0006 removed the project's key from every deployment's trust path
and left open how an operator authorises an upgrade from off their own
infrastructure. The owner's constraints, all recorded on #54: nothing
to install or carry; no device credential; no key the project holds
for everyone; usable through the web UI; the real admin must be aware
and present before anything begins; a hacked birdcage must be unable to
install an agent of its choosing.

Every scheme that had the admin *make* a signature on purpose -- a
tool, a page, an extension, a hardware token -- failed one of those.
The admin already makes a signature every day without knowing: their
mail provider signs every email they send (DKIM) with a key published
in DNS.

## Decision

1. **An upgrade is approved by the admin replying to birdcage's summary
   email from the address pinned on every agent at enrolment.** The
   request reference is in the subject. Each agent verifies the reply's
   DKIM signature itself against the provider's DNS key, checks `From`,
   checks the reference, and rejects stale or reused messages. Birdcage
   carries the raw message; it cannot forge it.
2. **An agent installs only bytes whose SHA-256 appears in the
   `SHA256SUMS` published at the release address pinned at enrolment.**
   The bytes come from birdcage; the checksum file comes from the
   release address over HTTPS. Default is this project's releases; an
   operator may pin their own mirror or fork.
3. **Both are required, for local and SSO accounts alike.** No other
   approval path exists. Changing the pinned admin address is itself an
   approved action, verified against the old address.
4. **Loss is handled by re-enrolment**, not by recovery keys. Losing
   the mailbox for good means re-enrolling every agent.

## Consequences

- A hacked birdcage can neither start an upgrade nor substitute a
  build. A doctored summary can at most name a different published
  release, and agents refuse versions not newer than their own.
- Birdcage needs an inbound mailbox; agents need DNS and HTTPS egress;
  an admin whose mail server does not sign outgoing mail cannot approve
  upgrades. Setup must check this with a test approval.
- ADR-0006 decision (3) -- published checksums as *optional*
  verification material -- is amended: they are required for install.
  Decision (1), no vendor key in any trust path, is unchanged.
- `upgrade` stays unmintable (`store.CommandKind`, pinned by
  TestUpgradeCommandCannotBeMinted) until the agent's verify path is
  built and tested against real provider signatures.
- Per-canary credentials (token, mTLS certificate) are untouched; the
  admin's approval is never per canary.

## Superseded

Listed in full on #54. In short: project signing key; operator signing
key with recovery keys; secrets typed into birdcage; approve command,
off-box page, browser extension, phone app, SSH-key signing, per-canary
challenge emails, witness file; project key as a second lock; device
credentials; identity-provider token for SSO; per-agent approval keys.
