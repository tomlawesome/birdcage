# ADR-0011: A client certificate's subject OU carries the agent's kind, and every ingest route authorises on it

**Status:** Accepted
**Date:** 2026-09-23
**Relates to:** #106, ADR-0009 decision 3 ("the kind lives in the client
certificate, and is authorised on"), ADR-0010, #72 (client certificate
renewal is not designed yet), #47 (enrolment and the CA).

## Context

ADR-0009 decided that an agent's kind must live in its client
certificate and be authorised on at every ingest route, so that a
honeypot's credential cannot post vulnerability findings and a
scanner's cannot post honeypot alerts. It did not settle where in the
certificate the kind goes, what "authorised" means precisely, or what
happens to the certificates every already-enrolled node already holds,
none of which carry a kind at all. Issue #106 settled those questions;
this ADR records the settlement.

## Decision

**1. The kind lives in the subject's OrganizationalUnit, exactly one
value.** `internal/ca.CA.IssueClient` takes the agent's kind and sets
`Subject.OrganizationalUnit = []string{string(kind)}` alongside the
existing `CommonName` (the canary id). Not a SAN URI, not a custom
extension: the kind is one word from a closed, registered set
(`internal/agentkind`), OU holds it with no parsing, it sits beside the
existing CommonName convention on the same subject, and it stays
visible to `openssl x509 -text` and to the live e2e journey, unlike a
custom extension would.

The CA/Browser Forum's ballot SC47 deprecated OU only in *publicly
trusted* certificates, because a public CA cannot verify a subscriber's
own OU value. That reasoning does not reach a private CA writing its
own authorisation attribute into certificates only it issues and only
it verifies -- birdcage's own position, and Kubernetes' client-certificate
authentication's as well (subject CN = user, O = groups, from its own
private CA).

There is no kindless overload of `IssueClient`. Every issuance path
states a kind, mechanically, by the function's signature -- not by a
convention a future caller could forget.

**2. A certificate carries a kind only if OU has exactly one value, and
that value is registered.** Zero values (every certificate issued before
this change), more than one, or a string `agentkind.Valid` rejects, all
refuse. Never a "contains" check over the slice.

**3. Every ingest route is authorised on kind, in two checks.** The
route table (`internal/ingest/http.go`'s `ingestRoute`) is the only way
a handler is registered on the ingest mux, and its zero value for
`kinds` refuses every request -- a route added without declaring its
kinds fails closed by construction. Two checks, both must pass:

   - **Registry**: the canary's kind, resolved from the database by the
     same token lookup that resolves identity, must be in the route's
     allowed set. Runs on every request, including the one exemption
     `requireBearerToken` grants plain (non-TLS) test requests for
     certificate carriage -- the registry check is never inside that
     exemption, so it can never become an authorisation hole for it.
   - **Certificate**: when a real client certificate is presented, its
     OU (checked per decision 2) must equal the registry's own kind --
     not merely "an allowed kind for this route". A tampered registry
     row disagreeing with the immutable certificate refuses even when
     each alone might look fine; a stolen credential is bounded by the
     kind baked into it at issuance.

**4. A kind refusal is 403, never 401.** `{"error":"forbidden"}`,
deliberately distinct from the uniform 401 issue #32 established for a
missing, unknown or revoked token. A 401 is permanent to the agent and
drives it toward re-enrolment; a kind refusal means "this credential is
fine, this route is not yours", and an agent must not respond to that by
churning credentials. Two audit actions record it, both through the
existing coalescer so a caller holding a valid-but-wrong-kind credential
cannot turn a stream of correctly-refused requests into an audit-log
flood: `ingest.kind_refused` (decision 3's registry check) and
`ingest.kind_mismatch` (decision 3's certificate check).

**5. Migration: force re-enrolment, not a grandfather clause.**
Every certificate issued before this change carries no OU at all and is
refused at every ingest route the moment this ships. The alternative --
treat an unmarked certificate as its old kind until it next renews -- is
rejected, because #72 records that nothing renews a client certificate
today: "until it renews" would be a permanent bypass. An unmarked
certificate is also, by definition, exactly the credential the threat
model assumes an attacker might hold (any node that predates this
change never proved its kind to begin with), so treating it as
trustworthy-until-proven-otherwise is the wrong default. The recovery is
the same one every dead credential already has: `birdcage canary enrol`
and the printed run command. The refusal is loud, not silent -- the
audit entries in decision 4, plus #45's existing "not delivering" state.

## Consequences

- A node enrolled before this change stops working at every ingest
  route the moment it ships, and needs re-enrolling. At 0.1.0-beta with
  no announced release, this is an accepted, one-time cost, not an
  ongoing migration path.
- Any future certificate-renewal design (#72) inherits a constraint:
  a renewal must reissue with the same kind, read from the canaries row,
  never from anything the agent itself sends -- `IssueClient`'s signature
  enforces this mechanically, since every caller must state a kind and
  there is no kindless variant to reach for instead. A registered kind's
  string is therefore frozen for at least the lifetime of the
  longest-lived issued certificate (a year, today): renaming one while
  its certificates are still live would refuse the whole fleet of that
  kind.
- `/ingest/heartbeat` gained a per-kind body split in the same delivery
  (issue #106, commit 3): Honeypot keeps its original log-tailer shape,
  every other kind sends a common-only shape (agent version, nothing
  else). This ADR does not restate that split's own reasoning --
  ADR-0009's own "the small common part is shared" already states it --
  beyond noting that the certificate-kind check above is what makes the
  split's body-shape choice enforceable at all: without it, nothing
  stopped a certificate of any kind claiming any shape.
- No new dependency: everything here is stdlib `crypto/x509`.
