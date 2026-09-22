# ADR-0009: Birdcage is the control plane for a fleet of agents, and an agent has a kind

**Status:** Accepted
**Date:** 2026-09-22
**Relates to:** #47 (enrolment), #48 (the agent as a deliverable),
#32 (ingest transport), #102 (host port reporting), #103 (host firewall),
ADR-0001, ADR-0005, ADR-0006.
**Amends:** ADR-0008, decision 2 ("two images, not one") and decision 4
(the image-boundary check). The rest of ADR-0008 stands, and its
reasoning is the reason this ADR exists.

## Context

The owner settled on 2026-09-22 that a second kind of deployed agent --
a vulnerability scanner, ADR-0010 -- belongs inside birdcage rather than
in a new project: "I don't want a sprawling mass of projects. So I think
it makes most sense to expand birdcage as its early into development."

That decision is cheap to act on and expensive to defer, because
birdcage does not currently have a fleet model. It has a *canary* model,
and "canary" is load-bearing in five places:

- `canaries` and `enrolment_sessions` carry no kind or role column
  (`internal/db/migrations/sqlite/0003_canaries.sql`,
  `0009_enrolment_sessions.sql`), in both the SQLite and Postgres
  schemas.
- A client certificate's subject is the canary ID and nothing else
  (`internal/ca/ca.go:374`). Nothing authorises on it --
  `internal/ca/ca.go:45-48` says so explicitly.
- `POST /ingest/events` takes an OpenCanary-shaped body mirroring
  `store.AlertInsert` (`internal/ingest/batch.go:41-50`), and
  `/ingest/heartbeat` takes log-tailer fields
  (`internal/ingest/heartbeat.go:26-40`).
- `internal/enrol/provision.go:30` writes `MockingbirdPorts`, a fixed
  OpenCanary port list, into every node it provisions, whatever is
  actually running there.
- The CLI noun is `canary` (`cmd/birdcage/main.go:195-291`). There is no
  `agent`, `node` or `fleet` noun.

Ten migrations is a cheap rename. Fifty is not.

## Decision

1. **Birdcage is the control plane for a fleet of security agents.**
   Honeypots are the first kind of agent, not the only kind. This is a
   statement about birdcage's internal model, not an invitation to
   absorb arbitrary tooling: ADR-0010 states the bar a new kind has to
   clear.

2. **Every enrolled node carries a kind**, chosen at enrolment and fixed
   for the life of that node's identity. A kind column lands on the node
   registry and on enrolment sessions, in both schemas. Changing kind
   means enrolling a new node.

3. **The kind lives in the client certificate, and is authorised on.**
   Each ingest route declares which kinds may post to it, and a
   certificate that does not carry a permitted kind is refused. A
   honeypot cannot post vulnerability findings; a scanner cannot post
   honeypot alerts.

   This is the security point of the whole ADR, and it is why the kind
   goes in the certificate rather than in a request field. A mockingbird
   node is *deliberately* exposed to attack -- that is its job. Its
   credential must therefore buy an attacker nothing beyond what a
   honeypot legitimately does. Today it would buy them the whole ingest
   surface, because nothing checks who is posting what.

4. **The noun becomes `agent`** in the schema, the CLI and the docs.
   `birdcage canary ...` stays as an alias so existing runbooks and
   muscle memory keep working.

5. **Provisioning is per kind.** The hardcoded `MockingbirdPorts` in
   `internal/enrol/provision.go` becomes a per-kind provisioning
   profile. A node's expected ports are a fact about its kind.

6. **The image-boundary check generalises.** ADR-0008 decision 4 -- no
   server package may reach the agent image, enforced by
   `scripts/agent-deps-check.sh` and the `lint:agent-deps` CI job
   (`docs/ci-hops.md:91`) -- runs once per agent image rather than once
   for mockingbird. Each kind declares its own allowed package set.

## Consequences

- **ADR-0008 decision 2 is amended, not overturned.** "Two images, not
  one" becomes "one server image, and one image per agent kind". The
  reasoning survives untouched, and in fact hardens: the owner's
  original justification was "the canary is an attack surface, it should
  be an isolated build with no birdcage code within it". That argument
  applies with more force to a privileged scanner, which reads the
  Docker socket and the host's package database. A scanner must never
  share an image with a decoy -- ADR-0010 restates this as a decision in
  its own right.
- The ingest routes stop being generically named for a single payload
  shape. `/ingest/events` remains the honeypot alert route; new kinds
  get their own routes with their own bodies, rather than a polymorphic
  envelope that every consumer has to unpick.
- Heartbeat fields are kind-specific, because
  `internal/ingest/heartbeat.go`'s current fields are log-tailer
  concepts. The small common part -- agent version, last contact -- is
  shared; the rest belongs to the kind.
- Existing deployments see a schema migration and a CLI alias. No
  operator-visible behaviour changes.
- **This ADR adds no agent kind.** It makes adding one possible. The
  first user is ADR-0010, and the work is scheduled before v1 on the
  owner's instruction ("Spine before v1", 2026-09-22) precisely because
  it gets more expensive the longer it waits.
- "Lane" is untouched. It is a free-text operator grouping
  (`cmd/birdcage/canary.go:282-312`), never validated and never used for
  authorisation, and kind is not a replacement for it: a lane says where
  a node sits, a kind says what it is.
