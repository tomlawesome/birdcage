# Birdcage architecture

## System context

```mermaid
flowchart LR
    canary1["OpenCanary node A"]
    canary2["OpenCanary node B"]
    canaryN["OpenCanary node N..."]
    birdcage["Birdcage application"]
    db[("SQLite or Postgres")]
    browser["Browser dashboard"]
    crowdsec["CrowdSec LAPI"]
    routeros["RouterOS (service account)"]
    mikroview["mikroview (separate app)"]
    idp["OIDC provider (Authentik)"]

    canary1 -->|"HTTPS (agent, #48)"| birdcage
    canary2 -->|"HTTPS (agent, #48)"| birdcage
    canaryN -->|"HTTPS (agent, #48)"| birdcage
    birdcage <-->|"SQL"| db
    browser <-->|"HTTPS"| birdcage
    birdcage <-->|"REST, Go client SDKs"| crowdsec
    birdcage -->|"REST API"| routeros
    birdcage -->|"read-only API token, lookback query"| mikroview
    browser <-->|"OIDC"| idp
    birdcage <-->|"OIDC"| idp
```

Each OpenCanary instance's own agent (#48, not yet landed) tails its
node's syslog-formatted OpenCanary output locally and posts batches of
events to birdcage's HTTPS ingest listener (issue #32, landed), bearer-
token authenticated per canary -- birdcage never polls, since OpenCanary
has no query API. See [issue #1](https://gitlab.tomlawson.io/ai/birdcage/-/issues/1)
for how nodes get configured to point at their birdcage instance at
install time.

## Application boundaries

| Boundary | Responsibility | Status |
| --- | --- | --- |
| Ingestion bridge | HTTPS listener authenticating a canary's agent by bearer token, normalizing posted batches into `alerts` | Landed (#32); the canary-side agent that posts to it is [#48](https://gitlab.tomlawson.io/ai/birdcage/-/issues/48), not yet implemented |
| Storage | Persist alerts and the audit log (SQLite and Postgres, both mandatory in v1, selected by `DATABASE_URL`) | Landed with #2/#7; see [ADR-0001](adr/0001-stack-and-storage.md) and [docs/configuration.md](configuration.md) |
| Dashboard | Multi-instance alert view, filtering, canary registry/heartbeats, visitors grouped by source and the trace | API landed (#3, #34, #35); UI pending |
| Analysis | Turn raw alert volume into an actionable signal | Not yet defined -- [#6](https://gitlab.tomlawson.io/ai/birdcage/-/issues/6) |
| CrowdSec integration | Query/act on CrowdSec decisions via official Go SDKs | Not yet implemented -- [#4](https://gitlab.tomlawson.io/ai/birdcage/-/issues/4) |
| RouterOS mitigation | Apply firewall/address-list changes via a service account | Not yet implemented -- [#5](https://gitlab.tomlawson.io/ai/birdcage/-/issues/5) |
| Audit log | Append-only record of every automated action taken | Required for v1; write path lands alongside #4/#5 |
| Auth | Local accounts, OIDC, sessions, API/ingest tokens -- copied model from mikroview | Not yet implemented -- [#8](https://gitlab.tomlawson.io/ai/birdcage/-/issues/8); see [ADR-0003](adr/0003-mikroview-sidecar.md) |

## Data model

Tables designed alongside the issue that needed them, rather than fixed in
advance:

- **`alerts`**: `instance_id`, `source_ip`, `dest_port`, `service`, `raw`,
  `received_at`. One row per OpenCanary hit (#2).
- **`audit_log`**: `action`, `target`, `reason`, `triggered_by`,
  `created_at`. One row per automated action birdcage takes. Append-only by
  convention and by a database trigger -- the application layer must never
  issue `UPDATE`/`DELETE` against it.
- **`agents`**: the registry of enrolled nodes (#34; renamed from
  `canaries` in #107 once ADR-0009 gave a node a kind -- a canary is one
  kind, not the category) -- `id` (the same value `alerts.instance_id`
  carries), `name`, `lane`, `kind`, `ports`, `heartbeat_interval_s`,
  `enrolled_at`, `last_heartbeat_at`.
- **`heartbeats`**: `agent_id`, `at`. One row per phone-home
  (`POST /api/heartbeat`), pruned to the last 24h on insert (#34).

Accounts, sessions and tokens follow mikroview's shapes (ADR-0003); their
storage is designed with #8.

## Deployment and branching

See [ADR-0002](adr/0002-gitflow-branching.md) for the `dev` -> `preview` ->
`main` branch/promotion model, and mikroview's `Dockerfile`
(`tomlawesome/mikroview`) for the distroless multi-stage container pattern
birdcage's own `Dockerfile` is expected to follow once implementation
starts. Birdcage ships as two container images of its own -- Birdcage and
Mockingbird -- and is deployed independently of mikroview, not in its
compose stack; see
[ADR-0008](adr/0008-container-only-distribution-and-two-images.md).
