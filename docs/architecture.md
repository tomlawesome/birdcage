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
    mikroview["mikroview (sidecar)"]
    idp["OIDC provider (Authentik)"]

    canary1 -->|"syslog"| birdcage
    canary2 -->|"syslog"| birdcage
    canaryN -->|"syslog"| birdcage
    birdcage <-->|"SQL"| db
    browser <-->|"HTTPS"| birdcage
    birdcage <-->|"REST, Go client SDKs"| crowdsec
    birdcage -->|"REST API"| routeros
    birdcage -->|"read-only API token, lookback query"| mikroview
    browser <-->|"OIDC"| idp
    birdcage <-->|"OIDC"| idp
```

Each OpenCanary instance pushes its own hits via syslog (its native
`SyslogLogger` output) -- birdcage never polls, since OpenCanary has no
query API. See [issue #1](https://github.com/tomlawesome/birdcage/issues/1)
for how nodes get configured to point at their birdcage instance at
install time.

## Application boundaries

| Boundary | Responsibility | Status |
| --- | --- | --- |
| Ingestion bridge | Parse OpenCanary syslog output, normalize into `alerts` | Not yet implemented -- [#2](https://github.com/tomlawesome/birdcage/issues/2) |
| Storage | Persist alerts and the audit log (SQLite and Postgres, both mandatory in v1, selected by `DATABASE_URL`) | Landed with #2/#7; see [ADR-0001](adr/0001-stack-and-storage.md) and [docs/configuration.md](configuration.md) |
| Dashboard | Multi-instance alert view, filtering | API landed (#3); UI pending |
| Analysis | Turn raw alert volume into an actionable signal | Not yet defined -- [#6](https://github.com/tomlawesome/birdcage/issues/6) |
| CrowdSec integration | Query/act on CrowdSec decisions via official Go SDKs | Not yet implemented -- [#4](https://github.com/tomlawesome/birdcage/issues/4) |
| RouterOS mitigation | Apply firewall/address-list changes via a service account | Not yet implemented -- [#5](https://github.com/tomlawesome/birdcage/issues/5) |
| Audit log | Append-only record of every automated action taken | Required for v1; write path lands alongside #4/#5 |
| Auth | Local accounts, OIDC, sessions, API/ingest tokens -- copied model from mikroview | Not yet implemented -- [#8](https://github.com/tomlawesome/birdcage/issues/8); see [ADR-0003](adr/0003-mikroview-sidecar.md) |

## Data model (planned)

Two tables, both designed alongside the ingestion bridge issue (#2) rather
than fixed in advance of it:

- **`alerts`**: `instance_id`, `source_ip`, `dest_port`, `service`, `raw`,
  `received_at`. One row per OpenCanary hit.
- **`audit_log`**: `action`, `target`, `reason`, `triggered_by`,
  `created_at`. One row per automated action birdcage takes. Append-only by
  convention -- the application layer must never issue `UPDATE`/`DELETE`
  against it.

Accounts, sessions and tokens follow mikroview's shapes (ADR-0003); their
storage is designed with #8.

## Deployment and branching

See [ADR-0002](adr/0002-gitflow-branching.md) for the `dev` -> `preview` ->
`main` branch/promotion model, and mikroview's `Dockerfile`
(`tomlawesome/mikroview`) for the distroless multi-stage container pattern
birdcage's own `Dockerfile` is expected to follow once implementation
starts. Birdcage is deployed in the same compose stack as mikroview --
see [ADR-0003](adr/0003-mikroview-sidecar.md).
