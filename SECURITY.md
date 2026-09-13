# Security policy

Birdcage is in early implementation (only the OpenCanary UDP syslog
ingestion bridge has landed; see [docs/v1-scope.md](docs/v1-scope.md)) --
this document describes the threat model and hardening it is designed
against, so that model is fixed before code lands rather than retrofitted
around whatever got built first. Update it as implementation reveals
details this can't predict yet.

## Threat model

Birdcage is meaningfully higher-stakes than a read-only tool: it will hold
live service-account credentials (CrowdSec, RouterOS) and, per
[ADR-0001](docs/adr/0001-stack-and-storage.md), is intended to take
automated mitigating action against real infrastructure. Compromise of
birdcage itself is not just an information leak -- it's a path to acting on
your network and firewall.

**Authentication is part of v1** (changed 2026-09-12,
[ADR-0003](docs/adr/0003-mikroview-sidecar.md)): local accounts and
self-hosted-only OIDC, following
[mikroview](https://github.com/tomlawesome/mikroview)'s model. Until
[#8](https://github.com/tomlawesome/birdcage/issues/8) lands, nothing gates
the dashboard, so the network-exposure guidance below is the only control.
This section is rewritten route-by-route when #8 lands.

## Data handling

- **Service-account credentials (CrowdSec, RouterOS) are secrets.** They
  must be supplied via environment variables or Docker/Compose secrets,
  never committed to a config file in the repo, and never logged --
  including in error messages or debug output. Treat a log line containing
  a bearer token or API key as a real leak, not a hypothetical one.
- **Alert and audit data is persisted**, unlike mikroview's in-memory-only
  model -- birdcage's whole purpose is centralized history across
  instances. SQLite and Postgres, both mandatory in v1, selected by
  `DATABASE_URL` (see [ADR-0001](docs/adr/0001-stack-and-storage.md) and
  [docs/configuration.md](docs/configuration.md)). Alert data (source IPs,
  timestamps, targeted services) is not highly sensitive on its own, but a
  SQLite database file should still be kept off any shared/multi-tenant
  filesystem, same guidance as mikroview's `config.yaml`, and a Postgres
  `DATABASE_URL` is itself a credential -- it carries a plaintext password --
  and must be handled with the same care as the CrowdSec/RouterOS secrets
  above (env var or secret, never committed, never logged).
- **The audit log is append-only by convention.** No application code path
  may issue `UPDATE`/`DELETE` against it. This is what makes "birdcage took
  automated action" reviewable and reversible rather than a black box --
  see [ADR-0001](docs/adr/0001-stack-and-storage.md).

## Network exposure

- **OpenCanary syslog ingestion — UDP, default `:5514`** (override with
  `BIRDCAGE_SYSLOG_ADDR`). **No authentication, no TLS.** OpenCanary
  instances push their hits here as plain UDP syslog datagrams, so anyone
  who can reach the port can inject forged alerts claiming any
  `instance_id`, at any volume. This listener stays unauthenticated
  regardless of the dashboard auth described above -- plain UDP syslog has
  no session to gate: it must be bound to a loopback or trusted-LAN-only
  interface (see "Recommended deployment hardening") and must never be
  exposed to the internet or an untrusted network. It binds the
  unprivileged port 5514 (not 514) so birdcage can
  run as a non-root container; operators point each OpenCanary instance's
  syslog handler `address` at this port.
- **Dashboard HTTP — TCP, default `:8080`** (override with
  `BIRDCAGE_HTTP_ADDR`). Read-only JSON API; no authentication yet --
  [issue #8](https://github.com/tomlawesome/birdcage/issues/8)
  (ADR-0003) -- so bind it to loopback or a trusted LAN only until then.
  Three routes, all `GET`: `/api/alerts`, `/api/instances`,
  `/api/stats`.

## Recommended deployment hardening

- Bind birdcage's HTTP port to a loopback or trusted-LAN-only interface,
  not every interface.
- Put it behind a VPN (e.g. WireGuard/Tailscale) if you need to reach it
  from outside that LAN -- there is no login screen to stop anyone who
  reaches it in v1.
- Keep CrowdSec/RouterOS credentials in environment variables or secrets,
  not in a config file that might be more widely readable than your
  environment.
- Restrict the RouterOS service account's own permissions to the minimum
  needed for the mitigation actions birdcage actually takes (e.g.
  firewall/address-list write access), not a full admin account -- birdcage
  compromising that account should not mean compromising the router.

## Reporting a vulnerability

This is a small, personally-maintained project without a formal disclosure
program. If you find a security issue, please open a GitHub issue
describing it -- for anything you'd rather not post publicly first, open a
minimal issue asking for a private contact channel instead of including
details in it.
