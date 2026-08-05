# Security policy

Birdcage is pre-implementation (see [docs/v1-scope.md](docs/v1-scope.md)) --
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

**v1 has no built-in authentication** (same stance as
[mikroview](https://github.com/tomlawesome/mikroview)'s SECURITY.md):
anyone who can reach birdcage's HTTP port can see all aggregated honeypot
alert data and, once implemented, trigger or observe automated mitigation
actions. **Birdcage must not be exposed to the internet or an untrusted
network in v1** -- see "Recommended deployment hardening" below. OIDC
authentication is tracked for after v1
([issue #8](https://github.com/tomlawesome/birdcage/issues/8)), not before.

## Data handling

- **Service-account credentials (CrowdSec, RouterOS) are secrets.** They
  must be supplied via environment variables or Docker/Compose secrets,
  never committed to a config file in the repo, and never logged --
  including in error messages or debug output. Treat a log line containing
  a bearer token or API key as a real leak, not a hypothetical one.
- **Alert and audit data is persisted**, unlike mikroview's in-memory-only
  model -- birdcage's whole purpose is centralized history across
  instances. SQLite for v1 (see [ADR-0001](docs/adr/0001-stack-and-storage.md)).
  Alert data (source IPs, timestamps, targeted services) is not highly
  sensitive on its own, but the database file should still be kept off any
  shared/multi-tenant filesystem, same guidance as mikroview's
  `config.yaml`.
- **The audit log is append-only by convention.** No application code path
  may issue `UPDATE`/`DELETE` against it. This is what makes "birdcage took
  automated action" reviewable and reversible rather than a black box --
  see [ADR-0001](docs/adr/0001-stack-and-storage.md).

## Network exposure

Not yet finalized -- birdcage's HTTP surface doesn't exist yet
([issue #3](https://github.com/tomlawesome/birdcage/issues/3)). This
section will list each listener (dashboard HTTP, any ingestion port) and
its auth/TLS status once implemented, in the same format as mikroview's
SECURITY.md.

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
