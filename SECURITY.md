# Security policy

Birdcage is in early implementation (the HTTPS ingest submux -- per-canary
bearer tokens, TLS 1.3 -- and the command endpoint have landed; the agent
(#48) and enrolment (#47) have not; see [docs/v1-scope.md](docs/v1-scope.md))
-- this document describes the threat model and hardening it is designed
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

**A canary that cannot report is a security event, not an availability
one** (issue #45). A honeypot's entire value is a hit landing on the
dashboard; a canary that goes throttled, stops delivering, can't complete
its token rotation, or has a revoked token reused against it, is
indistinguishable from a quiet network unless birdcage says so loudly and
explicitly. Treating that as a mere uptime blip — logged, not surfaced —
lets an attacker who can overwhelm, starve or clone a canary's identity
buy the same silence a stopped agent would, with no operator ever told.
The dashboard surfaces each of these states on the canary's tile and in
the top-level status, ranked against — not below — an active attack.

**Authentication is part of v1** (changed 2026-09-12,
[ADR-0003](docs/adr/0003-mikroview-sidecar.md)): local accounts and
self-hosted-only OIDC, following
[mikroview](https://github.com/tomlawesome/mikroview)'s model. Until
[#8](https://gitlab.tomlawson.io/ai/birdcage/-/issues/8) lands, nothing gates
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

## Output escaping

Text birdcage did not generate itself -- a canary id, a service name, a
source address, an OpenCanary `raw` field -- comes from a machine we
expect to be attacked, and the stored record of it is evidence: nothing
upstream of output strips, rewrites, or otherwise sanitises it (the same
rule the Mockingbird agent follows for what it forwards). Escaping happens
only at the point that text is displayed, per surface:

- **Dashboard:** every value is rendered through Svelte's own text
  interpolation, never `{@html}`, so HTML/script injection is escaped
  the same way regardless of which field carries attacker-supplied text.
- **CLI (`birdcage canary mint | list | revoke`, and any future
  subcommand):** printed through `internal/term.Escape`, which renders
  C0, DEL, and C1 control characters as literal, visible text (e.g. an
  embedded escape sequence prints as `\x1b`, not as the raw byte) before
  it reaches a terminal, leaving ordinary printable text -- including
  non-ASCII -- untouched. It also escapes the bidirectional formatting
  characters, which reorder how surrounding text *displays* rather than
  moving the cursor: unescaped, they let a canary id read on screen as a
  different id than the one stored (the Trojan Source class,
  CVE-2021-42574). Without this, a crafted canary id or service
  name could hide output lines, overwrite what's already on screen, or
  make a revoked token's status print as active.

## Network exposure

- **Canary ingest — HTTPS**, address and on/off switch via
  `BIRDCAGE_INGEST_ADDR` (unset disables the listener entirely).
  **Bearer-token authenticated, TLS 1.3 minimum, HTTP/1.1 only.** A
  canary's agent (#48) posts batches of events to `POST /ingest/events`
  with `Authorization: Bearer <token>`; missing, unknown and revoked
  tokens all get an identical 401. This listener is on its own
  `*http.Server`, structurally unreachable from every dashboard route
  above and from the dashboard's own auth seam (issue #32). Its serving
  certificate is minted by birdcage's own CA (`BIRDCAGE_CA_DIR`, issue
  #47 slice 1) rather than an operator-supplied file; an unloadable or
  wrongly-permissioned CA directory stops birdcage at startup rather
  than falling back to plaintext. See
  [docs/configuration.md](docs/configuration.md#birdcage_ca_dir) for
  `BIRDCAGE_CA_DIR` and `BIRDCAGE_ADVERTISE_HOST`. Full threat model,
  rotation, and rate limits: issue #32.

  **Mutual TLS (issue #47 slice 3).** The bearer token alone is no longer
  enough: every connection must also present a client certificate issued
  by birdcage's own CA, and that certificate's subject must name the same
  canary the bearer token resolved to. A missing certificate is refused
  at the TLS handshake, before any request is read; a certificate for the
  wrong canary passes the handshake but is refused with the same 401 and
  an `ingest.client_cert_mismatch` audit entry. The enrolment listener
  (below) does not require one -- a canary has no certificate to present
  until `POST /enrol/provision` issues its first one.
- **Dashboard HTTP — TCP, default `:8080`** (override with
  `BIRDCAGE_HTTP_ADDR`). No authentication yet --
  [issue #8](https://gitlab.tomlawson.io/ai/birdcage/-/issues/8)
  (ADR-0003) -- so bind it to loopback or a trusted LAN only until then.
  Every route below has the same gap:

  | Route            | Method | Auth                          |
  | ---------------- | ------ | ------------------------------ |
  | `/`              | GET    | requireAuth seam, pending #8  |
  | `/api/alerts`    | GET    | requireAuth seam, pending #8  |
  | `/api/instances` | GET    | requireAuth seam, pending #8  |
  | `/api/stats`     | GET    | requireAuth seam, pending #8  |
  | `/api/canaries`  | GET    | requireAuth seam, pending #8  |
  | `/api/visitors`  | GET    | requireAuth seam, pending #8  |
  | `/api/trace`     | GET    | requireAuth seam, pending #8  |
  | `/api/heartbeat` | POST   | requireAuth seam, pending #8  |
  | `/api/stream`    | GET    | requireAuth seam, pending #8  |

  `/api/stream` (issue #44) is a server-sent-events connection birdcage
  holds open rather than answering once, so until #8 lands it also caps
  total concurrent connections (`internal/stream.Hub`, 256) and drops the
  slowest subscriber's buffer rather than growing it without limit --
  mitigating the connection-exhaustion risk a held-open, unauthenticated
  route adds beyond the other routes above (see issue #44's Research
  section for the threat model and CVE search this came from). A dropped
  or refused stream falls back to the dashboard's existing 30s poll,
  which every route above already relies on.

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
