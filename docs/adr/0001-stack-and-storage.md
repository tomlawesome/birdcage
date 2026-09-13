# ADR-0001: Stack, storage, and v1 auth stance

**Status:** Accepted; frontend and v1 auth stance superseded by [ADR-0003](0003-mikroview-sidecar.md) (2026-09-12)
**Date:** 2026-08-04

## Context

Birdcage centralizes alerts from multiple OpenCanary honeypot instances into
a single dashboard, with an ambition to add CrowdSec/RouterOS-driven
automated mitigation. It needs a backend language, a frontend framework, a
storage engine, and a v1 stance on authentication, decided before any
implementation work starts.

## Decision

- **Backend: Go.** CrowdSec ships official Go client libraries
  (`crowdsecurity/crowdsec/pkg/apiclient` for the LAPI, and
  `crowdsecurity/go-cs-bouncer` for the bouncer SDK) since CrowdSec itself is
  written in Go. Python/Node have no equivalent maintained SDK and would mean
  hand-rolling REST calls against CrowdSec's API. The same reasoning extends
  to RouterOS mitigation, where mikroview (`tomlawesome/mikroview`) already
  has Go/RouterOS familiarity to build on.
- **Superseded by ADR-0003 (Svelte + TypeScript).** **Frontend: React + TypeScript.** Chosen for faster access to mature
  "admin dashboard" component ecosystems (shadcn/ui, Tremor, visx/nivo for
  charts) that fit a multi-instance monitoring dashboard well. This trades
  away direct reuse of mikroview's existing Svelte components, though the
  underlying design language (CSS custom properties, dark-dashboard layout)
  ports over framework-agnostically if wanted.
- **Storage: SQLite and Postgres, both in v1** (owner, 2026-09-13; originally
  SQLite only, Postgres deferred). SQLite is the default, via a pure-Go driver (no cgo, so it still
  builds into a `CGO_ENABLED=0` distroless image the same way mikroview
  does). Right for a single-node, self-hosted deployment: no separate DB
  server, trivial to back up (one file). Postgres is mandatory in v1 (see
  [issue #7](https://github.com/tomlawesome/birdcage/issues/7)), informed by
  `tomlawesome/orbit`'s existing Postgres + Drizzle + migration/test setup
  as prior art for the pattern once multi-node/HA deployment is a real
  requirement.
- **Audit trail is required, not optional.** Every automated action birdcage
  takes (a CrowdSec decision acted on, a RouterOS firewall change) must be
  recorded in an append-only audit log -- action, target, reason, trigger,
  timestamp -- before v1 is considered complete. An automated-mitigation tool
  is only trustworthy if what it did is reviewable and un-editable after the
  fact.
- **Superseded by ADR-0003 (authentication is in v1).** **No built-in
  authentication in v1.** Same stance as mikroview: birdcage is
  expected to sit behind a reverse proxy or VPN, not to gate access itself.
  Given birdcage holds live service-account credentials and can take
  automated action, this is revisited once v1 ingestion/dashboard/mitigation
  works -- see [issue #8](https://github.com/tomlawesome/birdcage/issues/8)
  (OIDC via Authentik, modeled on `tomlawesome/orbit`'s
  `docs/authentication.md`).

## Consequences

- Service-account credentials (CrowdSec, RouterOS) must be handled as
  secrets from day one (env vars / Docker secrets, never logged, never
  committed) even though nothing gates access to the dashboard itself yet --
  see SECURITY.md.
- SQLite's single-file model means backup/restore is simple; Postgres is the
  choice for multi-node or heavier deployments. Every query must run on both.
- No auth in v1 means SECURITY.md's network-exposure guidance is load-bearing
  in a way it wasn't for mikroview (a read-only viewer); a misconfigured
  reverse proxy here exposes a tool that can act on your network, not just
  view it.
