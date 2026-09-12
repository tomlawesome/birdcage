# ADR-0003: Birdcage is a sidecar to mikroview

**Status:** Accepted
**Date:** 2026-09-12

## Context

Birdcage started as a standalone project after several rounds of deciding
where honeypot alerts belong (recorded in mikroview's `AGENTS.md`: no
OpenCanary logic in mikroview; a multi-instance honeypot dashboard is a
different product). That boundary still holds. What has changed is how the
two apps should sit next to each other.

The owner wants birdcage to feel like part of the same toolset: same look,
same way of signing in, same way of handing out API keys. Folding birdcage
into mikroview was considered again on 2026-09-12 and rejected for the
original reasons plus one more: birdcage holds service-account credentials
and changes firewall state, while mikroview is a read-only viewer. Putting
an actor inside a viewer changes mikroview's security posture for every
user of it.

Mikroview already has a strong auth model that the owner does not want to
rework: local accounts (Argon2id, roles `admin`/`user`/`viewer`), optional
OIDC restricted to self-hosted providers (Authentik, Keycloak, Zitadel,
Entra single-tenant; multi-tenant providers refused at startup), opaque
server-side sessions, and two bearer-token kinds (read-only API tokens on a
separate mux; per-device ingest tokens). See mikroview `SECURITY.md`,
`internal/auth/`, `internal/oidc/`, `internal/api/auth.go`,
`docs/configuration.md` (API tokens, OIDC).

## Decision

1. **Sidecar, not merge.** Birdcage stays its own repository, binary,
   container, database and port. It is deployed alongside mikroview in the
   same compose stack. Neither app is required for the other to run.

2. **The two apps talk only through API keys.** Birdcage holds a mikroview
   read-only API token and calls the bounded IP+time lookback query
   (mikroview#29) for traffic context around a honeypot hit. Any future
   traffic the other way uses a birdcage API token in the same style. No
   shared sessions, no shared database, no shared process.

3. **Copy mikroview's design language, not its code.** Three things carry
   over, each re-implemented in birdcage and kept in step by hand:

   - **Visual identity.** Layout, colour system and component feel from
     mikroview's `frontend/src/app.css` custom properties and
     `docs/design/`. Birdcage gets its own mark and name, in the style of
     `brand/BRANDING.md`, so the two are recognisably siblings, not the
     same app.
   - **Auth model.** Local accounts with Argon2id and the same three roles;
     OIDC with the same self-hosted-only policy and `(issuer, subject)`
     identity; opaque server-side sessions with the same cookie flags.
     Sharing login in practice means both apps point at the same OIDC
     provider (Authentik), so one identity signs in to either.
   - **Token model.** Read-only API tokens routed to a separate read-only
     mux, and write-only ingest tokens that cannot reach read endpoints.
     SHA-256 hashed at rest, raw value shown once.

4. **Frontend is Svelte + TypeScript**, replacing ADR-0001's React choice,
   so the login, account-admin and token-admin screens can follow
   mikroview's closely rather than being redrawn in another framework.

5. **Authentication is in v1**, replacing ADR-0001's "no built-in
   authentication in v1". Birdcage acts on the network, so the case for
   gating it is stronger than mikroview's was. Issue #8 moves into M1 and
   is rewritten to this model; the dashboard (#3) does not ship without it.

## Consequences

- ADR-0001 is amended, not replaced: Go backend and SQLite storage stand;
  frontend and v1 auth stance are superseded by this ADR.
- `SECURITY.md` must be rewritten around a gated dashboard: which routes
  require a session, which accept which token kind, and what still needs a
  reverse proxy (TLS).
- Copied code is a fork. Mikroview auth fixes do not reach birdcage on
  their own; each security-relevant change there is checked against
  birdcage's copy. A shared Go module is a later option once the copy has
  proven to be genuinely identical -- deliberately not done up front.
- Mikroview is unchanged by this decision. Anything birdcage needs from it
  beyond mikroview#29 is a proposal on mikroview, not an assumption here.

## Superseded

- **Merge birdcage into mikroview** (raised 2026-09-12): rejected, see
  Context.
- **Shared sessions or birdcage trusting mikroview as its identity
  provider**: would need mikroview to grow a session-introspection endpoint
  and same-site cookies; reworking mikroview's auth was ruled out by the
  owner.
- **Extract mikroview's auth into a shared module now**: premature; see
  Consequences.
