# ADR-0016: Sign-in through gauntlet v0.4.1, stored as sealed documents in birdcage's own database

**Status:** Accepted (owner rulings 2026-10-10 on #8)
**Date:** 2026-10-10
**Relates to:** #8 (this change), #164 (first admin by setup code), #180
(admin passkey rule), #189 (screens waiting on mikroview), ADR-0005 (auth
comes from the shared module gauntlet), ai/mikroview#1202 (mikroview's own
move onto gauntlet, whose rulings these mirror).

## Context

The dashboard has no sign-in: `requireAuth` (`internal/api/api.go`) is a
placeholder that lets every request through, and the dashboard API is kept
read-only so that this costs nothing worse than a read (#124, #135).
ADR-0005 moved authentication into gauntlet, which is now released
(v0.4.1) and ready to embed. Gauntlet owns no database: each app saves its
stores through a `persist.Backend` it writes over its own storage.

The canary side is untouched: enrolment (`/enrol/*`, one-time enrolment
tokens) and ingest (`/ingest/*`, mutual TLS plus canary bearer tokens) run
on their own listeners and never pass through the dashboard's sign-in.

## Decisions

1. **Dependency.** `github.com/tomlawesome/gauntlet` v0.4.1, fetched from
   the Git host, never through proxy.golang.org or sum.golang.org:
   `GOPRIVATE=github.com/tomlawesome/*` locally and in every CI job that
   resolves modules. Modules gauntlet brings in are approved by reference
   to gauntlet's own approved-modules list (owner, 2026-10-10, #8);
   birdcage's ledger gains an entry saying so.
2. **Storage (owner, 9a).** Each gauntlet store -- `accounts`, `tokens`,
   `signins` -- is one sealed document in a new table, `auth_documents`
   (migration 0029, SQLite and Postgres): `name` (primary key), `payload`
   (bytes), `version` (integer), `updated_at`. The backend is the
   standard optimistic-concurrency shape: `Save` with `expect == 0`
   inserts only if no row exists, otherwise updates only where `version`
   still equals `expect`, and either miss returns `persist.ErrConflict`.
   SQLite stays the default database. The backend must pass gauntlet's
   own conformance suite, `persisttest.Run`, on both engines.
3. **Key (ruling 2).** `BIRDCAGE_AUTH_KEY_FILE` names a mounted file of at
   least 32 bytes (`persist.MinKeyBytes`); every store is wrapped in
   `persist.Encrypt` under it, with the store name as its label.
   Birdcage refuses to start without a readable key, with a message
   saying how to make and mount one. `AllowPlaintextAtRest` is never set.
4. **Gate.** `gate.Protect` replaces `requireAuth` in front of the
   dashboard API; `g.Routes()` serves `/api/auth/` and `/api/tokens`
   (neither path exists in birdcage today). Every existing dashboard route
   needs a signed-in session or a read API token, any role. The frontend
   assets stay reachable without a session (the sign-in screen is one of
   them). Config: cookie `birdcage_session`, `SecureCookie` true whenever
   the dashboard serves TLS, CSRF header value `birdcage`, product name
   `birdcage`, client address from the connection (birdcage terminates
   TLS itself and trusts no proxy headers).
5. **Admin passkey (ruling 1, settles #180).** Required when
   `BIRDCAGE_PUBLIC_URL` is an https URL on a domain name and passkeys are
   wired; optional otherwise. `BIRDCAGE_AUTH_ADMIN_PASSKEY`
   (`required`|`optional`) overrides. Passkeys are wired from
   `BIRDCAGE_PUBLIC_URL` when it is set; without it they stay off and the
   rule is optional.
6. **Sessions, tokens, passwords (rulings 3-7).** Sessions at gauntlet's
   maximums (1 hour idle, 1 day total). API tokens expire after a year;
   `Gate.SweepTokens` runs daily. The common-password list refresher is
   on (gauntlet ADR-0007; the outbound fetch is documented); Have I Been
   Pwned is off. Birdcage issues no gauntlet ingest tokens: canaries keep
   their own credentials, so ruling 4's "ingest tokens never expire" has
   nothing to apply to.
7. **History, passkey-alone, SSO roles (rulings 8-10).** Sign-in history
   is recorded from the start (the page waits on #189); passkey-alone
   sign-in and SSO group roles are off.
8. **Country (ruling 11).** `gauntlet/geoip` runs when the operator
   configures a provider: `BIRDCAGE_GEOIP_IPINFO_TOKEN_FILE`, or
   `BIRDCAGE_GEOIP_MAXMIND_ACCOUNT_ID` with
   `BIRDCAGE_GEOIP_MAXMIND_LICENCE_KEY_FILE`. Its data lives under the
   data directory, outside backups. With no provider, country stays off
   and birdcage still starts. The provider's credit line appears wherever
   a country is shown (none until #189's page).
9. **Unusual sign-ins (answers 10b, 11a).** Flagged (gauntlet's default)
   until mikroview's hold screens exist; then held (#189).
10. **Codes in the log (#164).** The one-time setup code and the
    emergency unlock and escape codes go to birdcage's log as gauntlet
    writes them; nothing else stores them. CLI processes that open the
    store announce no codes, as in mikroview.
11. **Screens.** Reused from mikroview's frontend where they exist:
    sign-in with second factor, passkey and SSO buttons; first admin with
    setup code; authenticator app and passkeys; recovery and reset codes;
    SSO link; users and API tokens; sign out; password change. Missing
    ones wait on mikroview (#189). The API client sends
    `X-Requested-With: birdcage` on every request that changes data, and
    a `401` from any dashboard route shows the sign-in screen.
12. **SSO.** Optional, off unless configured
    (`BIRDCAGE_OIDC_ISSUER`, `BIRDCAGE_OIDC_CLIENT_ID`,
    `BIRDCAGE_OIDC_CLIENT_SECRET_FILE`), gauntlet's self-hosted-only
    issuer policy unchanged.

## Consequences

- Every live journey that reads the dashboard API signs in first, through
  one shared helper: create the first admin with the setup code from the
  log, enrol an authenticator app (password accounts must hold a second
  factor), and mint a read API token the journey's requests carry. The
  browser smoke signs in through the screen.
- Losing the key file loses every account: the install docs say to back
  it up separately from the database.
- A restart signs everyone out (gauntlet keeps sessions in memory).

## Superseded

- *ADR-0003's hand-copied auth* -- replaced by ADR-0005 and this record.
