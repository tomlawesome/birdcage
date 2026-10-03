# ADR-0005: Authentication comes from a shared Go module, `gauntlet`

**Status:** Accepted
**Date:** 2026-09-13
**Amends:** ADR-0003 (decision 3 "Auth model" and "Token model"; the
"Copied code is a fork" consequence; the "Extract mikroview's auth into a
shared module now" superseded entry).

## Context

ADR-0003 had birdcage re-implement mikroview's authentication by hand and
keep the copy in step manually, with a shared module as "a later option".
Reading the ADR on 2026-09-13 the owner reversed that: *"we should really
work towards our implementation of authentication etc being in a reusable
module now. It makes little sense to copy mikroview, only to later try and
create a shared Go module."*

A read-only survey of mikroview the same day showed the code is already
separable. `internal/auth` (accounts with Argon2id, roles, in-memory
sessions, API and ingest tokens, login rate limiting), `internal/oidc`
(protocol only) and the handlers and middleware in
`internal/api/auth.go|oidc.go|tokens.go` reach the rest of mikroview only
through three seams: `internal/persist` (a storage interface, backed there
by JSON files or a Postgres `store_blob` table), `internal/logging` and
`internal/evict`. No concrete mikroview types cross into the auth code.
Third-party dependencies: `golang.org/x/crypto/argon2`,
`github.com/coreos/go-oidc/v3`, `golang.org/x/oauth2`.

## Decision

1. **One shared module, its own repository:** `github.com/tomlawesome/gauntlet`
   (owner, 2026-09-13: *"Own repo I think"*; name: *"I prefer 'gauntlet' —
   users must run the gauntlet to gain entry."*). It holds the auth model
   ADR-0003 describes — local accounts, roles, OIDC with the self-hosted-only
   policy and `(issuer, subject)` identity, opaque server-side sessions,
   read-only API tokens and write-only ingest tokens — as a library with
   its own tests.

2. **Storage, logging and eviction stay behind interfaces** shaped on
   mikroview's three seams, so each app supplies its own. Birdcage's
   implementation stores accounts and tokens in its own database (SQLite or
   Postgres, ADR-0001); mikroview's keeps its `persist` backends. The
   module never owns a database.

3. **Birdcage first, mikroview after.** The module is built and proven in
   birdcage (#8). Mikroview is not changed in this work; its move onto the
   module is filed there as mikroview #1202 (milestone v0.6.0, owner 2026-09-13) and opens only when the owner
   says so. Until then mikroview's auth code is the reference the module is
   read against, continuously, so it fits without change when that day
   comes (owner: *"you WILL need to keep reading mikroview code to ensure
   it will work"*).

4. **Behaviour is identical for existing users.** Mikroview's accounts,
   sessions, tokens and OIDC logins must work unchanged after the move; a
   migration test against a copy of real stored data is part of that
   issue's acceptance, not of birdcage's.

## Consequences

- ADR-0003's "copied code is a fork" consequence no longer applies: a
  security fix lands once, in `gauntlet`, and each app picks it up by
  bumping the version.
- Birdcage's #8 becomes "build `gauntlet` and use it", not "re-implement
  mikroview's auth". The issue body is rewritten to that.
- The module's API is a design call and stays with the top model; its
  seams are fixed by what mikroview already needs, not invented.
- A new repository is an owner action: the assistant prepares the layout
  and hands over the create step.

## Superseded

- **Re-implement by hand, share later** (ADR-0003, 2026-09-12): reversed by
  the owner on reading the ADR; see Context.
- **Nested module inside mikroview's repository**: considered 2026-09-13,
  rejected by the owner in favour of a repository of its own — a nested
  module ties birdcage's build to mikroview's history and makes the
  ownership boundary unclear.
