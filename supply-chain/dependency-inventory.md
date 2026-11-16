# Dependency inventory

Read-only inventory for issue #73 ("Dependency review: list every third-party
dependency for owner approval"). Every direct and transitive third-party
dependency this project pulls in, from every manifest and pinned artifact
named in that issue: `go.mod`/`go.sum`, `frontend/package.json` +
`package-lock.json`, `build/birdcage/Dockerfile`, `build/mockingbird/Dockerfile`,
`build/opencanary/requirements.txt` (+ `requirements.in`), `.gitlab-ci.yml`
and `.github/workflows/*.yml`.

Nothing in the tables changes a dependency. Owner decisions on individual rows
still belong on issue #73; this file is the durable record those decisions can
point at, and its ledger (next section) is the approval list: nothing else
holds it. The scheduled staleness check named in that issue's addendum
(2026-09-19: *"Third party dependencies must be checked for staleness
regularly by CI"*) is `audit:staleness` (#139, docs/ci-hops.md): every
"Latest upstream" cell below is a dated snapshot, current only as of the
date this file says, and that job's `staleness-report.md` artifact --
not this table -- is the live figure.

## Approved third-party modules (the ledger)

This is the single record of what the owner has approved; the rows below
carry the evidence. The owner's rule is: no
third-party module without the owner's explicit approval, on its issue, with
provenance. Approved for this project, with the issue that records the
decision:

- `golang.org/x/net` (bpf) and `golang.org/x/sys` — Go team; #65, 2026-09-19.
- `github.com/emersion/go-imap/v2` — approval mailbox; #54, 2026-09-19.
- `github.com/emersion/go-msgauth` (dkim) — agent-side signature check;
  #54, 2026-09-19. Brings `emersion/go-message`, `emersion/go-sasl`,
  `emersion/go-milter` (module only, never linked) as the same author.
- `github.com/tomlawesome/gauntlet` (the owner's own sign-in module,
  Apache-2.0), fetched from its Git host, never through proxy.golang.org
  (ADR-0016 decision 1). The modules it brings in -- among them
  `github.com/coreos/go-oidc/v3`, `golang.org/x/oauth2`, `go-webauthn` and
  `golang.org/x/crypto/argon2` -- are approved by reference to gauntlet's
  own approved-modules list; owner, 2026-10-10, #8 (answer 4a), replacing
  the narrower approval of 2026-09-26.
- `github.com/jackc/pgx/v5`, `modernc.org/sqlite` — predate the rule; listed
  for the owner's review on #73.

Shipped as a binary in an agent image, never linked into birdcage:

- `grype` (Anchore) — the scanner agent's engine, Apache-2.0; owner,
  2026-09-22, #108. Chosen over Trivy against a verified comparison; the
  reasoning is in ADR-0010, "Engine: Grype". Its vulnerability database is
  fetched at runtime and cached, never vendored.
- `samba-server` (Samba Team, via Alpine) — the SMB lure's whole reason to
  exist, GPL-3.0-or-later; owner, 2026-09-23, #87 decision 1 ("Real Samba on
  Alpine"). Pinned to an exact apk version in `build/smb-lure/Dockerfile` and
  rebuilt on every Alpine security update to it. No apk licence gate exists,
  so this entry and row 223 below are the record; GPLv3 in a shipped image
  has the owner's precedent in `hpfeeds@3.0.0`.

Build-only, never shipped:

- `git` (Alpine package) -- only in `build/birdcage/Dockerfile`'s Go build
  stage, so gauntlet can be fetched from its Git host; never in a shipped
  image (`scripts/go-fetch-guard.py` holds both). Owner, 2026-10-10, #8
  (answer 3a); row 230.

CI-only tools, never linked or shipped:

- `golang.org/x/vuln` (govulncheck) -- Go team, BSD-3-Clause; owner,
  2026-09-27, #51. Installed at CI time in `lint:govulncheck`; never
  imported by any package birdcage builds.
- `gitleaks` (gitleaks project) -- MIT; owner, 2026-09-27, #28. The
  released binary, checksum-verified by `scripts/ensure-gitleaks.sh`,
  never the commercially-licensed `gitleaks-action`; installed at CI
  time in `lint:gitleaks`.
- `python3` (Alpine package, Python Software Foundation) -- the release
  jobs' evidence judge in `scripts/verify-validation-evidence.sh`; owner,
  2026-09-30, #158. Installed via `RELEASE_APK_PACKAGES`, never shipped.
- `crowdsecurity/crowdsec` container image (CrowdSec SAS, MIT) -- the
  real Local API `e2e:crowdsec` runs `birdcage crowdsec add` against,
  pinned by digest in `scripts/e2e/crowdsec-stack.sh` (v1.8.1); #4,
  ADR-0014. **Proposed, awaiting the owner's approval on #4.** A CI
  fixture only: never linked, never shipped, and nothing in it phones
  out (the journey disables the agent, the central-API client and the
  hub download).

Frontend (`frontend/package.json`), dev-only, never shipped:

- `@vitest/coverage-v8` -- the coverage plugin of the test runner the
  project already uses, by the same team (vitest-dev) and peer-pinned to
  the exact vitest version, so not a new third party to trust. MIT.
  Owner, 2026-09-20: *"it's not really a third party. It's a plugin by
  the exact same team."* #74.

Frontend, shipped in the bundle:

- `qrcode-generator` 2.0.4, pinned exactly (Kazuhiko Arase, MIT, no
  dependencies of its own) -- draws the authenticator QR code on the
  sign-in door until gauntlet serves the pattern itself; owner,
  2026-11-15, #8 (29a). Row 231.

Anything else goes to the owner first, on the issue, with provenance.

## Methodology

Sections A-G reuse the 210-row table [posted on issue #73 on
2026-09-20](https://gitlab.tomlawson.io/ai/birdcage/-/issues/73#note_21224),
whose version numbers were checked that session against each ecosystem's
primary source (npm registry, PyPI JSON API, proxy.golang.org, Docker Hub,
GitHub releases/tags API, go.dev/dl, nodejs.org, endoflife.date) -- none from
memory. This review re-verified the decision-critical rows directly against
proxy.golang.org, the GitHub API and PyPI on 2026-09-22 (`pgx/v5`,
`modernc.org/sqlite`, `hpfeeds`, `cosign`, `actions/checkout`,
`github/codeql-action`) and found no drift in the two days between sessions.
The remaining rows are two days old rather than independently re-verified
this session; nothing in that gap looked likely to move a pinned patch
version, but treat "Latest upstream" as dated 2026-09-20 except where a row
says otherwise.

Section H is new: dependencies this review found that the 2026-09-20 table
missed -- OS packages installed inline inside `.gitlab-ci.yml` job scripts,
one CI image, and the whole `.github/workflows/countersign.yml` workflow.

Four columns were added beyond the issue's own table format, per this
review's brief:

- **Maintainer** -- the publishing individual or organisation. For the ~170
  transitive rows this is often "inherited" from whichever direct dependency
  pulls it in (named in the cell), rather than individually profiled --
  npm's own dependency graphs run three and four levels deep and a fully
  independent maintainer lookup for each leaf package was not attempted.
- **Popularity signal** -- a rough, four-level qualitative read (very
  high/high/moderate/small-utility), not a download-count figure. "Small
  utility" covers the bulk of the transitive rows: real signal for these is
  "does its direct parent get used", not its own standalone popularity.
- **Shipped / dev-CI-only** -- which artefact, if any, carries this
  dependency to a user: the `birdcage` binary, the `mockingbird` image, or
  neither (dev tooling, CI runner, build stage, release/signing step).
- **Approval status** -- read directly against the approved-module
  ledger above, not a judgement call. Three states: **Approved -- #N** (recorded there by name), **Predates
  the rule -- flagged on #73** (the two rows the ledger itself names as
  pending this review: `pgx/v5`, `modernc.org/sqlite`), and **Predates the
  rule -- not individually recorded** (everything else that is `direct`:
  original-architecture choices -- the Postgres/SQLite drivers aside -- that
  were never individually logged as approved, because the per-dependency
  approval practice postdates them). Transitive rows are marked **n/a --
  transitive**: nothing here asks the owner to approve a package nobody
  chose to depend on directly.

### A. Go module (`go.mod`, `go.sum`)

| # | Dependency | Pinned | Latest upstream (verified 2026-09-20, spot-checked 2026-09-22) | Licence | Direct/Transitive | Maintainer | Popularity signal | Shipped / dev-CI-only | Approval status |
|---|---|---|---|---|---|---|---|---|---|
| 1 | `github.com/emersion/go-imap/v2` | v2.0.0-beta.8 | v2.0.0-beta.8 (proxy.golang.org, verified -- already current) | MIT | direct | emersion (independent OSS maintainer, GitHub handle "emersion") | high (the standard choice for its niche) | Shipped -- linked into the birdcage and/or mockingbird Go binary | Approved -- #54 |
| 2 | `github.com/emersion/go-msgauth` | v0.7.0 | v0.7.0 | MIT | direct | emersion | moderate (established, purpose-fit, not mainstream-scale) | Shipped -- linked into the birdcage and/or mockingbird Go binary | Approved -- #54 |
| 3 | `github.com/jackc/pgx/v5` | v5.12.0 | v5.12.0 (current, 2026-11-14) | MIT | direct | jackc (Jack Christensen, independent maintainer) | high (the standard choice for its niche) | Shipped -- linked into the birdcage and/or mockingbird Go binary | Predates the rule -- flagged on #73 for owner decision |
| 4 | `golang.org/x/crypto` | v0.58.0 | v0.58.0 (current, 2026-11-14) | BSD-3-Clause | direct | Go team (Google) | very high (mainstream, widely deployed) | Shipped -- linked into the birdcage and/or mockingbird Go binary | Predates the rule -- not individually recorded |
| 5 | `golang.org/x/net` | v0.62.0 | v0.62.0 (current, 2026-11-14) | BSD-3-Clause | direct | Go team (Google) | very high (mainstream, widely deployed) | Shipped -- linked into the birdcage and/or mockingbird Go binary | Approved -- #65 |
| 6 | `golang.org/x/sys` | v0.49.0 | v0.49.0 (current, 2026-11-14) | BSD-3-Clause | direct | Go team (Google) | very high (mainstream, widely deployed) | Shipped -- linked into the birdcage and/or mockingbird Go binary | Approved -- #65 |
| 7 | `golang.org/x/time` | v0.16.0 | v0.16.0 | BSD-3-Clause | direct | Go team (Google) | moderate (established, purpose-fit, not mainstream-scale) | Shipped -- linked into the birdcage and/or mockingbird Go binary | Predates the rule -- not individually recorded |
| 8 | `modernc.org/sqlite` | v1.62.0 | v1.62.0 (current, 2026-11-14) | BSD-3-Clause | direct | cznic / modernc.org (Jan Mercl, independent maintainer) | high (the standard choice for its niche) | Shipped -- linked into the birdcage and/or mockingbird Go binary | Predates the rule -- flagged on #73 for owner decision |
| 9 | `github.com/dustin/go-humanize` | v1.1.0 | v1.1.0 (current, 2026-11-14) | MIT | transitive | dustin (Dustin Sallings, independent) | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 10 | `github.com/emersion/go-message` | v0.18.2 | v0.18.2 | MIT | transitive | emersion | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 11 | `github.com/emersion/go-sasl` | v0.0.0-20241020182733-b788ff22d5a6 | v0.0.0-20241020182733-b788ff22d5a6 (proxy.golang.org confirms this is still the newest commit -- already current) | MIT | transitive | emersion | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 12 | `github.com/google/uuid` | v1.6.0 | v1.6.0 | BSD-3-Clause | transitive | Google | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 13 | `github.com/jackc/pgpassfile` | v1.0.0 | v1.0.0 | MIT | transitive | jackc | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 14 | `github.com/jackc/pgservicefile` | v0.0.0-20240606120523-5a60cdf6a761 | v0.0.0-20240606120523-5a60cdf6a761 (proxy.golang.org confirms this is still the newest commit -- already current) | MIT | transitive | jackc | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 15 | `github.com/jackc/puddle/v2` | v2.2.3 | v2.2.3 (current, 2026-11-14) | MIT | transitive | jackc | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 16 | `github.com/mattn/go-isatty` | v0.0.24 | v0.0.24 | MIT | transitive | mattn (Yasuhiro Matsumoto, independent) | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 17 | `github.com/ncruces/go-strftime` | v1.1.0 | v1.1.0 (current, 2026-11-14) | MIT | transitive | ncruces (independent) | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 18 | `github.com/remyoudompheng/bigfft` | v0.0.0-20230129092748-24d4a6f8daec | v0.0.0-20230129092748-24d4a6f8daec (proxy.golang.org confirms this is still the newest commit -- already current) | BSD-3-Clause (confirmed via GitHub repo licence field). | transitive | remyoudompheng (independent) | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 19 | `golang.org/x/sync` | v0.24.0 | v0.24.0 (current, 2026-11-14) | BSD-3-Clause | transitive | Go team (Google) | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 20 | `golang.org/x/text` | v0.43.0 | v0.43.0 (current, 2026-11-14) | BSD-3-Clause | transitive | Go team (Google) | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 21 | `modernc.org/libc` | v1.80.1 | v1.80.1 (current, 2026-11-14) | BSD-3-Clause | transitive | cznic / modernc.org | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 22 | `modernc.org/mathutil` | v1.7.1 | v1.7.1 | BSD-3-Clause | transitive | cznic / modernc.org | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 23 | `modernc.org/memory` | v1.11.0 | v1.12.1 | BSD-3-Clause | transitive | cznic / modernc.org | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |

### B. Frontend, `frontend/package.json` + `package-lock.json` -- all dev-only, never shipped, except `qrcode-generator` (row 231), which ships in the bundle (see the ledger above)

| # | Dependency | Pinned | Latest upstream (verified 2026-09-20, spot-checked 2026-09-22) | Licence | Direct/Transitive | Maintainer | Popularity signal | Shipped / dev-CI-only | Approval status |
|---|---|---|---|---|---|---|---|---|---|
| 24 | `@babel/code-frame` | 7.29.7 | 8.0.6 | MIT | transitive | Babel core team | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 25 | `@babel/helper-string-parser` | 7.29.7 | 8.0.6 | MIT | transitive | Babel core team | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 26 | `@babel/helper-validator-identifier` | 7.29.7 | 8.0.6 | MIT | transitive | Babel core team | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 27 | `@babel/parser` | 7.29.9 | 7.29.9 | MIT | transitive | Babel core team | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 28 | `@babel/runtime` | 7.29.7 | 8.0.5 | MIT | transitive | Babel core team | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 29 | `@babel/types` | 7.29.8 | 8.0.6 | MIT | transitive | Babel core team | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 30 | `@bcoe/v8-coverage` | 1.0.2 | 1.0.2 | MIT | transitive | Ben Coe (independent) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 31 | `@emnapi/core` | 2.0.0-beta.2 | 1.11.3 (a beta pinned here; 1.11.3 is the stable line) | MIT | transitive | toyobayashi (independent; optional, via `@rolldown/binding-wasm32-wasi`, via `vite`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 32 | `@emnapi/runtime` | 2.0.0-beta.2 | 1.11.3 (a beta pinned here; 1.11.3 is the stable line) | MIT | transitive | toyobayashi (independent; optional, via `@rolldown/binding-wasm32-wasi`, via `vite`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 33 | `@emnapi/wasi-threads` | 2.2.0 | 2.2.0 (current, 2026-11-14) | MIT | transitive | toyobayashi (independent; optional, via `@rolldown/binding-wasm32-wasi`, via `vite`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 34 | `@exodus/bytes` | 1.15.1 | 1.15.1 | MIT | transitive | Exodus (crypto wallet company), published utility | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 35 | `@jridgewell/gen-mapping` | 0.3.13 | 0.3.13 | MIT | transitive | Justin Ridgewell (independent, sourcemap tooling) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 36 | `@jridgewell/remapping` | 2.3.5 | 2.3.5 | MIT | transitive | Justin Ridgewell (independent, sourcemap tooling) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 37 | `@jridgewell/resolve-uri` | 3.1.2 | 3.1.2 | MIT | transitive | Justin Ridgewell (independent, sourcemap tooling) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 38 | `@jridgewell/sourcemap-codec` | 1.6.0 | 1.6.0 | MIT | transitive | Justin Ridgewell (independent, sourcemap tooling) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 39 | `@jridgewell/trace-mapping` | 0.3.31 | 0.3.31 | MIT | transitive | Justin Ridgewell (independent, sourcemap tooling) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 40 | `@napi-rs/wasm-runtime` | 1.2.6 | 1.2.7 | MIT | transitive | napi-rs project (optional, via `@rolldown/binding-wasm32-wasi`, via `vite`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 41 | `@oxc-project/types` | 0.149.0 | 0.150.0 | MIT | transitive | oxc project (Rust JS tooling, VoidZero-adjacent) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 42 | `@rolldown/binding-wasm32-wasi` | 1.2.19 | 1.3.2 | MIT | transitive | VoidZero / Rolldown team (optional wasm32 binding, via `vite`; not installed on this host) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 43 | `@rolldown/pluginutils` | 1.0.1 | 1.0.1 | MIT | transitive | VoidZero / Rolldown team | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 44 | `@sveltejs/acorn-typescript` | 1.0.13 | 1.0.13 | MIT | transitive | Svelte core team | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 45 | `@sveltejs/load-config` | 0.2.3 | 0.2.3 | MIT | transitive | Svelte core team | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 46 | `@sveltejs/vite-plugin-svelte` | 7.3.0 | 7.3.0 | MIT | direct | Svelte core team | moderate (established, purpose-fit, not mainstream-scale) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 47 | `@testing-library/dom` | 10.4.1 | 10.4.2 | MIT | transitive | Testing Library org | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 48 | `@testing-library/svelte` | 5.4.2 | 5.4.2 | MIT | direct | Testing Library org (community, Kent C. Dodds-founded) | moderate (established, purpose-fit, not mainstream-scale) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 49 | `@testing-library/svelte-core` | 1.1.3 | 1.1.3 | MIT | transitive | Testing Library org | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 50 | `@tsconfig/svelte` | 5.0.8 | 5.0.8 | MIT | direct | Svelte core team / tsconfig community bases | moderate (established, purpose-fit, not mainstream-scale) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 51 | `@tybys/wasm-util` | 0.10.4 | 0.10.4 (current, 2026-11-14) | MIT | transitive | toyobayashi (independent; optional, via `@rolldown/binding-wasm32-wasi`, via `vite`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 52 | `@types/aria-query` | 5.0.4 | 5.0.4 | MIT | transitive | DefinitelyTyped community | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 53 | `@types/chai` | 5.2.3 | 5.2.3 | MIT | transitive | DefinitelyTyped community | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 54 | `@types/deep-eql` | 4.0.2 | 4.0.2 | MIT | transitive | DefinitelyTyped community | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 55 | `@types/estree` | 1.0.9 | 1.0.9 | MIT | transitive | DefinitelyTyped community | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 56 | `@types/node` | 26.6.6 | 26.6.6 (current, 2026-11-14) | MIT | direct | DefinitelyTyped community (types published under Microsoft-run @types scope) | moderate (established, purpose-fit, not mainstream-scale) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 57 | `@vitest/coverage-v8` | 5.1.0 | 5.1.0 (current, 2026-11-14) | MIT | direct | vitest-dev (same team as vitest) | moderate (established, purpose-fit, not mainstream-scale) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Approved -- #74 |
| 58 | `@vitest/istanbul-lib-coverage` | 1.0.1 | 1.0.1 | MIT | transitive | vitest-dev | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 59 | `@vitest/istanbul-lib-report` | 1.0.1 | 1.0.1 | MIT | transitive | vitest-dev | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 60 | `@vitest/mocker` | 5.0.0 | 5.0.1 | MIT | transitive | vitest-dev | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 61 | `@vitest/spy` | 5.0.0 | 5.0.1 | MIT | transitive | vitest-dev | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 62 | `acorn` | 8.18.0 | 8.18.0 | MIT | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 63 | `ansi-regex` | 5.0.1 | 6.3.0 | MIT | transitive | Testing Library org (transitive via `@testing-library/svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 64 | `ansi-styles` | 5.2.0 | 7.0.0 | MIT | transitive | Testing Library org (transitive via `@testing-library/svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 65 | `aria-query` | 5.3.0 | 5.3.2 | Apache-2.0 | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 66 | `assertion-error` | 2.0.1 | 2.0.1 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 67 | `ast-v8-to-istanbul` | 1.0.6 | 1.0.6 | MIT | transitive | vitest-dev (transitive via `@vitest/coverage-v8`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 68 | `axobject-query` | 4.1.0 | 4.1.0 | Apache-2.0 | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 69 | `bcp-47` | 2.1.2 | 2.1.2 (current, 2026-11-14) | MIT | transitive | Titus Wormer (wooorm, independent; transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 70 | `bcp-47-match` | 2.0.3 | 2.0.3 (current, 2026-11-14) | MIT | transitive | Titus Wormer (wooorm, independent; transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 71 | `chai` | 6.2.2 | 6.2.2 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 72 | `chokidar` | 4.0.3 | 5.0.0 | MIT | transitive | Svelte core team (transitive via `svelte-check`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 73 | `clsx` | 2.1.1 | 2.1.1 | MIT | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 74 | `data-urls` | 7.0.0 | 7.0.0 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 75 | `decimal.js` | 10.6.0 | 10.6.0 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 76 | `deepmerge` | 4.3.1 | 4.3.1 | MIT | transitive | Svelte core team (transitive via `@sveltejs/vite-plugin-svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 77 | `dequal` | 2.0.3 | 2.0.3 | MIT | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 78 | `detect-libc` | 2.1.2 | 2.1.2 | Apache-2.0 | transitive | VoidZero / Vite team (transitive via `vite`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 79 | `devalue` | 5.9.2 | 6.0.0 | MIT | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 80 | `dom-accessibility-api` | 0.5.16 | 0.7.1 | MIT | transitive | Testing Library org (transitive via `@testing-library/svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 81 | `entities` | 8.1.0 | 8.1.0 | BSD-2-Clause | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 82 | `es-module-lexer` | 2.3.2 | 3.0.2 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 83 | `esm-env` | 1.2.2 | 1.2.2 | MIT | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 84 | `esrap` | 2.3.7 | 2.3.7 | MIT | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 85 | `estree-walker` | 3.0.3 | 3.0.3 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 86 | `expect-type` | 1.4.0 | 1.4.0 | Apache-2.0 | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 87 | `fdir` | 6.5.0 | 6.5.0 | MIT | transitive | Svelte core team (transitive via `svelte-check`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 88 | `fsevents` | 2.3.3 | 2.3.3 | MIT | transitive | VoidZero / Vite team (transitive via `vite`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 89 | `html-encoding-sniffer` | 6.0.0 | 6.0.0 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 90 | `is-alphabetical` | 2.0.1 | 2.0.1 (current, 2026-11-14) | MIT | transitive | Titus Wormer (wooorm, independent; transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 91 | `is-alphanumerical` | 2.0.1 | 2.0.1 (current, 2026-11-14) | MIT | transitive | Titus Wormer (wooorm, independent; transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 92 | `is-decimal` | 2.0.1 | 2.0.1 (current, 2026-11-14) | MIT | transitive | Titus Wormer (wooorm, independent; transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 93 | `is-potential-custom-element-name` | 1.0.1 | 1.0.1 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 94 | `is-reference` | 3.0.3 | 3.0.3 | MIT | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 95 | `js-tokens` | 10.0.0 | 10.0.0 | MIT | transitive | vitest-dev (transitive via `@vitest/coverage-v8`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 96 | `jsdom` | 31.0.0 | 31.0.1 (published 2026-11-13, under the 3-day age rule; 31.0.0 pinned) -- approved by the owner 2026-11-14 (#204), with its six new packages | MIT | direct | jsdom org, led by Domenic Denicola | very high (mainstream, widely deployed) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 97 | `lightningcss` | 1.33.0 | 1.33.0 | MPL-2.0 | transitive | VoidZero / Vite team (transitive via `vite`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 98 | `locate-character` | 3.0.0 | 3.0.0 | MIT | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 99 | `lru-cache` | 11.5.2 | 11.5.3 | BlueOak-1.0.0 | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 100 | `lz-string` | 1.5.0 | 1.5.0 | MIT | transitive | Testing Library org (transitive via `@testing-library/svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 101 | `magic-string` | 1.3.1 | 1.4.1 | MIT | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 102 | `magicast` | 0.5.5 | 0.5.5 | MIT | transitive | vitest-dev (transitive via `@vitest/coverage-v8`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 103 | `mri` | 1.2.0 | 1.2.0 | MIT | transitive | Svelte core team (transitive via `svelte-check`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 104 | `nanoid` | 3.3.19 | 6.0.1 | MIT | transitive | VoidZero / Vite team (transitive via `vite`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 105 | `obug` | 2.2.1 | 3.0.0 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 106 | `parse5` | 8.0.1 | 8.0.1 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 107 | `parse5-parser-stream` | 8.1.1 | 8.1.1 (current, 2026-11-14) | MIT | transitive | jsdom org / parse5 (Ivan Nikulin; transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 108 | `picocolors` | 1.1.1 | 1.1.1 | ISC | transitive | Svelte core team (transitive via `svelte-check`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 109 | `picomatch` | 4.0.7 | 4.0.7 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 110 | `pixelmatch` | 7.2.0 | 8.0.0 (2026-11-14); held at 7.x, see #211 | ISC | direct | mapbox-originated, now independent (community) | moderate (established, purpose-fit, not mainstream-scale) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 111 | `playwright` | 1.65.0 | 1.65.0 (current, 2026-11-14; 1.65.1 of 2026-11-13 is under the 3-day age rule) | Apache-2.0 | direct | Microsoft | very high (mainstream, widely deployed) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 112 | `playwright-core` | 1.63.0 | 1.63.0 | Apache-2.0 | transitive | Microsoft (transitive via `playwright`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 113 | `pngjs` | 7.0.0 | 7.0.0 | MIT | direct | independent (lukeapage / community) | moderate (established, purpose-fit, not mainstream-scale) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 114 | `postcss` | 8.5.28 | 8.5.28 | MIT | transitive | VoidZero / Vite team (transitive via `vite`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 115 | `pretty-format` | 27.5.1 | 30.5.1 | MIT | transitive | Testing Library org (transitive via `@testing-library/svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 116 | `punycode` | 2.3.1 | 2.3.1 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 117 | `react-is` | 17.0.2 | 19.3.0 | MIT | transitive | Testing Library org (transitive via `@testing-library/svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 118 | `readdirp` | 4.1.2 | 5.1.1 | MIT | transitive | Svelte core team (transitive via `svelte-check`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 119 | `rolldown` | 1.2.8 | 1.2.9 | MIT | transitive | VoidZero / Vite team (transitive via `vite`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 120 | `sade` | 1.8.1 | 1.8.1 | MIT | transitive | Svelte core team (transitive via `svelte-check`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 121 | `saxes` | 6.0.0 | 6.0.0 | ISC | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 122 | `source-map-js` | 1.2.1 | 1.2.1 | BSD-3-Clause | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 123 | `std-env` | 4.2.0 | 4.2.0 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 124 | `svelte` | 5.57.3 | 5.57.3 (current, 2026-11-14) | MIT | direct | Svelte core team (Rich Harris et al, Vercel-sponsored) | very high (mainstream, widely deployed) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 125 | `svelte-check` | 4.7.8 | 4.7.8 (current, 2026-11-14) | MIT | direct | Svelte core team | moderate (established, purpose-fit, not mainstream-scale) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 126 | `tinybench` | 6.1.4 | 6.2.0 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 127 | `tinyexec` | 1.3.0 | 1.3.1 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 128 | `tinyglobby` | 0.2.17 | 0.2.17 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 129 | `tinyrainbow` | 3.1.1 | 3.1.1 | MIT | transitive | vitest-dev (transitive via `@vitest/coverage-v8`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 130 | `tldts` | 7.4.12 | 7.4.13 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 131 | `tldts-core` | 7.4.12 | 7.4.13 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 132 | `tough-cookie` | 6.0.2 | 6.0.2 | BSD-3-Clause | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 133 | `tr46` | 6.0.0 | 6.0.0 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 134 | `tslib` | 2.9.1 | 2.9.1 (current, 2026-11-14) | 0BSD | transitive | Microsoft (optional, via `@rolldown/binding-wasm32-wasi`, via `vite`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 135 | `typescript` | 6.0.3 | 7.0.2 | Apache-2.0 | direct | Microsoft | very high (mainstream, widely deployed) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 136 | `undici` | 8.10.2 | 8.10.2 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 137 | `undici-types` | 6.21.0 | 8.10.2 | MIT | transitive | Node.js/undici project (bundled into @types/node) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 138 | `vite` | 8.3.8 | 8.3.8 (current, 2026-11-14) -- approved by the owner 2026-11-14 (#204), with rolldown 1.2.19's seven new optional wasm packages | MIT | direct | VoidZero (Evan You's company) / Vite team | very high (mainstream, widely deployed) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 139 | `vitefu` | 1.1.3 | 1.1.3 | MIT | transitive | Svelte core team (transitive via `@sveltejs/vite-plugin-svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 140 | `vitest` | 5.1.0 | 5.1.0 (current, 2026-11-14) | MIT | direct | vitest-dev (Anthony Fu and collaborators, Vite ecosystem) | very high (mainstream, widely deployed) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 141 | `w3c-xmlserializer` | 5.0.0 | 5.0.0 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 142 | `webidl-conversions` | 8.0.1 | 8.0.1 | BSD-2-Clause | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 143 | `whatwg-mimetype` | 5.0.0 | 5.0.0 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 144 | `whatwg-url` | 16.0.1 | 17.1.1 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 145 | `why-is-node-running` | 2.3.0 | 3.2.2 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 146 | `xml-name-validator` | 5.0.0 | 5.0.0 | Apache-2.0 | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 147 | `xmlchars` | 2.2.0 | 2.2.0 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 148 | `zimmerframe` | 1.1.5 | 1.1.5 | MIT | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 149 | `lightningcss-*` (11 per-platform prebuilt binaries, grouped for readability) | 1.33.0 (all 11 pinned to the same version) | 1.33.0 | MPL-2.0 | transitive | lightningcss project (Devon Govett), prebuilt native binaries pulled in via vite | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 150 | `@rolldown/binding-*` (15 per-platform prebuilt binaries, grouped for readability) | 1.2.8 (all 15 pinned to the same version) | 1.2.9 | MIT | transitive | VoidZero / Rolldown team, prebuilt native binaries pulled in via vite | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 231 | `qrcode-generator` | 2.0.4 (exact, no caret) | 2.0.4 | MIT | direct | Kazuhiko Arase (independent; the library's author since its first release) | high (about 8.6 million npm downloads a week, 2026-11-08 to 2026-11-14) | **Shipped** -- in the frontend bundle: draws the authenticator QR code on the sign-in door's "Prove it works" screen (`frontend/src/door/qr.ts`); no dependencies of its own | Approved -- owner, 2026-11-15, #8 (29a) |

### C. OpenCanary, `build/opencanary/requirements.txt` (uv-compiled from `requirements.in`, hash-pinned; moved out of the mockingbird image by issue #132, unchanged otherwise)

| # | Dependency | Pinned | Latest upstream (verified 2026-09-20, spot-checked 2026-09-22) | Licence | Direct/Transitive | Maintainer | Popularity signal | Shipped / dev-CI-only | Approval status |
|---|---|---|---|---|---|---|---|---|---|
| 151 | `attrs` | 26.1.0 | 26.1.0 | MIT | transitive | attrs community (Hynek Schlawack) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 152 | `automat` | 25.4.16 | 25.4.16 | MIT | transitive | Twisted Matrix Labs / Glyph Lefkowitz | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 153 | `bcrypt` | 3.2.0 | 5.0.0 | Apache-2.0 | transitive | Python Cryptographic Authority (PyCA) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 154 | `certifi` | 2026.10.23 | 2026.10.23 (current, 2026-11-14) | MPL-2.0 | transitive | certifi community (Kenneth Reitz-founded, Mozilla CA bundle repack) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 155 | `cffi` | 2.1.1 | 2.1.1 | MIT-0 | transitive | PyPy/CFFI team | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 156 | `charset-normalizer` | 3.5.2 | 3.5.2 (current, 2026-11-14) | MIT | transitive | independent (Ahmed TAHRI / community) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 157 | `constantly` | 23.10.4 | 23.10.4 | MIT | transitive | Twisted Matrix Labs | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 158 | `cryptography` | 50.0.2 | 50.0.2 (current, 2026-11-14) | Apache-2.0 OR BSD-3-Clause | transitive | Python Cryptographic Authority (PyCA) | very high (mainstream, widely deployed) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 159 | `gitdb` | 4.0.12 | 4.0.12 | BSD-3-Clause | transitive | GitPython community | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 160 | `gitpython` | 3.2.1 | 3.2.1 (current, 2026-11-14) | BSD-3-Clause | transitive | GitPython community (Byron / Sebastian Thiel) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 161 | `hpfeeds` | 3.0.0 | 3.1.0 | GPL-3.0 | transitive | Honeynet Project lineage (Mark Schloesser and contributors) -- independent of opencanary/Thinkst | high (the standard choice for its niche) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 162 | `hyperlink` | 21.0.0 | 21.0.0 | MIT | transitive | Twisted Matrix Labs | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 163 | `idna` | 3.20 | 3.20 | BSD-3-Clause | transitive | independent (Kim Davies) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 164 | `incremental` | 24.11.0 | 24.11.0 | MIT | transitive | Twisted Matrix Labs | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 165 | `jinja2` | 3.1.6 | 3.1.6 | BSD-3-Clause | transitive | Pallets project (Flask/Jinja maintainers) | very high (mainstream, widely deployed) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 166 | `markupsafe` | 3.0.4 | 3.0.4 (current, 2026-11-14) | BSD-3-Clause | transitive | Pallets project | very high (mainstream, widely deployed) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 167 | `ntlmlib` | 0.72 | 0.72 | Apache-2.0 | transitive | OpenCanary project's own vendored fork lineage | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 168 | `opencanary` | 0.9.10 | 0.9.10 | BSD-3-Clause (own code; bundled Synology and Ext JS skin assets not covered, #176) | direct | Thinkst Applied Research | high (the standard choice for its niche) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | Predates the rule -- not individually recorded |
| 169 | `ordereddict` | 1.1 | 1.1 | MIT | transitive | backport of stdlib's collections.OrderedDict (independent packaging) | small utility (popularity tracks its direct parent) | Removed by #101 -- ntlmlib's Python-2 `OrderedDict` fallback import never ran on this image's Python 3.13, so the lock drops the pin instead of shipping dead weight | n/a -- transitive |
| 170 | `packaging` | 26.3 | 26.3 | Apache-2.0 OR BSD-2-Clause | transitive | Python Packaging Authority (PyPA) | very high (mainstream, widely deployed) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 171 | `passlib` | 1.7.1 | 1.7.4 | BSD | transitive | independent (Eli Collins, effectively unmaintained) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 172 | `pyasn1` | 0.6.4 | 0.6.4 (held by opencanary 0.9.10's exact pin; newest 0.6.5 / 26.10.0) | BSD-2-Clause | transitive | pyasn1 community | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 173 | `pyasn1-modules` | 0.4.2 | 0.4.2 | BSD-2-Clause | transitive | pyasn1 community | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 174 | `pycparser` | 3.12 | 3.12 (current, 2026-11-14) | BSD-3-Clause | transitive | independent (Eli Bendersky) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 175 | `pyopenssl` | 26.3.0 | 26.4.0 | Apache-2.0 | transitive | Python Cryptographic Authority (PyCA) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 176 | `redis` | 7.4.0 | 8.1.0 | MIT | transitive | Redis Inc. (redis-py client) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 177 | `requests` | 2.33.0 | 2.34.2 | Apache-2.0 | transitive | psf/requests community (Kenneth Reitz-founded, now community-run) | very high (mainstream, widely deployed) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 178 | `service-identity` | 21.1.0 | 26.1.0 | MIT | transitive | Hynek Schlawack (independent, PyCA-adjacent) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 179 | `setuptools` | 83.0.0 | 84.0.0 | MIT | transitive | Python Packaging Authority (PyPA) | very high (mainstream, widely deployed) | Removed by #179 -- opencanary declares it but nothing the image runs imports it, and it vendors autocommand (LGPLv3), so the lock drops the pin (`--no-emit-package setuptools`) | n/a -- transitive |
| 180 | `simplejson` | 3.16.0 | 4.1.2 | MIT OR AFL-2.1 | transitive | independent (Bob Ippolito / community) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 181 | `six` | 1.17.0 | 1.17.0 | MIT | transitive | Benjamin Peterson (independent, in maintenance mode) | very high (mainstream, widely deployed) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 182 | `smmap` | 5.0.3 | 5.0.3 | BSD-3-Clause | transitive | GitPython community | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 183 | `twisted` | 26.4.0 | 26.4.0 (held by opencanary 0.9.10's exact pin; newest 0.6.5 / 26.10.0) | MIT | transitive | Twisted Matrix Labs | very high (mainstream, widely deployed) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 184 | `typing-extensions` | 4.16.0 | 4.16.0 | PSF-2.0 | transitive | Python typing SIG (CPython-adjacent) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 185 | `urllib3` | 2.7.0 | 2.8.0 | MIT | transitive | urllib3 community (Andrey Petrov-founded) | very high (mainstream, widely deployed) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |
| 186 | `zope-interface` | 7.2 | 8.6 | ZPL-2.1 | transitive | Zope Foundation | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the opencanary image (build/opencanary -- moved out of mockingbird by issue #132) | n/a -- transitive |

### D. Container base images (`build/birdcage/Dockerfile`, `build/mockingbird/Dockerfile`, `build/holder/Dockerfile`, `build/nightjar/Dockerfile`)

| # | Dependency | Pinned | Latest upstream (verified 2026-09-20, spot-checked 2026-09-22) | Licence | Direct/Transitive | Maintainer | Popularity signal | Shipped / dev-CI-only | Approval status |
|---|---|---|---|---|---|---|---|---|---|
| 187 | `node:26-alpine` | 26-alpine (resolves to 26.9.0-alpine, verified via Docker Hub) | 26.9.0-alpine (current -- Node 26 is still on the "Current" release line, not yet LTS) | MIT (Node.js) | direct | OpenJS Foundation (Node.js), image built by the Docker Official Images team | very high (mainstream, widely deployed) | Build-only -- build stage, discarded before the runtime image | Predates the rule -- not individually recorded |
| 188 | `golang:1.27.4-alpine` (by digest) | 1.27.4-alpine, pinned by index digest (#188) | 1.27.4-alpine (current, 2026-11-13) | BSD-3-Clause (Go) + Alpine's own licences | direct | Go team (Google), image built by the Docker Official Images team | very high (mainstream, widely deployed) | Build-only -- build stage, discarded before the runtime image | Predates the rule -- not individually recorded |
| 189 | `gcr.io/distroless/static-debian13:nonroot` | static-debian13:nonroot (floating tag, no digest pin) | Current -- "debian13" (trixie) is Google's latest distroless generation; no newer generation tag exists yet. | Apache-2.0 (distroless project) | direct | Google (GoogleContainerTools/distroless) | high (the standard choice for its niche) | Shipped -- the shipped runtime base image | Predates the rule -- not individually recorded |
| 190 | `gcr.io/distroless/python3-debian13:nonroot` | python3-debian13:nonroot (floating tag, no digest pin) | Current -- same distroless generation as above. | Apache-2.0 (distroless project) | direct | Google (GoogleContainerTools/distroless) | high (the standard choice for its niche) | Shipped -- the shipped runtime base image | Predates the rule -- not individually recorded |
| 191 | `python:3.13-slim-trixie` | 3.13-slim-trixie | 3.13.13-slim-trixie is the current patch, but Python 3.14 is now the latest major release line (endoflife.date, verified). | PSF-2.0 (CPython) + Debian's licences | direct | Python Software Foundation, image built by the Docker Official Images team | very high (mainstream, widely deployed) | Build-only -- build stage, discarded before the runtime image | Predates the rule -- not individually recorded |
| 227 | `golang:1.27.4-alpine` (by digest) (holder's build stage) | 1.27.4-alpine, pinned by index digest (#188) | 1.27.4-alpine (current, 2026-11-13) | BSD-3-Clause (Go) + Alpine's own licences | direct | Go team (Google), image built by the Docker Official Images team | very high (mainstream, widely deployed) | Build-only -- build stage in `build/holder/Dockerfile`, discarded before the `scratch` runtime image | Predates the rule -- not individually recorded |
| 228 | `golang:1.27.4-alpine` (by digest) (nightjar's build stage) | 1.27.4-alpine, pinned by index digest (#188) | 1.27.4-alpine (current, 2026-11-13) | BSD-3-Clause (Go) + Alpine's own licences | direct | Go team (Google), image built by the Docker Official Images team | very high (mainstream, widely deployed) | Build-only -- build stage in `build/nightjar/Dockerfile`, discarded before the distroless runtime image (row 189) | Predates the rule -- not individually recorded |
| 230 | `git (apk package, birdcage's Go build stage)` | `2.54.1-r0`, pinned exactly -- `apk add --no-cache git=2.54.1-r0` in the `backend` stage of `build/birdcage/Dockerfile` | `2.54.1-r0` -- current in Alpine 3.24's `main` repository, read with `apk policy git` in the stage's own pinned `golang:1.27.4-alpine` image, 2026-11-13 (2.54.0-r0 withdrawn) | GPL-2.0-only | direct | Git project (Software Freedom Conservancy), packaged by Alpine Linux | very high (mainstream, widely deployed) | Build-only -- lets `go mod download` fetch `github.com/tomlawesome/gauntlet` from its Git host with `GOPRIVATE` set, never through proxy.golang.org (ADR-0016 decision 1); the runtime stage copies only `/out/birdcage` and `/var/lib/birdcage`, so git never ships. `scripts/go-fetch-guard.py` (`lint:ci`) refuses git in any other image or in a final stage | Approved -- #8, owner, 2026-10-10 (answer 3a): "if git doesn't end up in any user images, that's fine" |

### E. CI runner images, `.gitlab-ci.yml` (not shipped -- only run the pipeline's own jobs)

| # | Dependency | Pinned | Latest upstream (verified 2026-09-20, spot-checked 2026-09-22) | Licence | Direct/Transitive | Maintainer | Popularity signal | Shipped / dev-CI-only | Approval status |
|---|---|---|---|---|---|---|---|---|---|
| 192 | `alpine:3.24` | 3.24 (floating minor) | 3.24.2 is the current patch (already what the floating tag resolves to). | MIT (Alpine) | direct | Alpine Linux project | very high (mainstream, widely deployed) | **Shipped** -- corrected 2026-09-23 (#87). It is the runtime base of `build/smb-lure/Dockerfile`, so it now ships. It remains a CI runner image here, and is build-only in `build/nightjar/Dockerfile`, whose `grype` stage uses it and is discarded before that image's distroless runtime. | Predates the rule -- not individually recorded |
| 193 | `golang:1.27.4` (by digest) | 1.27.4, pinned by index digest (#188; the floating `1.27` tag moved to 1.27.4 under open merge requests) | 1.27.4 is current (go.dev/dl, 2026-11-13). | BSD-3-Clause (Go) | direct | Go team (Google), Docker Official Images | very high (mainstream, widely deployed) | CI-only -- CI runner/service image, never shipped | Predates the rule -- not individually recorded |
| 194 | `python:3.15-alpine` | 3.15-alpine (floating minor) | 3.15-alpine (current, 2026-11-14); 3.15.2 checked with every job that uses it | PSF-2.0 (CPython) + Alpine's licences | direct | Python Software Foundation, Docker Official Images | very high (mainstream, widely deployed) | CI-only -- CI runner/service image, never shipped | Predates the rule -- not individually recorded |
| 195 | `node:22-trixie` | 22-trixie (floating minor) | 22.22-trixie is the current patch; Node 22 ("Jod") is the active LTS line, verified via nodejs.org. | MIT (Node.js) | direct | OpenJS Foundation (Node.js), Docker Official Images | very high (mainstream, widely deployed) | CI-only -- CI runner/service image, never shipped | Predates the rule -- not individually recorded |
| 196 | `postgres:17-alpine` | 17-alpine (floating minor, `test:go` service container) | 17-alpine3.24 is the current patch. | PostgreSQL Licence | direct | PostgreSQL Global Development Group, Docker Official Images | very high (mainstream, widely deployed) | CI-only -- CI runner/service image, never shipped | Predates the rule -- not individually recorded |
| 197 | `docker:29-cli` | 29-cli (floating major) | Already the current tag (Docker Hub shows no newer `NN-cli` major). | Apache-2.0 (Docker CLI) | direct | Docker Inc. | very high (mainstream, widely deployed) | CI-only -- CI runner/service image, never shipped | Predates the rule -- not individually recorded |

### F. Fetched at build or test time (not base images, but named artifacts pulled in by the pipeline)

| # | Dependency | Pinned | Latest upstream (verified 2026-09-20, spot-checked 2026-09-22) | Licence | Direct/Transitive | Maintainer | Popularity signal | Shipped / dev-CI-only | Approval status |
|---|---|---|---|---|---|---|---|---|---|
| 198 | `golangci-lint` | v2.15.0 (`go install .../golangci-lint/v2@v2.15.0` in `lint:go`) | v2.15.0 (verified via GitHub releases API) -- current, 2026-11-14 (v2.15.0 released 2026-10-16, GitHub releases API). | GPL-3.0 | direct | golangci-lint community (OSS org) | very high (mainstream, widely deployed) | CI/release-only -- fetched at build/test/release time, never shipped | Predates the rule -- not individually recorded |
| 199 | `go1.27.4 (tarball)` | go1.27.4.linux-amd64.tar.gz, fetched by `curl` from go.dev/dl in `test:smoke` | go1.27.4 is current (go.dev/dl, verified 2026-11-13) -- already current, matching the Dockerfiles' pinned Go. | BSD-3-Clause (Go) | direct | Go team (Google) | moderate (established, purpose-fit, not mainstream-scale) | CI/release-only -- fetched at build/test/release time, never shipped | Predates the rule -- not individually recorded |
| 200 | `libcap (apk package)` | unpinned -- `apk add --no-cache libcap` in `build/mockingbird/Dockerfile`'s agent stage (Alpine picks whatever is current in its repo at build time) | Unverified -- Alpine's package index version wasn't checked this session; the package is unpinned so "latest" and "pinned" are the same moving target. | Dual BSD-3-Clause / GPL-2.0-only per upstream's own COPYING file -- not confirmed against a registry API this session, so treat as a claim to verify rather than fact. | direct | Linux libcap upstream (Andrew G. Morgan et al), packaged by Alpine | moderate (established, purpose-fit, not mainstream-scale) | CI/release-only -- fetched at build/test/release time, never shipped | Predates the rule -- not individually recorded |
| 201 | `postgresql-client (apt package)` | unpinned -- `apt-get install -y postgresql-client` in `test:go` | Unverified -- Debian's current package version wasn't checked this session. | PostgreSQL Licence | direct | PostgreSQL Global Development Group, packaged by Debian | moderate (established, purpose-fit, not mainstream-scale) | CI/release-only -- fetched at build/test/release time, never shipped | Predates the rule -- not individually recorded |
| 202 | `pyyaml (pip package)` | unpinned -- `pip install --quiet pyyaml` in `lint:ci` | 6.0.3 (PyPI JSON API, verified). | MIT | direct | PyYAML community | moderate (established, purpose-fit, not mainstream-scale) | CI/release-only -- fetched at build/test/release time, never shipped | Predates the rule -- not individually recorded |
| 203 | `bash (apk package)` | unpinned -- `apk add --no-cache bash` in `lint:ci` and every `e2e:*` job | Unverified -- Alpine's current package version wasn't checked this session. | GPL-3.0-or-later (GNU project; not confirmed against a registry API this session). | direct | GNU Project, packaged by Alpine | moderate (established, purpose-fit, not mainstream-scale) | CI/release-only -- fetched at build/test/release time, never shipped | Predates the rule -- not individually recorded |
| 220 | `Responder` (fixture image, `registry.tomlawson.io/ai/birdcage-fixtures/poisoner-fixture`, pulled by digest) | the `E2E_POISONER_FIXTURE_DIGEST` pin in `.gitlab-ci.yml` (`e2e:poisoner`), published once by the fixtures project (#127) and pulled by digest | v3.2.2.0 is the newest upstream tag (verified 2026-09-24 via `git ls-remote --tags https://github.com/lgandx/Responder`); the fixtures project records which tag its image was built from, and moving the digest here is the version check. | GPL-3.0 | direct | Laurent Gaffie (lgandx); image built, scanned and published by the private `ai/birdcage-fixtures` project | high (the reference LLMNR/NBT-NS/mDNS poisoner; what #86 exists to catch) | CI-only -- `e2e:poisoner`'s sibling container, pulled by `scripts/ci-ensure-image.sh`, never built here and never in any shipped image | Directed by the coordinator for #86 slice C as CI-only; **the owner has not individually approved it** -- see "What needs the owner's attention". Owner, 2026-09-24 (#86, 45b): built once in the private fixtures project, never in this repository |
| 221 | `debian:trixie-slim` (base of `build/e2e-samba` and `build/e2e-snmp`) | trixie-slim (floating minor) | Unverified -- Debian's current point release wasn't checked this session; the tag is floating, so "latest" and "pinned" are the same moving target. | Mixed, Debian main (DFSG-free) | direct | Debian project, Docker Official Images | very high (mainstream, widely deployed) | CI-only -- journey fixture image, never shipped | Predates the rule -- recorded here because the fixtures' packages were not; the Responder fixture no longer uses it in this repository (#127) |

### G. GitHub Actions, `.github/workflows/*.yml` (CodeQL + dependency review mirror only -- GitLab is where the gate actually runs)

| # | Dependency | Pinned | Latest upstream (verified 2026-09-20, spot-checked 2026-09-22) | Licence | Direct/Transitive | Maintainer | Popularity signal | Shipped / dev-CI-only | Approval status |
|---|---|---|---|---|---|---|---|---|---|
| 204 | `actions/checkout` | v7.0.1 (commit `3d3c42e...`, verified that commit tags v7.0.1) | v7.0.1 -- already current (GitHub releases API, verified). | MIT | direct | GitHub | very high (mainstream, widely deployed) | CI-only -- GitHub Actions mirror pipeline only | Predates the rule -- not individually recorded |
| 205 | `github/codeql-action/init` | v4.39.3 (commit `33d7b85da...`) | v4.39.3 (current, 2026-11-14) | MIT | direct | GitHub | very high (mainstream, widely deployed) | CI-only -- GitHub Actions mirror pipeline only | Predates the rule -- not individually recorded |
| 206 | `github/codeql-action/analyze` | v4.39.3 (commit `33d7b85da...`) | v4.39.3 (current, 2026-11-14) | MIT | direct | GitHub | very high (mainstream, widely deployed) | CI-only -- GitHub Actions mirror pipeline only | Predates the rule -- not individually recorded |
| 207 | `actions/dependency-review-action` | v5.0.0 (commit `a1d282b...`) | v5.0.0 -- already current (GitHub releases API, verified). | MIT | direct | GitHub | very high (mainstream, widely deployed) | CI-only -- GitHub Actions mirror pipeline only | Predates the rule -- not individually recorded |

Every `uses:` pin above (and `actions/checkout` in `countersign.yml`, row 217) is
also recorded in `supply-chain/action-pins.json` -- issue #27's adoption of
orbit's supply-chain-policy shape, which records *when* a pin was last
reviewed, not only that it is pinned. `scripts/action-pins-check.py`, run in
`lint:ci`, fails if a `uses:` pin is unrecorded, not a full commit SHA, or
disagrees with its recorded version.

### H. Found in this review but missing from the issue #73 table (2026-09-20 comment) -- `.gitlab-ci.yml` and `.github/workflows/countersign.yml`

The 2026-09-20 table covered `.gitlab-ci.yml`'s `image:` and `services:` lines fairly completely, but missed several packages fetched inline inside job scripts, one CI image, and a whole GitHub Actions workflow file that did not exist (or was not read) at review time. Numbering continues from 211.

| # | Dependency | Pinned | Latest upstream (verified 2026-09-22) | Licence | Direct/Transitive | Maintainer | Popularity signal | Shipped / dev-CI-only | Approval status |
|---|---|---|---|---|---|---|---|---|---|
| 208 | `registry.gitlab.com/gitlab-org/release-cli:latest` | `latest` (floating, no digest pin) | No newer tagged release found; upstream project is in maintenance mode -- GitLab's own docs point new work at `glab` instead. | MIT | direct | GitLab | high (bundled with every GitLab installation) | CI-only -- `release:gitlab` job image, never shipped | Predates the rule -- not individually recorded |
| 209 | `openssl (apk package)` | unpinned -- `apk add --no-cache openssl` in several `e2e:*`/`test:go` jobs | Unverified -- Alpine package index version not checked this session. | Apache-2.0 | direct | OpenSSL project | very high (mainstream, widely deployed) | CI-only -- generates test/e2e TLS material, never shipped | Predates the rule -- not individually recorded |
| 210 | `openssl (apt package)` | unpinned -- `apt-get -qq install -y postgresql-client openssl` in `test:go` | Unverified -- Debian package index version not checked this session. | Apache-2.0 | direct | OpenSSL project, packaged by Debian | very high (mainstream, widely deployed) | CI-only -- captures the Postgres service container's TLS cert, never shipped | Predates the rule -- not individually recorded |
| 211 | `curl (apk package)` | unpinned -- `RELEASE_APK_PACKAGES` (`bash curl python3`), installed by the `.registry_login` release anchor | Unverified -- Alpine package index version not checked this session. | curl licence (MIT-style) | direct | curl project (Daniel Stenberg et al) | very high (mainstream, widely deployed) | CI/release-only -- release-job HTTP calls, never shipped | Predates the rule -- not individually recorded |
| 212 | `git (apk package)` | unpinned -- `apk add --no-cache git` in `release:push` | Unverified -- Alpine package index version not checked this session. | GPL-2.0-only | direct | Git project (Software Freedom Conservancy) | very high (mainstream, widely deployed) | CI/release-only -- reads the merge commit's parents, never shipped | Predates the rule -- not individually recorded |
| 213 | `git (apk package, second job)` | unpinned -- `apk add --no-cache git openssh-client curl jq` in `sync:mirror-to-github` | Unverified this session. | GPL-2.0-only | direct | Git project | very high (mainstream, widely deployed) | CI-only -- mirrors `dev`/`preview`/`main` to GitHub over SSH, never shipped | Predates the rule -- not individually recorded |
| 214 | `openssh-client (apk package)` | unpinned -- same `sync:mirror-to-github` job as #216 | Unverified this session. | BSD-style (OpenSSH) | direct | OpenBSD/OpenSSH project | very high (mainstream, widely deployed) | CI-only -- same job as #216, never shipped | Predates the rule -- not individually recorded |
| 215 | `jq (apk package)` | unpinned -- same `sync:mirror-to-github` job as #216 | Unverified this session. | MIT | direct | jq project (independent, stedolan/jqlang) | very high (mainstream, widely deployed) | CI-only -- same job as #216, never shipped | Predates the rule -- not individually recorded |
| 216 | `cosign` | v3.1.4, checksum-pinned in `scripts/ensure-cosign.sh` (fetched by both the GitLab release jobs and GitHub's `countersign.yml`) | v3.1.4 (current, 2026-11-14) | Apache-2.0 | direct | sigstore project (Linux Foundation-hosted, OpenSSF) | high (the standard tool for keyless/key-based container signing) | Build/release-only -- signs and verifies image digests, never shipped in a product image | Predates the rule -- not individually recorded |
| 217 | `actions/checkout` (in `countersign.yml`) | v7.0.1 (commit `3d3c42e...`, the same SHA pin as row 204; was the floating `@v5` tag until the 2026-09-30 audit fix) | v7.0.1 -- already current (same check as row 204). | MIT | direct | GitHub | very high (mainstream, widely deployed) | CI-only -- countersigning workflow checkout, never shipped | Predates the rule -- not individually recorded |
### I. `build/nightjar/Dockerfile` (#108: the scanner agent's own image, landed in commit 4 of that issue's slice)

The pinned Grype release binary, and its vulnerability database -- the latter
is a **runtime feed, not a dependency**: never fetched by this Dockerfile,
never vendored, never baked into the image. Grype fetches and refreshes it
itself on the operator's own device, into the `nightjar-grype-db` volume
(ADR-0010 decision 2, and the house rule against vendoring lookup datasets).
It is listed here only so the feed itself, and the trust an operator places
in it, is not invisible to this inventory.

| # | Dependency | Pinned | Latest upstream (verified 2026-09-22) | Licence | Direct/Transitive | Maintainer | Popularity signal | Shipped / dev-CI-only | Approval status |
|---|---|---|---|---|---|---|---|---|---|
| 218 | `grype` (Anchore) | v0.121.3, `linux_amd64`, SHA-256 `e9da18cc1429e786722e32161288103600efffd8e483c90761f90485bd1bec85` -- pinned by both the version and the checksum in `build/nightjar/Dockerfile`'s `GRYPE_VERSION`/`GRYPE_SHA256` build args, verified against the release's own `grype_0.121.3_checksums.txt` and against a fresh download of the artefact itself (matched) | v0.121.3 (current, 2026-11-14; GitHub releases API, 5 days old; checksum re-verified against a fresh download) | Apache-2.0 | direct | Anchore | high (13k GitHub stars, ~147 contributors -- #108's own comparison record) | Shipped -- copied into the Nightjar runtime image as a pinned binary, never linked into any Go binary (the ledger above) | Approved -- #108, 2026-09-22 |
| 219 | Grype's vulnerability database | Not pinned by this repository at all -- fetched and refreshed by Grype itself at runtime into the `nightjar-grype-db` volume (`GRYPE_DB_CACHE_DIR`), never vendored or baked into the image. Grype's own default fail-closed behaviour (refuses a database older than five days) is kept unmodified. | N/A -- a live feed, not a versioned release this inventory tracks | Grype's own database build is Apache-2.0 per ADR-0010's engine comparison; the underlying vulnerability advisories it aggregates carry their own upstream licences (NVD, distro security trackers, GitHub advisories), which this repository never redistributes since the feed is fetched directly by the operator's own Nightjar instance, not by birdcage | direct (a runtime feed, not a code dependency) | Anchore (aggregates upstream vulnerability sources) | n/a -- not a popularity-ranked artefact | Runtime feed only -- never shipped in any image or binary | n/a -- a runtime feed, not a dependency in the sense this inventory otherwise tracks; recorded per this section's own header |

### J. `build/smb-lure/Dockerfile` (#87: the SMB lure's own image)

A real Samba, serving read-only guest shares beside a canary, in its own
image (ADR-0008). Two rows: the Samba package it runs, and the Python that
generates the share content in a build stage which is then discarded.

The base image is `alpine:3.24`, row 192 above -- which this image is the
reason to have corrected from "never shipped" to shipped.

| # | Dependency | Pinned | Latest upstream (verified 2026-09-23) | Licence | Direct/Transitive | Maintainer | Popularity signal | Shipped / dev-CI-only | Approval status |
|---|---|---|---|---|---|---|---|---|---|
| 223 | `samba-server` (apk package) | `4.23.8-r0`, pinned exactly in `build/smb-lure/Dockerfile` | `4.23.8-r0` -- current in Alpine 3.24's `main` repository, read from `apk policy samba` in the image itself, 2026-09-23. Samba's own current release line is 4.23.x. | GPL-3.0-or-later | direct | Samba Team, packaged by Alpine Linux | very high (mainstream, widely deployed -- it is what the NAS this image imitates actually runs) | Shipped -- it is the service the image exists to run. Unmodified upstream, in its own container, linked into no binary of ours: the same shape as `grype` in the scanner image (the ledger above, "Shipped as a binary in an agent image, never linked into birdcage") | Approved -- #87, owner, 2026-09-23 ("Real Samba on Alpine", decision 1). GPLv3 in a shipped image has the owner's precedent in `hpfeeds@3.0.0` (`supply-chain/licence-policy.yml`) |
| 224 | `python3` (apk package) | `3.14.10-r1`, pinned exactly in `build/smb-lure/Dockerfile` | `3.14.10-r1` -- current in Alpine 3.24's `main`, read from `apk policy python3` in the image, 2026-10-28 (#165: Alpine dropped 3.14.7-r1; 2026-10-28: it dropped 3.14.8-r0 too, failing build:images on every branch) | PSF-2.0 (CPython) + Alpine's own licences | direct | Python Software Foundation, packaged by Alpine Linux | very high (mainstream, widely deployed) | Build-only -- runs `make-bait.py` in a stage that is discarded; no Python reaches the shipped image | Predates the rule -- not individually recorded (a build-stage tool, the same footing as row 188) |

There is no licence gate covering apk packages. `scripts/licence-check.sh`
covers Go modules, `-npm` covers npm and `-python` covers the pip packages
in the mockingbird image; nothing reads an Alpine package's licence. So row
226's GPL-3.0-or-later is recorded and approved here and in the ledger above, and
is not enforced by CI. Worth closing if a third apk-pinned shipped package
ever appears.

### K. CI-only security scanners added by #51 and #28

Two new `lint`-stage jobs (`docs/ci-hops.md`), neither linked into
birdcage nor shipped in any image -- the same footing as `golangci-lint`
(row 198). Owner approval for both is recorded on their issues,
2026-09-27.

| # | Dependency | Pinned | Latest upstream (verified 2026-09-27) | Licence | Direct/Transitive | Maintainer | Popularity signal | Shipped / dev-CI-only | Approval status |
|---|---|---|---|---|---|---|---|---|---|
| 225 | `golang.org/x/vuln` (govulncheck) | v1.9.0, `go install .../govulncheck@v1.9.0` in `lint:govulncheck`, verified by the Go checksum database like every other module download | v1.9.0 -- current, 2026-11-14 (tag dated 2026-10-10, go.googlesource.com) | BSD-3-Clause | direct | Go team (golang.org/x) | high (the standard Go vulnerability scanner, maintained by the language team) | CI-only -- installed and run in `lint:govulncheck`, never imported by any package birdcage builds | Approved -- #51, owner, 2026-09-27 |
| 226 | `gitleaks` (gitleaks project) | v8.30.1, checksum-pinned (archive and extracted-binary SHA-256) in `scripts/ensure-gitleaks.sh`, verified against the release's own `gitleaks_8.30.1_checksums.txt` and against a fresh download of the archive itself (matched) | v8.30.1 -- current (GitHub releases API, verified 2026-09-27) | MIT | direct | gitleaks project (Zachary Rice and contributors) | high (the standard OSS secret-scanning tool; this project's own pre-commit gate already uses it) | CI-only -- installed and run in `lint:gitleaks`, never linked or shipped. The released binary, not the commercially-licensed `gitleaks-action` | Approved -- #28, owner, 2026-09-27 |
| 229 | `python3` (apk package, release jobs) | unpinned -- `RELEASE_APK_PACKAGES` in `.gitlab-ci.yml`, installed by the `.registry_login` release anchor and `test:release-scripts` | `python3-3.14.8-r0` -- what Alpine 3.24 in `docker:29-cli` installs, read with `apk policy python3`, 2026-10-02 | PSF-2.0 (CPython) + Alpine's own licences | direct | Python Software Foundation, packaged by Alpine Linux | very high (mainstream, widely deployed) | CI/release-only -- runs the evidence judge in `scripts/verify-validation-evidence.sh`, never shipped | Owner, 2026-09-30, #158: "python is safe. So it's fine." Same package as row 224 |

## Summary, by approval status

229 rows total (210 from the issue's own table, 10 found in section H, 2 in section I,
3 in section F, 2 in section J, 2 in section K, 2 more in section D found in this
review -- holder's and nightjar's own golang build stages -- and 1 more in section D
for #8: git in birdcage's Go build stage, row 229).

| Status | Rows |
|---|---|
| Approved, with issue number | 11 (`golang.org/x/net`+`x/sys` #65; `go-imap/v2`+`go-msgauth` #54; `@vitest/coverage-v8` #74; `grype` #108; `samba-server` #87; `golang.org/x/vuln` #51; `gitleaks` #28; `git` in birdcage's build stage #8; `qrcode-generator` #8, row 231) |
| Predates the rule -- flagged on #73, owner decision pending | 2 (`github.com/jackc/pgx/v5`, `modernc.org/sqlite`) |
| Predates the rule -- not individually recorded | 51 (every other **direct** dependency, including `debian:trixie-slim`, row 221, and holder's/nightjar's golang build stages, rows 227-228) |
| Newly added, not yet approved -- see "What needs the owner's attention" | 1 (`Responder`, row 220) |
| Runtime feed, not a dependency | 1 (Grype's vulnerability database, row 219) |
| n/a -- transitive | 163 |

`grype` (Anchore, Apache-2.0) now appears in section I, above: #108 commit 4
landed `build/nightjar/Dockerfile`, the manifest this row was waiting on.

## What needs the owner's attention

**A new third party, CI-only, not individually approved:** `Responder`
(row 220), GPL-3.0, built from upstream v3.2.2.0. It runs in a sibling
container in `e2e:poisoner` and is never linked into or copied into any
shipped image -- the same footing as `grype`, which the owner did approve
explicitly (the ledger above, #108). Two things worth a decision:

- The owner's rule is "no third-party module without the owner's explicit
  approval". This was added on the coordinator's direction for #86 slice C,
  which is not the owner's approval. It needs either that approval or a
  recorded exception.
- Where it is built. The owner ruled on 2026-09-24 (#86, decision 45b)
  that attack tooling is never built in this repository, whose mirror is
  public: the image is built, scanned and published once by the private
  `ai/birdcage-fixtures` project (#127) and this repository only pins its
  digest. The first build was published on 2026-09-24 and scanned before
  release (findings below). There is no published upstream image to pin
  instead: `lgandx/responder` does not exist on Docker Hub (checked
  2026-09-24) and Debian does not package it.
- Scan of the published image (grype, 2026-09-24): 8 Critical, 82 High,
  86 Medium, all in Debian base packages, not the tool. Every Critical is
  `libcurl`, marked "won't fix" by Debian, exploit probability near zero.
  Six Highs are fixable in principle but Debian trixie has not shipped the
  patched packages yet; the image's `apt-get upgrade` clears them on the
  next rebuild once it does. Accepted for a CI-only, isolated, throwaway
  fixture with no real attack surface.

**Journey fixture images were already unrecorded before this:**
`build/e2e-samba` and `build/e2e-snmp` build on `debian:trixie-slim` and
install Debian packages, and none of that appeared in this inventory. Row
224 records the base image now; the two fixtures' own packages are still
missing. Not fixed here because it is not this change's to fix.

**Unapproved and shipped, same footing as `x/net`/`x/sys` but never recorded:**
`golang.org/x/crypto` and `golang.org/x/time` are direct Go dependencies,
linked into the shipped binary, from the same Go-team family as `x/net` and
`x/sys` -- but unlike those two, neither is named in the ledger's approved
list. Worth either an explicit approval or a note that Go-team `x/*`
extensions are self-evidently fine as a category.

**Genuinely behind current upstream** (direct dependencies only; the full
table has more transitive gaps that don't need an owner decision):
- `typescript` 6.0.3 -> 7.0.2, a major version (row 135)
- `pixelmatch` 7.2.0 -> 8.0.0, held back on purpose (row 110): 8 measures
  colour difference differently, so the pixel gates' thresholds must be
  re-measured before moving (#211)
- `python:3.13-slim-trixie` / `python:3.13-alpine`: Python 3.14 is now the
  latest major line; no reason recorded for staying on 3.13 (rows 191, 194)
- `github/codeql-action/init`/`analyze` v4.37.6 -> v4.38.1, several releases
  behind on the security-scanning action itself (rows 205-206)
- `svelte` and `vitest`, one patch each behind (rows 124, 140) -- minor,
  listed for completeness

**Licence flags with a redistribution question:** `hpfeeds` (GPL-3.0,
transitive via `opencanary`, row 161) ships inside the mockingbird image --
already reviewed and accepted as a named exception in
`supply-chain/licence-policy.yml` (`allow-python-package-licenses:
hpfeeds@3.0.0`), so this is a confirmation, not a new finding. `golangci-lint`
(GPL-3.0, row 198), `bash` (GPL-3.0-or-later, row 203) and `git` (GPL-2.0-only,
rows 212-213) are also copyleft but CI-only and never shipped, so they raise
no distribution obligation. No other row's licence looked like it creates one.

**Found in this review, missing from the 2026-09-20 table (section H):**
- `registry.gitlab.com/gitlab-org/release-cli:latest` -- unpinned `:latest`
  tag, and upstream is in maintenance mode (GitLab's own docs point new work
  at `glab` instead).
- `.github/workflows/countersign.yml` pinned `actions/checkout@v5` -- a
  floating major tag two majors behind the `v7.0.1` the other two workflows
  pin by commit SHA. Fixed 2026-09-30: it now pins the same `v7.0.1`
  commit SHA as the other two. It is the one workflow holding `id-token:
  write` and `packages: write`, so a floating tag there was the worst
  place for one.
- Five more CI-only OS packages fetched via `apk`/`apt` inside job scripts
  (`openssl` x2, `curl`, `git` x2, `openssh-client`, `jq`), all unpinned,
  none previously listed.
- `cosign` v3.1.3, checksum-pinned in `scripts/ensure-cosign.sh` and used by
  both the GitLab release path and GitHub's countersigning workflow --
  confirmed still current.

Nothing above was changed, removed or re-pinned. This is the inventory; the
owner's per-row decisions and any resulting removal/replacement/upgrade
issues are a separate step, as #73 itself specifies.
