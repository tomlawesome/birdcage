# Dependency inventory

Read-only inventory for issue #73 ("Dependency review: list every third-party
dependency for owner approval"). Every direct and transitive third-party
dependency this project pulls in, from every manifest and pinned artifact
named in that issue: `go.mod`/`go.sum`, `frontend/package.json` +
`package-lock.json`, `build/birdcage/Dockerfile`, `build/mockingbird/Dockerfile`,
`build/mockingbird/requirements.txt` (+ `requirements.in`), `.gitlab-ci.yml`
and `.github/workflows/*.yml`.

Nothing here changes a dependency. Owner decisions on individual rows still
belong on issue #73; this file is the durable record those decisions can
point at, and the baseline the scheduled staleness check named in that
issue's addendum (2026-09-19: *"Third party dependencies must be checked for
staleness regularly by CI"*) should eventually diff against.

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
- **Approval status** -- read directly against `AGENTS.md`'s "Approved
  third-party modules" section as it stands on this branch, not a judgement
  call. Three states: **Approved -- #N** (recorded there by name), **Predates
  the rule -- flagged on #73** (the two rows AGENTS.md itself names as
  pending this review: `pgx/v5`, `modernc.org/sqlite`), and **Predates the
  rule -- not individually recorded** (everything else that is `direct`:
  original-architecture choices -- the Postgres/SQLite drivers aside -- that
  were never individually logged as approved, because the per-dependency
  approval practice postdates them). Transitive rows are marked **n/a --
  transitive**: nothing here asks the owner to approve a package nobody
  chose to depend on directly.

### A. Go module (`go.mod`, `go.sum`)

| # | Dependency | Pinned | Latest upstream (verified 2026-09-20, spot-checked 2026-09-22) | Licence | Direct/Transitive | Maintainer | Popularity signal | Shipped / dev-CI-only | Approval status (AGENTS.md) |
|---|---|---|---|---|---|---|---|---|---|
| 1 | `github.com/emersion/go-imap/v2` | v2.0.0-beta.8 | v2.0.0-beta.8 (proxy.golang.org, verified -- already current) | MIT | direct | emersion (independent OSS maintainer, GitHub handle "emersion") | high (the standard choice for its niche) | Shipped -- linked into the birdcage and/or mockingbird Go binary | Approved -- #54 |
| 2 | `github.com/emersion/go-msgauth` | v0.7.0 | v0.7.0 | MIT | direct | emersion | moderate (established, purpose-fit, not mainstream-scale) | Shipped -- linked into the birdcage and/or mockingbird Go binary | Approved -- #54 |
| 3 | `github.com/jackc/pgx/v5` | v5.11.0 | v5.11.0 | MIT | direct | jackc (Jack Christensen, independent maintainer) | high (the standard choice for its niche) | Shipped -- linked into the birdcage and/or mockingbird Go binary | Predates the rule -- flagged on #73 for owner decision |
| 4 | `golang.org/x/crypto` | v0.57.0 | v0.57.0 | BSD-3-Clause | direct | Go team (Google) | very high (mainstream, widely deployed) | Shipped -- linked into the birdcage and/or mockingbird Go binary | Predates the rule -- not individually recorded |
| 5 | `golang.org/x/net` | v0.59.0 | v0.59.0 | BSD-3-Clause | direct | Go team (Google) | very high (mainstream, widely deployed) | Shipped -- linked into the birdcage and/or mockingbird Go binary | Approved -- #65 |
| 6 | `golang.org/x/sys` | v0.48.0 | v0.48.0 | BSD-3-Clause | direct | Go team (Google) | very high (mainstream, widely deployed) | Shipped -- linked into the birdcage and/or mockingbird Go binary | Approved -- #65 |
| 7 | `golang.org/x/time` | v0.16.0 | v0.16.0 | BSD-3-Clause | direct | Go team (Google) | moderate (established, purpose-fit, not mainstream-scale) | Shipped -- linked into the birdcage and/or mockingbird Go binary | Predates the rule -- not individually recorded |
| 8 | `modernc.org/sqlite` | v1.57.0 | v1.59.0 | BSD-3-Clause | direct | cznic / modernc.org (Jan Mercl, independent maintainer) | high (the standard choice for its niche) | Shipped -- linked into the birdcage and/or mockingbird Go binary | Predates the rule -- flagged on #73 for owner decision |
| 9 | `github.com/dustin/go-humanize` | v1.0.1 | v1.1.0 | MIT | transitive | dustin (Dustin Sallings, independent) | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 10 | `github.com/emersion/go-message` | v0.18.2 | v0.18.2 | MIT | transitive | emersion | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 11 | `github.com/emersion/go-sasl` | v0.0.0-20241020182733-b788ff22d5a6 | v0.0.0-20241020182733-b788ff22d5a6 (proxy.golang.org confirms this is still the newest commit -- already current) | MIT | transitive | emersion | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 12 | `github.com/google/uuid` | v1.6.0 | v1.6.0 | BSD-3-Clause | transitive | Google | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 13 | `github.com/jackc/pgpassfile` | v1.0.0 | v1.0.0 | MIT | transitive | jackc | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 14 | `github.com/jackc/pgservicefile` | v0.0.0-20240606120523-5a60cdf6a761 | v0.0.0-20240606120523-5a60cdf6a761 (proxy.golang.org confirms this is still the newest commit -- already current) | MIT | transitive | jackc | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 15 | `github.com/jackc/puddle/v2` | v2.2.2 | v2.2.2 | MIT | transitive | jackc | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 16 | `github.com/mattn/go-isatty` | v0.0.24 | v0.0.24 | MIT | transitive | mattn (Yasuhiro Matsumoto, independent) | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 17 | `github.com/ncruces/go-strftime` | v1.0.0 | v1.0.0 | MIT | transitive | ncruces (independent) | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 18 | `github.com/remyoudompheng/bigfft` | v0.0.0-20230129092748-24d4a6f8daec | v0.0.0-20230129092748-24d4a6f8daec (proxy.golang.org confirms this is still the newest commit -- already current) | BSD-3-Clause (confirmed via GitHub repo licence field). | transitive | remyoudompheng (independent) | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 19 | `golang.org/x/sync` | v0.23.0 | v0.23.0 | BSD-3-Clause | transitive | Go team (Google) | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 20 | `golang.org/x/text` | v0.42.0 | v0.42.0 | BSD-3-Clause | transitive | Go team (Google) | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 21 | `modernc.org/libc` | v1.74.4 | v1.77.0 | BSD-3-Clause | transitive | cznic / modernc.org | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 22 | `modernc.org/mathutil` | v1.7.1 | v1.7.1 | BSD-3-Clause | transitive | cznic / modernc.org | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |
| 23 | `modernc.org/memory` | v1.11.0 | v1.12.1 | BSD-3-Clause | transitive | cznic / modernc.org | small utility (popularity tracks its direct parent) | Shipped -- linked into the birdcage and/or mockingbird Go binary | n/a -- transitive |

### B. Frontend, `frontend/package.json` + `package-lock.json` -- all dev-only, never shipped (see AGENTS.md)

| # | Dependency | Pinned | Latest upstream (verified 2026-09-20, spot-checked 2026-09-22) | Licence | Direct/Transitive | Maintainer | Popularity signal | Shipped / dev-CI-only | Approval status (AGENTS.md) |
|---|---|---|---|---|---|---|---|---|---|
| 24 | `@asamuzakjp/css-color` | 6.0.7 | 7.0.0 | MIT | transitive | asamuzakjp (independent maintainer) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 25 | `@asamuzakjp/dom-selector` | 8.3.2 | 9.2.1 | MIT | transitive | asamuzakjp (independent maintainer) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 26 | `@babel/code-frame` | 7.29.7 | 8.0.6 | MIT | transitive | Babel core team | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 27 | `@babel/helper-string-parser` | 7.29.7 | 8.0.6 | MIT | transitive | Babel core team | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 28 | `@babel/helper-validator-identifier` | 7.29.7 | 8.0.6 | MIT | transitive | Babel core team | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 29 | `@babel/parser` | 7.29.9 | 7.29.9 | MIT | transitive | Babel core team | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 30 | `@babel/runtime` | 7.29.7 | 8.0.5 | MIT | transitive | Babel core team | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 31 | `@babel/types` | 7.29.8 | 8.0.6 | MIT | transitive | Babel core team | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 32 | `@bcoe/v8-coverage` | 1.0.2 | 1.0.2 | MIT | transitive | Ben Coe (independent) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 33 | `@bramus/specificity` | 2.4.2 | 2.4.2 | MIT | transitive | Bramus Van Damme (independent) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 34 | `@csstools/color-helpers` | 6.1.1 | 6.1.1 | MIT-0 | transitive | CSS Tools community (PostCSS-adjacent) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 35 | `@csstools/css-calc` | 3.3.0 | 3.4.0 | MIT | transitive | CSS Tools community (PostCSS-adjacent) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 36 | `@csstools/css-color-parser` | 4.2.2 | 4.2.3 | MIT | transitive | CSS Tools community (PostCSS-adjacent) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 37 | `@csstools/css-parser-algorithms` | 4.0.0 | 4.0.0 | MIT | transitive | CSS Tools community (PostCSS-adjacent) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 38 | `@csstools/css-syntax-patches-for-csstree` | 1.1.13 | 1.1.14 | MIT-0 | transitive | CSS Tools community (PostCSS-adjacent) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 39 | `@csstools/css-tokenizer` | 4.0.0 | 4.0.1 | MIT | transitive | CSS Tools community (PostCSS-adjacent) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 40 | `@exodus/bytes` | 1.15.1 | 1.15.1 | MIT | transitive | Exodus (crypto wallet company), published utility | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 41 | `@jridgewell/gen-mapping` | 0.3.13 | 0.3.13 | MIT | transitive | Justin Ridgewell (independent, sourcemap tooling) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 42 | `@jridgewell/remapping` | 2.3.5 | 2.3.5 | MIT | transitive | Justin Ridgewell (independent, sourcemap tooling) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 43 | `@jridgewell/resolve-uri` | 3.1.2 | 3.1.2 | MIT | transitive | Justin Ridgewell (independent, sourcemap tooling) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 44 | `@jridgewell/sourcemap-codec` | 1.6.0 | 1.6.0 | MIT | transitive | Justin Ridgewell (independent, sourcemap tooling) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 45 | `@jridgewell/trace-mapping` | 0.3.31 | 0.3.31 | MIT | transitive | Justin Ridgewell (independent, sourcemap tooling) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 46 | `@oxc-project/types` | 0.149.0 | 0.150.0 | MIT | transitive | oxc project (Rust JS tooling, VoidZero-adjacent) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 47 | `@rolldown/pluginutils` | 1.0.1 | 1.0.1 | MIT | transitive | VoidZero / Rolldown team | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 48 | `@sveltejs/acorn-typescript` | 1.0.13 | 1.0.13 | MIT | transitive | Svelte core team | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 49 | `@sveltejs/load-config` | 0.2.3 | 0.2.3 | MIT | transitive | Svelte core team | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 50 | `@sveltejs/vite-plugin-svelte` | 7.3.0 | 7.3.0 | MIT | direct | Svelte core team | moderate (established, purpose-fit, not mainstream-scale) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 51 | `@testing-library/dom` | 10.4.1 | 10.4.2 | MIT | transitive | Testing Library org | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 52 | `@testing-library/svelte` | 5.4.2 | 5.4.2 | MIT | direct | Testing Library org (community, Kent C. Dodds-founded) | moderate (established, purpose-fit, not mainstream-scale) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 53 | `@testing-library/svelte-core` | 1.1.3 | 1.1.3 | MIT | transitive | Testing Library org | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 54 | `@tsconfig/svelte` | 5.0.8 | 5.0.8 | MIT | direct | Svelte core team / tsconfig community bases | moderate (established, purpose-fit, not mainstream-scale) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 55 | `@types/aria-query` | 5.0.4 | 5.0.4 | MIT | transitive | DefinitelyTyped community | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 56 | `@types/chai` | 5.2.3 | 5.2.3 | MIT | transitive | DefinitelyTyped community | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 57 | `@types/deep-eql` | 4.0.2 | 4.0.2 | MIT | transitive | DefinitelyTyped community | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 58 | `@types/estree` | 1.0.9 | 1.0.9 | MIT | transitive | DefinitelyTyped community | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 59 | `@types/node` | 22.20.2 | 26.6.2 | MIT | direct | DefinitelyTyped community (types published under Microsoft-run @types scope) | moderate (established, purpose-fit, not mainstream-scale) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 60 | `@vitest/coverage-v8` | 5.0.0 | 5.0.1 | MIT | direct | vitest-dev (same team as vitest) | moderate (established, purpose-fit, not mainstream-scale) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Approved -- #74 |
| 61 | `@vitest/istanbul-lib-coverage` | 1.0.1 | 1.0.1 | MIT | transitive | vitest-dev | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 62 | `@vitest/istanbul-lib-report` | 1.0.1 | 1.0.1 | MIT | transitive | vitest-dev | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 63 | `@vitest/mocker` | 5.0.0 | 5.0.1 | MIT | transitive | vitest-dev | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 64 | `@vitest/spy` | 5.0.0 | 5.0.1 | MIT | transitive | vitest-dev | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 65 | `acorn` | 8.18.0 | 8.18.0 | MIT | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 66 | `ansi-regex` | 5.0.1 | 6.3.0 | MIT | transitive | Testing Library org (transitive via `@testing-library/svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 67 | `ansi-styles` | 5.2.0 | 7.0.0 | MIT | transitive | Testing Library org (transitive via `@testing-library/svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 68 | `aria-query` | 5.3.0 | 5.3.2 | Apache-2.0 | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 69 | `assertion-error` | 2.0.1 | 2.0.1 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 70 | `ast-v8-to-istanbul` | 1.0.6 | 1.0.6 | MIT | transitive | vitest-dev (transitive via `@vitest/coverage-v8`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 71 | `axobject-query` | 4.1.0 | 4.1.0 | Apache-2.0 | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 72 | `bidi-js` | 1.1.0 | 1.1.0 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 73 | `chai` | 6.2.2 | 6.2.2 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 74 | `chokidar` | 4.0.3 | 5.0.0 | MIT | transitive | Svelte core team (transitive via `svelte-check`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 75 | `clsx` | 2.1.1 | 2.1.1 | MIT | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 76 | `css-tree` | 3.2.1 | 3.2.1 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 77 | `data-urls` | 7.0.0 | 7.0.0 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 78 | `decimal.js` | 10.6.0 | 10.6.0 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 79 | `deepmerge` | 4.3.1 | 4.3.1 | MIT | transitive | Svelte core team (transitive via `@sveltejs/vite-plugin-svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 80 | `dequal` | 2.0.3 | 2.0.3 | MIT | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 81 | `detect-libc` | 2.1.2 | 2.1.2 | Apache-2.0 | transitive | VoidZero / Vite team (transitive via `vite`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 82 | `devalue` | 5.9.2 | 6.0.0 | MIT | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 83 | `dom-accessibility-api` | 0.5.16 | 0.7.1 | MIT | transitive | Testing Library org (transitive via `@testing-library/svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 84 | `entities` | 8.1.0 | 8.1.0 | BSD-2-Clause | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 85 | `es-module-lexer` | 2.3.2 | 3.0.2 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 86 | `esm-env` | 1.2.2 | 1.2.2 | MIT | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 87 | `esrap` | 2.3.7 | 2.3.7 | MIT | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 88 | `estree-walker` | 3.0.3 | 3.0.3 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 89 | `expect-type` | 1.4.0 | 1.4.0 | Apache-2.0 | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 90 | `fdir` | 6.5.0 | 6.5.0 | MIT | transitive | Svelte core team (transitive via `svelte-check`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 91 | `fsevents` | 2.3.3 | 2.3.3 | MIT | transitive | VoidZero / Vite team (transitive via `vite`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 92 | `html-encoding-sniffer` | 6.0.0 | 6.0.0 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 93 | `is-potential-custom-element-name` | 1.0.1 | 1.0.1 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 94 | `is-reference` | 3.0.3 | 3.0.3 | MIT | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 95 | `js-tokens` | 10.0.0 | 10.0.0 | MIT | transitive | vitest-dev (transitive via `@vitest/coverage-v8`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 96 | `jsdom` | 30.0.1 | 30.1.0 | MIT | direct | jsdom org, led by Domenic Denicola | very high (mainstream, widely deployed) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 97 | `lightningcss` | 1.33.0 | 1.33.0 | MPL-2.0 | transitive | VoidZero / Vite team (transitive via `vite`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 98 | `locate-character` | 3.0.0 | 3.0.0 | MIT | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 99 | `lru-cache` | 11.5.2 | 11.5.3 | BlueOak-1.0.0 | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 100 | `lz-string` | 1.5.0 | 1.5.0 | MIT | transitive | Testing Library org (transitive via `@testing-library/svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 101 | `magic-string` | 1.3.1 | 1.4.1 | MIT | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 102 | `magicast` | 0.5.5 | 0.5.5 | MIT | transitive | vitest-dev (transitive via `@vitest/coverage-v8`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 103 | `mdn-data` | 2.27.1 | 2.36.0 | CC0-1.0 | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 104 | `mri` | 1.2.0 | 1.2.0 | MIT | transitive | Svelte core team (transitive via `svelte-check`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 105 | `nanoid` | 3.3.19 | 6.0.1 | MIT | transitive | VoidZero / Vite team (transitive via `vite`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 106 | `obug` | 2.2.1 | 3.0.0 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 107 | `parse5` | 8.0.1 | 8.0.1 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 108 | `picocolors` | 1.1.1 | 1.1.1 | ISC | transitive | Svelte core team (transitive via `svelte-check`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 109 | `picomatch` | 4.0.7 | 4.0.7 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 110 | `pixelmatch` | 7.2.0 | 7.2.0 | ISC | direct | mapbox-originated, now independent (community) | moderate (established, purpose-fit, not mainstream-scale) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 111 | `playwright` | 1.63.0 | 1.63.0 | Apache-2.0 | direct | Microsoft | very high (mainstream, widely deployed) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 112 | `playwright-core` | 1.63.0 | 1.63.0 | Apache-2.0 | transitive | Microsoft (transitive via `playwright`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 113 | `pngjs` | 7.0.0 | 7.0.0 | MIT | direct | independent (lukeapage / community) | moderate (established, purpose-fit, not mainstream-scale) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 114 | `postcss` | 8.5.28 | 8.5.28 | MIT | transitive | VoidZero / Vite team (transitive via `vite`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 115 | `pretty-format` | 27.5.1 | 30.5.1 | MIT | transitive | Testing Library org (transitive via `@testing-library/svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 116 | `punycode` | 2.3.1 | 2.3.1 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 117 | `react-is` | 17.0.2 | 19.3.0 | MIT | transitive | Testing Library org (transitive via `@testing-library/svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 118 | `readdirp` | 4.1.2 | 5.1.1 | MIT | transitive | Svelte core team (transitive via `svelte-check`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 119 | `require-from-string` | 2.0.2 | 2.0.2 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 120 | `rolldown` | 1.2.8 | 1.2.9 | MIT | transitive | VoidZero / Vite team (transitive via `vite`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 121 | `sade` | 1.8.1 | 1.8.1 | MIT | transitive | Svelte core team (transitive via `svelte-check`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 122 | `saxes` | 6.0.0 | 6.0.0 | ISC | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 123 | `siginfo` | 2.0.0 | 2.0.0 | ISC | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 124 | `source-map-js` | 1.2.1 | 1.2.1 | BSD-3-Clause | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 125 | `stackback` | 0.0.2 | 0.0.2 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 126 | `std-env` | 4.2.0 | 4.2.0 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 127 | `svelte` | 5.57.0 | 5.57.1 | MIT | direct | Svelte core team (Rich Harris et al, Vercel-sponsored) | very high (mainstream, widely deployed) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 128 | `svelte-check` | 4.7.6 | 4.7.6 | MIT | direct | Svelte core team | moderate (established, purpose-fit, not mainstream-scale) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 129 | `symbol-tree` | 3.2.4 | 3.2.4 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 130 | `tinybench` | 6.1.4 | 6.2.0 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 131 | `tinyexec` | 1.3.0 | 1.3.1 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 132 | `tinyglobby` | 0.2.17 | 0.2.17 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 133 | `tinyrainbow` | 3.1.1 | 3.1.1 | MIT | transitive | vitest-dev (transitive via `@vitest/coverage-v8`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 134 | `tldts` | 7.4.12 | 7.4.13 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 135 | `tldts-core` | 7.4.12 | 7.4.13 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 136 | `tough-cookie` | 6.0.2 | 6.0.2 | BSD-3-Clause | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 137 | `tr46` | 6.0.0 | 6.0.0 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 138 | `typescript` | 6.0.3 | 7.0.2 | Apache-2.0 | direct | Microsoft | very high (mainstream, widely deployed) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 139 | `undici` | 8.10.2 | 8.10.2 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 140 | `undici-types` | 6.21.0 | 8.10.2 | MIT | transitive | Node.js/undici project (bundled into @types/node) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 141 | `vite` | 8.3.0 | 8.3.0 | MIT | direct | VoidZero (Evan You's company) / Vite team | very high (mainstream, widely deployed) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 142 | `vitefu` | 1.1.3 | 1.1.3 | MIT | transitive | Svelte core team (transitive via `@sveltejs/vite-plugin-svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 143 | `vitest` | 5.0.0 | 5.0.1 | MIT | direct | vitest-dev (Anthony Fu and collaborators, Vite ecosystem) | very high (mainstream, widely deployed) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | Predates the rule -- not individually recorded |
| 144 | `w3c-xmlserializer` | 5.0.0 | 5.0.0 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 145 | `webidl-conversions` | 8.0.1 | 8.0.1 | BSD-2-Clause | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 146 | `whatwg-mimetype` | 5.0.0 | 5.0.0 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 147 | `whatwg-url` | 16.0.1 | 17.1.1 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 148 | `why-is-node-running` | 2.3.0 | 3.2.2 | MIT | transitive | vitest-dev (transitive via `vitest`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 149 | `xml-name-validator` | 5.0.0 | 5.0.0 | Apache-2.0 | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 150 | `xmlchars` | 2.2.0 | 2.2.0 | MIT | transitive | jsdom org (transitive via `jsdom`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 151 | `zimmerframe` | 1.1.5 | 1.1.5 | MIT | transitive | Svelte core team (transitive via `svelte`) | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 152 | `lightningcss-*` (11 per-platform prebuilt binaries, grouped for readability) | 1.33.0 (all 11 pinned to the same version) | 1.33.0 | MPL-2.0 | transitive | lightningcss project (Devon Govett), prebuilt native binaries pulled in via vite | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |
| 153 | `@rolldown/binding-*` (15 per-platform prebuilt binaries, grouped for readability) | 1.2.8 (all 15 pinned to the same version) | 1.2.9 | MIT | transitive | VoidZero / Rolldown team, prebuilt native binaries pulled in via vite | small utility (popularity tracks its direct parent) | Dev/CI-only -- frontend build & test tooling; svelte itself compiles into the shipped bundle, the rest never ships | n/a -- transitive |

### C. Mockingbird honeypot, `build/mockingbird/requirements.txt` (uv-compiled from `requirements.in`, hash-pinned)

| # | Dependency | Pinned | Latest upstream (verified 2026-09-20, spot-checked 2026-09-22) | Licence | Direct/Transitive | Maintainer | Popularity signal | Shipped / dev-CI-only | Approval status (AGENTS.md) |
|---|---|---|---|---|---|---|---|---|---|
| 154 | `attrs` | 26.1.0 | 26.1.0 | MIT | transitive | attrs community (Hynek Schlawack) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 155 | `automat` | 25.4.16 | 25.4.16 | MIT | transitive | Twisted Matrix Labs / Glyph Lefkowitz | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 156 | `bcrypt` | 3.2.0 | 5.0.0 | Apache-2.0 | transitive | Python Cryptographic Authority (PyCA) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 157 | `certifi` | 2026.7.22 | 2026.7.22 | MPL-2.0 | transitive | certifi community (Kenneth Reitz-founded, Mozilla CA bundle repack) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 158 | `cffi` | 2.1.1 | 2.1.1 | MIT-0 | transitive | PyPy/CFFI team | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 159 | `charset-normalizer` | 3.5.1 | 3.5.1 | MIT | transitive | independent (Ahmed TAHRI / community) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 160 | `constantly` | 23.10.4 | 23.10.4 | MIT | transitive | Twisted Matrix Labs | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 161 | `cryptography` | 49.0.0 | 50.0.1 | Apache-2.0 OR BSD-3-Clause | transitive | Python Cryptographic Authority (PyCA) | very high (mainstream, widely deployed) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 162 | `gitdb` | 4.0.12 | 4.0.12 | BSD-3-Clause | transitive | GitPython community | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 163 | `gitpython` | 3.1.62 | 3.1.62 | BSD-3-Clause | transitive | GitPython community (Byron / Sebastian Thiel) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 164 | `hpfeeds` | 3.0.0 | 3.1.0 | GPL-3.0 | transitive | Honeynet Project lineage (Mark Schloesser and contributors) -- independent of opencanary/Thinkst | high (the standard choice for its niche) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 165 | `hyperlink` | 21.0.0 | 21.0.0 | MIT | transitive | Twisted Matrix Labs | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 166 | `idna` | 3.20 | 3.20 | BSD-3-Clause | transitive | independent (Kim Davies) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 167 | `incremental` | 24.11.0 | 24.11.0 | MIT | transitive | Twisted Matrix Labs | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 168 | `jinja2` | 3.1.6 | 3.1.6 | BSD-3-Clause | transitive | Pallets project (Flask/Jinja maintainers) | very high (mainstream, widely deployed) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 169 | `markupsafe` | 3.0.3 | 3.0.3 | BSD-3-Clause | transitive | Pallets project | very high (mainstream, widely deployed) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 170 | `ntlmlib` | 0.72 | 0.72 | Apache-2.0 | transitive | OpenCanary project's own vendored fork lineage | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 171 | `opencanary` | 0.9.9 | 0.9.9 | BSD | direct | Thinkst Applied Research | high (the standard choice for its niche) | Shipped -- installed into /opt/opencanary in the mockingbird image | Predates the rule -- not individually recorded |
| 172 | `ordereddict` | 1.1 | 1.1 | MIT | transitive | backport of stdlib's collections.OrderedDict (independent packaging) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 173 | `packaging` | 26.3 | 26.3 | Apache-2.0 OR BSD-2-Clause | transitive | Python Packaging Authority (PyPA) | very high (mainstream, widely deployed) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 174 | `passlib` | 1.7.1 | 1.7.4 | BSD | transitive | independent (Eli Collins, effectively unmaintained) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 175 | `pyasn1` | 0.6.4 | 0.6.4 | BSD-2-Clause | transitive | pyasn1 community | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 176 | `pyasn1-modules` | 0.4.2 | 0.4.2 | BSD-2-Clause | transitive | pyasn1 community | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 177 | `pycparser` | 3.0 | 3.0 | BSD-3-Clause | transitive | independent (Eli Bendersky) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 178 | `pyopenssl` | 26.3.0 | 26.4.0 | Apache-2.0 | transitive | Python Cryptographic Authority (PyCA) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 179 | `redis` | 7.4.0 | 8.1.0 | MIT | transitive | Redis Inc. (redis-py client) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 180 | `requests` | 2.33.0 | 2.34.2 | Apache-2.0 | transitive | psf/requests community (Kenneth Reitz-founded, now community-run) | very high (mainstream, widely deployed) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 181 | `service-identity` | 21.1.0 | 26.1.0 | MIT | transitive | Hynek Schlawack (independent, PyCA-adjacent) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 182 | `setuptools` | 78.1.1 | 84.0.0 | MIT | transitive | Python Packaging Authority (PyPA) | very high (mainstream, widely deployed) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 183 | `simplejson` | 3.16.0 | 4.1.2 | MIT OR AFL-2.1 | transitive | independent (Bob Ippolito / community) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 184 | `six` | 1.17.0 | 1.17.0 | MIT | transitive | Benjamin Peterson (independent, in maintenance mode) | very high (mainstream, widely deployed) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 185 | `smmap` | 5.0.3 | 5.0.3 | BSD-3-Clause | transitive | GitPython community | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 186 | `twisted` | 26.4.0 | 26.4.0 | MIT | transitive | Twisted Matrix Labs | very high (mainstream, widely deployed) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 187 | `typing-extensions` | 4.16.0 | 4.16.0 | PSF-2.0 | transitive | Python typing SIG (CPython-adjacent) | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 188 | `urllib3` | 2.7.0 | 2.8.0 | MIT | transitive | urllib3 community (Andrey Petrov-founded) | very high (mainstream, widely deployed) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |
| 189 | `zope-interface` | 7.2 | 8.6 | ZPL-2.1 | transitive | Zope Foundation | small utility (popularity tracks its direct parent) | Shipped -- installed into /opt/opencanary in the mockingbird image | n/a -- transitive |

### D. Container base images (`build/birdcage/Dockerfile`, `build/mockingbird/Dockerfile`)

| # | Dependency | Pinned | Latest upstream (verified 2026-09-20, spot-checked 2026-09-22) | Licence | Direct/Transitive | Maintainer | Popularity signal | Shipped / dev-CI-only | Approval status (AGENTS.md) |
|---|---|---|---|---|---|---|---|---|---|
| 190 | `node:26-alpine` | 26-alpine (resolves to 26.9.0-alpine, verified via Docker Hub) | 26.9.0-alpine (current -- Node 26 is still on the "Current" release line, not yet LTS) | MIT (Node.js) | direct | OpenJS Foundation (Node.js), image built by the Docker Official Images team | very high (mainstream, widely deployed) | Build-only -- build stage, discarded before the runtime image | Predates the rule -- not individually recorded |
| 191 | `golang:1.27.0-alpine` | 1.27.0-alpine | 1.27.1-alpine3.24 (a patch release behind; matches go.mod's own `go 1.27.0` directive) | BSD-3-Clause (Go) + Alpine's own licences | direct | Go team (Google), image built by the Docker Official Images team | very high (mainstream, widely deployed) | Build-only -- build stage, discarded before the runtime image | Predates the rule -- not individually recorded |
| 192 | `gcr.io/distroless/static-debian13:nonroot` | static-debian13:nonroot (floating tag, no digest pin) | Current -- "debian13" (trixie) is Google's latest distroless generation; no newer generation tag exists yet. | Apache-2.0 (distroless project) | direct | Google (GoogleContainerTools/distroless) | high (the standard choice for its niche) | Shipped -- the shipped runtime base image | Predates the rule -- not individually recorded |
| 193 | `gcr.io/distroless/python3-debian13:nonroot` | python3-debian13:nonroot (floating tag, no digest pin) | Current -- same distroless generation as above. | Apache-2.0 (distroless project) | direct | Google (GoogleContainerTools/distroless) | high (the standard choice for its niche) | Shipped -- the shipped runtime base image | Predates the rule -- not individually recorded |
| 194 | `python:3.13-slim-trixie` | 3.13-slim-trixie | 3.13.13-slim-trixie is the current patch, but Python 3.14 is now the latest major release line (endoflife.date, verified). | PSF-2.0 (CPython) + Debian's licences | direct | Python Software Foundation, image built by the Docker Official Images team | very high (mainstream, widely deployed) | Build-only -- build stage, discarded before the runtime image | Predates the rule -- not individually recorded |

### E. CI runner images, `.gitlab-ci.yml` (not shipped -- only run the pipeline's own jobs)

| # | Dependency | Pinned | Latest upstream (verified 2026-09-20, spot-checked 2026-09-22) | Licence | Direct/Transitive | Maintainer | Popularity signal | Shipped / dev-CI-only | Approval status (AGENTS.md) |
|---|---|---|---|---|---|---|---|---|---|
| 195 | `alpine:3.24` | 3.24 (floating minor) | 3.24.2 is the current patch (already what the floating tag resolves to). | MIT (Alpine) | direct | Alpine Linux project | very high (mainstream, widely deployed) | CI-only -- CI runner/service image, never shipped | Predates the rule -- not individually recorded |
| 196 | `golang:1.27` | 1.27 (floating minor, distinct from the Dockerfiles' pinned 1.27.0-alpine) | Already resolves to 1.27.1, per go.dev/dl. | BSD-3-Clause (Go) | direct | Go team (Google), Docker Official Images | very high (mainstream, widely deployed) | CI-only -- CI runner/service image, never shipped | Predates the rule -- not individually recorded |
| 197 | `python:3.13-alpine` | 3.13-alpine (floating minor) | 3.13.13-alpine3.24 is the current patch; same 3.13-vs-3.14 gap as row 5. | PSF-2.0 (CPython) + Alpine's licences | direct | Python Software Foundation, Docker Official Images | very high (mainstream, widely deployed) | CI-only -- CI runner/service image, never shipped | Predates the rule -- not individually recorded |
| 198 | `node:22-trixie` | 22-trixie (floating minor) | 22.22-trixie is the current patch; Node 22 ("Jod") is the active LTS line, verified via nodejs.org. | MIT (Node.js) | direct | OpenJS Foundation (Node.js), Docker Official Images | very high (mainstream, widely deployed) | CI-only -- CI runner/service image, never shipped | Predates the rule -- not individually recorded |
| 199 | `postgres:17-alpine` | 17-alpine (floating minor, `test:go` service container) | 17-alpine3.24 is the current patch. | PostgreSQL Licence | direct | PostgreSQL Global Development Group, Docker Official Images | very high (mainstream, widely deployed) | CI-only -- CI runner/service image, never shipped | Predates the rule -- not individually recorded |
| 200 | `docker:29-cli` | 29-cli (floating major) | Already the current tag (Docker Hub shows no newer `NN-cli` major). | Apache-2.0 (Docker CLI) | direct | Docker Inc. | very high (mainstream, widely deployed) | CI-only -- CI runner/service image, never shipped | Predates the rule -- not individually recorded |

### F. Fetched at build or test time (not base images, but named artifacts pulled in by the pipeline)

| # | Dependency | Pinned | Latest upstream (verified 2026-09-20, spot-checked 2026-09-22) | Licence | Direct/Transitive | Maintainer | Popularity signal | Shipped / dev-CI-only | Approval status (AGENTS.md) |
|---|---|---|---|---|---|---|---|---|---|
| 201 | `golangci-lint` | v2.13.2 (`go install .../golangci-lint/v2@v2.13.2` in `lint:go`) | v2.13.2 (verified via GitHub releases API) -- already current. | GPL-3.0 | direct | golangci-lint community (OSS org) | very high (mainstream, widely deployed) | CI/release-only -- fetched at build/test/release time, never shipped | Predates the rule -- not individually recorded |
| 202 | `go1.27.0 (tarball)` | go1.27.0.linux-amd64.tar.gz, fetched by `curl` from go.dev/dl in `test:smoke` | go1.27.1 is current (go.dev/dl, verified) -- one patch behind, same gap as the Dockerfiles' pinned Go. | BSD-3-Clause (Go) | direct | Go team (Google) | moderate (established, purpose-fit, not mainstream-scale) | CI/release-only -- fetched at build/test/release time, never shipped | Predates the rule -- not individually recorded |
| 203 | `libcap (apk package)` | unpinned -- `apk add --no-cache libcap` in `build/mockingbird/Dockerfile`'s agent stage (Alpine picks whatever is current in its repo at build time) | Unverified -- Alpine's package index version wasn't checked this session; the package is unpinned so "latest" and "pinned" are the same moving target. | Dual BSD-3-Clause / GPL-2.0-only per upstream's own COPYING file -- not confirmed against a registry API this session, so treat as a claim to verify rather than fact. | direct | Linux libcap upstream (Andrew G. Morgan et al), packaged by Alpine | moderate (established, purpose-fit, not mainstream-scale) | CI/release-only -- fetched at build/test/release time, never shipped | Predates the rule -- not individually recorded |
| 204 | `postgresql-client (apt package)` | unpinned -- `apt-get install -y postgresql-client` in `test:go` | Unverified -- Debian's current package version wasn't checked this session. | PostgreSQL Licence | direct | PostgreSQL Global Development Group, packaged by Debian | moderate (established, purpose-fit, not mainstream-scale) | CI/release-only -- fetched at build/test/release time, never shipped | Predates the rule -- not individually recorded |
| 205 | `pyyaml (pip package)` | unpinned -- `pip install --quiet pyyaml` in `lint:ci` | 6.0.3 (PyPI JSON API, verified). | MIT | direct | PyYAML community | moderate (established, purpose-fit, not mainstream-scale) | CI/release-only -- fetched at build/test/release time, never shipped | Predates the rule -- not individually recorded |
| 206 | `bash (apk package)` | unpinned -- `apk add --no-cache bash` in `lint:ci` and every `e2e:*` job | Unverified -- Alpine's current package version wasn't checked this session. | GPL-3.0-or-later (GNU project; not confirmed against a registry API this session). | direct | GNU Project, packaged by Alpine | moderate (established, purpose-fit, not mainstream-scale) | CI/release-only -- fetched at build/test/release time, never shipped | Predates the rule -- not individually recorded |

### G. GitHub Actions, `.github/workflows/*.yml` (CodeQL + dependency review mirror only -- GitLab is where the gate actually runs)

| # | Dependency | Pinned | Latest upstream (verified 2026-09-20, spot-checked 2026-09-22) | Licence | Direct/Transitive | Maintainer | Popularity signal | Shipped / dev-CI-only | Approval status (AGENTS.md) |
|---|---|---|---|---|---|---|---|---|---|
| 207 | `actions/checkout` | v7.0.1 (commit `3d3c42e...`, verified that commit tags v7.0.1) | v7.0.1 -- already current (GitHub releases API, verified). | MIT | direct | GitHub | very high (mainstream, widely deployed) | CI-only -- GitHub Actions mirror pipeline only | Predates the rule -- not individually recorded |
| 208 | `github/codeql-action/init` | v4.37.6 (commit `5595ccaf9...`) | v4.38.1 is current (GitHub tags API, verified) -- several patch/minor releases behind. | MIT | direct | GitHub | very high (mainstream, widely deployed) | CI-only -- GitHub Actions mirror pipeline only | Predates the rule -- not individually recorded |
| 209 | `github/codeql-action/analyze` | v4.37.6 (same commit as above -- both `init` and `analyze` come from the same action release) | v4.38.1, same gap as the row above. | MIT | direct | GitHub | very high (mainstream, widely deployed) | CI-only -- GitHub Actions mirror pipeline only | Predates the rule -- not individually recorded |
| 210 | `actions/dependency-review-action` | v5.0.0 (commit `a1d282b...`) | v5.0.0 -- already current (GitHub releases API, verified). | MIT | direct | GitHub | very high (mainstream, widely deployed) | CI-only -- GitHub Actions mirror pipeline only | Predates the rule -- not individually recorded |

### H. Found in this review but missing from the issue #73 table (2026-09-20 comment) -- `.gitlab-ci.yml` and `.github/workflows/countersign.yml`

The 2026-09-20 table covered `.gitlab-ci.yml`'s `image:` and `services:` lines fairly completely, but missed several packages fetched inline inside job scripts, one CI image, and a whole GitHub Actions workflow file that did not exist (or was not read) at review time. Numbering continues from 211.

| # | Dependency | Pinned | Latest upstream (verified 2026-09-22) | Licence | Direct/Transitive | Maintainer | Popularity signal | Shipped / dev-CI-only | Approval status (AGENTS.md) |
|---|---|---|---|---|---|---|---|---|---|
| 211 | `registry.gitlab.com/gitlab-org/release-cli:latest` | `latest` (floating, no digest pin) | No newer tagged release found; upstream project is in maintenance mode -- GitLab's own docs point new work at `glab` instead. | MIT | direct | GitLab | high (bundled with every GitLab installation) | CI-only -- `release:gitlab` job image, never shipped | Predates the rule -- not individually recorded |
| 212 | `openssl (apk package)` | unpinned -- `apk add --no-cache openssl` in several `e2e:*`/`test:go` jobs | Unverified -- Alpine package index version not checked this session. | Apache-2.0 | direct | OpenSSL project | very high (mainstream, widely deployed) | CI-only -- generates test/e2e TLS material, never shipped | Predates the rule -- not individually recorded |
| 213 | `openssl (apt package)` | unpinned -- `apt-get -qq install -y postgresql-client openssl` in `test:go` | Unverified -- Debian package index version not checked this session. | Apache-2.0 | direct | OpenSSL project, packaged by Debian | very high (mainstream, widely deployed) | CI-only -- captures the Postgres service container's TLS cert, never shipped | Predates the rule -- not individually recorded |
| 214 | `curl (apk package)` | unpinned -- `apk add --no-cache bash curl` in the `.registry_login` release anchor | Unverified -- Alpine package index version not checked this session. | curl licence (MIT-style) | direct | curl project (Daniel Stenberg et al) | very high (mainstream, widely deployed) | CI/release-only -- release-job HTTP calls, never shipped | Predates the rule -- not individually recorded |
| 215 | `git (apk package)` | unpinned -- `apk add --no-cache git` in `release:push` | Unverified -- Alpine package index version not checked this session. | GPL-2.0-only | direct | Git project (Software Freedom Conservancy) | very high (mainstream, widely deployed) | CI/release-only -- reads the merge commit's parents, never shipped | Predates the rule -- not individually recorded |
| 216 | `git (apk package, second job)` | unpinned -- `apk add --no-cache git openssh-client curl jq` in `sync:mirror-to-github` | Unverified this session. | GPL-2.0-only | direct | Git project | very high (mainstream, widely deployed) | CI-only -- mirrors `dev`/`preview`/`main` to GitHub over SSH, never shipped | Predates the rule -- not individually recorded |
| 217 | `openssh-client (apk package)` | unpinned -- same `sync:mirror-to-github` job as #216 | Unverified this session. | BSD-style (OpenSSH) | direct | OpenBSD/OpenSSH project | very high (mainstream, widely deployed) | CI-only -- same job as #216, never shipped | Predates the rule -- not individually recorded |
| 218 | `jq (apk package)` | unpinned -- same `sync:mirror-to-github` job as #216 | Unverified this session. | MIT | direct | jq project (independent, stedolan/jqlang) | very high (mainstream, widely deployed) | CI-only -- same job as #216, never shipped | Predates the rule -- not individually recorded |
| 219 | `cosign` | v3.1.3, checksum-pinned in `scripts/ensure-cosign.sh` (fetched by both the GitLab release jobs and GitHub's `countersign.yml`) | v3.1.3 -- confirmed current via GitHub releases (2026-08-06 release, no newer tag). | Apache-2.0 | direct | sigstore project (Linux Foundation-hosted, OpenSSF) | high (the standard tool for keyless/key-based container signing) | Build/release-only -- signs and verifies image digests, never shipped in a product image | Predates the rule -- not individually recorded |
| 220 | `actions/checkout` (in `countersign.yml`) | `@v5` -- a floating major tag, NOT the SHA-pin `codeql.yml`/`dependency-review.yml` use for the same action | v7.0.1 (GitHub releases API, verified) -- two majors ahead of the pinned `v5` tag. | MIT | direct | GitHub | very high (mainstream, widely deployed) | CI-only -- countersigning workflow checkout, never shipped | Predates the rule -- not individually recorded |
## Summary, by approval status

220 rows total (210 from the issue's own table, 10 found in section H).

| Status | Rows |
|---|---|
| Approved, with issue number | 5 (`golang.org/x/net`+`x/sys` #65; `go-imap/v2`+`go-msgauth` #54; `@vitest/coverage-v8` #74) |
| Predates the rule -- flagged on #73, owner decision pending | 2 (`github.com/jackc/pgx/v5`, `modernc.org/sqlite`) |
| Predates the rule -- not individually recorded | 47 (every other **direct** dependency) |
| n/a -- transitive | 166 |

`grype` (Anchore, Apache-2.0), approved on #108 for a future scanner-agent
image, does not appear above: it is not in any manifest this issue names, so
it is out of this inventory's scope until that image lands.

## What needs the owner's attention

**Unapproved and shipped, same footing as `x/net`/`x/sys` but never recorded:**
`golang.org/x/crypto` and `golang.org/x/time` are direct Go dependencies,
linked into the shipped binary, from the same Go-team family as `x/net` and
`x/sys` -- but unlike those two, neither is named in AGENTS.md's approved
list. Worth either an explicit approval or a note that Go-team `x/*`
extensions are self-evidently fine as a category.

**Genuinely behind current upstream** (direct dependencies only; the full
table has more transitive gaps that don't need an owner decision):
- `modernc.org/sqlite` v1.57.0 -> v1.59.0 (row 8, already flagged on #73)
- `typescript` 6.0.3 -> 7.0.2, a major version (row 138)
- `@types/node` 22.20.2 -> 26.6.2 (row 59)
- `golang:1.27.0-alpine` / the CI `go1.27.0` tarball, one patch behind
  1.27.1 (rows 191, 202)
- `python:3.13-slim-trixie` / `python:3.13-alpine`: Python 3.14 is now the
  latest major line; no reason recorded for staying on 3.13 (rows 194, 197)
- `github/codeql-action/init`/`analyze` v4.37.6 -> v4.38.1, several releases
  behind on the security-scanning action itself (rows 208-209)
- `svelte` and `vitest`, one patch each behind (rows 127, 143) -- minor,
  listed for completeness

**Licence flags with a redistribution question:** `hpfeeds` (GPL-3.0,
transitive via `opencanary`, row 164) ships inside the mockingbird image --
already reviewed and accepted as a named exception in
`supply-chain/licence-policy.yml` (`allow-python-package-licenses:
hpfeeds@3.0.0`), so this is a confirmation, not a new finding. `golangci-lint`
(GPL-3.0, row 201), `bash` (GPL-3.0-or-later, row 206) and `git` (GPL-2.0-only,
rows 215-216) are also copyleft but CI-only and never shipped, so they raise
no distribution obligation. No other row's licence looked like it creates one.

**Found in this review, missing from the 2026-09-20 table (section H):**
- `registry.gitlab.com/gitlab-org/release-cli:latest` -- unpinned `:latest`
  tag, and upstream is in maintenance mode (GitLab's own docs point new work
  at `glab` instead).
- `.github/workflows/countersign.yml` pins `actions/checkout@v5` -- a
  floating major tag two majors behind the `v7.0.1` the other two workflows
  pin by commit SHA. Inconsistent pinning style as much as a currency gap.
- Five more CI-only OS packages fetched via `apk`/`apt` inside job scripts
  (`openssl` x2, `curl`, `git` x2, `openssh-client`, `jq`), all unpinned,
  none previously listed.
- `cosign` v3.1.3, checksum-pinned in `scripts/ensure-cosign.sh` and used by
  both the GitLab release path and GitHub's countersigning workflow --
  confirmed still current.

Nothing above was changed, removed or re-pinned. This is the inventory; the
owner's per-row decisions and any resulting removal/replacement/upgrade
issues are a separate step, as #73 itself specifies.
