# Birdcage

Birdcage centralizes alerts from multiple OpenCanary honeypot instances into
a single dashboard — one place to see every decoy hit across your fleet,
instead of digging through per-instance logs. Beyond visibility, it aims to
add intelligent analysis of that activity, log collection and tracing
around each hit, and integration with CrowdSec and RouterOS (via a
dedicated service account) to attempt automated mitigating action against
confirmed threats.

Birdcage is a separate application from
[mikroview](https://github.com/tomlawesome/mikroview), with its own
deployment: same look and sign-in model, talking to it only through API
keys ([ADR-0003](docs/adr/0003-mikroview-sidecar.md),
[ADR-0008](docs/adr/0008-container-only-distribution-and-two-images.md)).

Birdcage is in early implementation — the components landed so far are the
HTTPS canary ingest listener (per-canary bearer tokens, TLS 1.3) and the
dashboard HTTP API (`cmd/birdcage`). See:

- [docs/v1-scope.md](docs/v1-scope.md) — what's in v1 vs. explicitly
  deferred, and the tracking epics.
- [docs/architecture.md](docs/architecture.md) — system context and
  component boundaries.
- [docs/configuration.md](docs/configuration.md) — `DATABASE_URL`
  (SQLite/Postgres) and backup/restore for both.
- [docs/adr/](docs/adr/) — the decisions behind the stack, storage, and
  branching model.
- [SECURITY.md](SECURITY.md) — threat model and deployment hardening.
- [CONTRIBUTING.md](CONTRIBUTING.md) — branching and testing expectations.

## Run the frontend

The dashboard (`frontend/`, a Svelte 5 + TypeScript app) is embedded into
the `birdcage` binary at build time — `go build ./...` works with no
frontend built at all (it just serves the API), but a real UI needs one
build step first:

```
cd frontend && npm ci && npm run build
cp -r frontend/dist/. web/dist/
go build ./...
```

`web/dist/` is gitignored except for the placeholder `.gitkeep` `go:embed`
needs to compile against a fresh clone — never commit a real build there.

For day-to-day frontend work, run the dev server against a real backend on
loopback `:8080` -- the dashboard refuses to start as plain HTTP on
anything else (issue #63, see [SECURITY.md](SECURITY.md#network-exposure)),
so a local run needs `BIRDCAGE_HTTP_ADDR` set explicitly:

```
BIRDCAGE_HTTP_ADDR=127.0.0.1:8080 go run ./cmd/birdcage
```

```
cd frontend && npm run dev
```

`npm run dev` also understands `?scene=quiet|silent|night` in the URL: it
loads one of the fixtures under `frontend/src/dev/fixtures/` instead of
calling the API, so the chrome and later slices can be built and reviewed
without a running backend or seeded data.

Other frontend commands: `npm run check` (types), `npm test` (vitest),
`npm run preview` (serve a production build locally).

To check the built binary actually serves the dashboard end to end:
seed a fresh SQLite database with the round-6 night story
(`go run ./cmd/seed-story ./seed.db`), build the binary with a real
frontend embedded as above, then run `BIRDCAGE_BIN=../birdcage npm run
smoke` from `frontend/` -- it starts that binary against the seeded
database on a free port and checks a real browser sees the sweep
sentence and four tiles.

## Licence

Birdcage is source-available, not open source. See [LICENSE](LICENSE).

**A person or a charity may run it, free of charge, as supplied.** That is the
whole permission: install it, run it, keep a backup. Configuring it is not
modifying it.

Nobody may modify it, build on it, or pass it to anyone else. Third-party
components inside it keep their own licences, several of which allow more than
this one does — those terms are not restricted by this one.

Not permitted at all for a company, including one that only runs it on its own
network and sells nothing; for a government; or for anything funded by the
state, such as a state school or hospital.

A registered charity is permitted whatever else is true of it, including one
that receives government funding. Being a registered charity is the test, not
where its money comes from.

Licences to use it commercially, or to modify or redistribute it, are
available. Ask.
