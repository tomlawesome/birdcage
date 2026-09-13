# Birdcage

Birdcage centralizes alerts from multiple OpenCanary honeypot instances into
a single dashboard — one place to see every decoy hit across your fleet,
instead of digging through per-instance logs. Beyond visibility, it aims to
add intelligent analysis of that activity, log collection and tracing
around each hit, and integration with CrowdSec and RouterOS (via a
dedicated service account) to attempt automated mitigating action against
confirmed threats.

Birdcage is a sidecar to [mikroview](https://github.com/tomlawesome/mikroview):
same look and sign-in model, separate app, talking to it only through API
keys ([ADR-0003](docs/adr/0003-mikroview-sidecar.md)).

Birdcage is in early implementation — the first component to land is the
OpenCanary UDP syslog ingestion bridge (`cmd/birdcage`). See:

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
`:8080` (`go run ./cmd/birdcage`):

```
cd frontend && npm run dev
```

`npm run dev` also understands `?scene=quiet|silent|night` in the URL: it
loads one of the fixtures under `frontend/src/dev/fixtures/` instead of
calling the API, so the chrome and later slices can be built and reviewed
without a running backend or seeded data.

Other frontend commands: `npm run check` (types), `npm test` (vitest),
`npm run preview` (serve a production build locally).
