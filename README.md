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
