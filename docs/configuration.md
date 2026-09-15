# Configuration

## Storage: `DATABASE_URL`

Birdcage supports two database engines, per
[issue #7](https://gitlab.tomlawson.io/ai/birdcage/-/issues/7) -- both are
mandatory in v1, not SQLite-with-Postgres-as-an-option: every migration and
every query in `internal/db` and `internal/store` runs on both, and CI tests
both on every change.

`DATABASE_URL` selects which one birdcage uses:

| `DATABASE_URL` | Engine | Notes |
| --- | --- | --- |
| unset | SQLite | Falls back to `BIRDCAGE_DB_PATH` (default `birdcage.db`, in the working directory) -- the pre-Postgres default, unchanged. |
| `sqlite:PATH` | SQLite | Opens the file at `PATH`. |
| `postgres://user:pass@host:5432/dbname` | Postgres | Also accepts the `postgresql://` scheme. Add `?sslmode=disable` for a local/loopback Postgres without TLS; use `sslmode=require` or stronger once it isn't. |

Whichever engine is selected, birdcage creates its own schema (the `alerts`
and `audit_log` tables) on first start -- there is nothing to run by hand
beyond having an empty database and a user with permission to create tables
in it.

**Treat a Postgres `DATABASE_URL` as a credential.** It carries a password in
plain text, the same as the CrowdSec/RouterOS service-account credentials
SECURITY.md already covers: environment variable or Docker/Compose secret,
never in a committed config file, never logged (birdcage's own logging
redacts the userinfo portion before writing a line that mentions it, but
don't rely on that as the only safeguard).

## Backup and restore

### SQLite

The whole database is one file (`BIRDCAGE_DB_PATH`, default `birdcage.db`).

- **Simplest**: stop birdcage, copy the file, restart. SQLite's on-disk
  format has no in-progress-write state once the process holding it is gone,
  so a plain file copy while stopped is a complete, consistent backup.
- **Without stopping birdcage**: use SQLite's own online backup, which is
  concurrency-safe against another connection writing to the database:

  ```
  sqlite3 birdcage.db ".backup birdcage-backup-$(date +%Y%m%d).db"
  ```

To restore, stop birdcage, replace the database file with the backup, and
restart.

### Postgres

Use Postgres' own dump/restore tools against the `DATABASE_URL` birdcage is
configured with (or an equivalent connection to the same server/database).

Back up:

```
pg_dump --format=custom --file=birdcage-backup-$(date +%Y%m%d).dump \
  "postgres://user:pass@host:5432/dbname"
```

Restore into a fresh, empty database (birdcage recreates its schema on next
start if the target is genuinely empty, but restoring the dump is what
brings back the data):

```
pg_restore --clean --if-exists --dbname="postgres://user:pass@host:5432/dbname" \
  birdcage-backup-20260101.dump
```

Stop birdcage before restoring so it isn't writing to the database mid-restore.

## Other environment variables

See [SECURITY.md](../SECURITY.md#network-exposure) for `BIRDCAGE_SYSLOG_ADDR`
and `BIRDCAGE_HTTP_ADDR`, which set the ingestion and dashboard listen
addresses and carry their own network-exposure guidance.

### `BIRDCAGE_INTERNAL_RANGES`

`GET /api/visitors` and `GET /api/trace` (issue #35) classify a source as
"from inside" your own network without being told, using RFC 1918
addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), IPv6 ULA
(`fc00::/7`), and link-local addresses. If part of your LAN uses address
space outside those defaults, list it here as a comma-separated list of
CIDR blocks, e.g.:

```
BIRDCAGE_INTERNAL_RANGES=100.64.0.0/10,203.0.113.0/24
```

Unset (the common case) adds nothing beyond the built-in defaults. An
invalid entry stops birdcage at startup with an error naming the bad CIDR,
rather than silently ignoring it.
