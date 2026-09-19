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

## Reverse proxy: `/api/stream` and buffering

`GET /api/stream` (issue #44) is a server-sent-events connection birdcage
holds open and writes to as alerts arrive, so the dashboard updates
within a second instead of waiting for its 30s poll. birdcage already
sends `Cache-Control: no-cache` and `X-Accel-Buffering: no` on this
response, but if you put birdcage behind nginx (or another reverse
proxy) with response buffering on -- nginx's default -- the proxy can
still hold every event in its own buffer until it fills, which silently
delays the stream by however long that takes to happen rather than
failing anything you'd notice. Confirm your proxy honors
`X-Accel-Buffering`, or disable buffering for this location explicitly:

```
location /api/stream {
    proxy_pass http://127.0.0.1:8080;
    proxy_buffering off;
    proxy_cache off;
}
```

Nothing breaks if you skip this -- the dashboard's 30s poll (unaffected
by proxy buffering) keeps the page correct either way -- but the "see a
hit the moment it lands" feature this route exists for won't actually
happen until the proxy stops buffering it.

## Other environment variables

See [SECURITY.md](../SECURITY.md#network-exposure) for `BIRDCAGE_HTTP_ADDR`
and `BIRDCAGE_INGEST_ADDR` (issue #32's HTTPS canary ingest listener),
which set the dashboard and ingestion listen addresses and carry their
own network-exposure guidance.

### `BIRDCAGE_CA_DIR`

Where birdcage keeps its own certificate authority (issue #47 slice 1),
used to mint the ingest listener's serving certificate. Default
`/var/lib/birdcage/ca` -- inside the Dockerfile's existing
`/var/lib/birdcage` volume, so a container operator gets a CA that
survives a restart with no Dockerfile change.

If the directory is missing birdcage creates it, mode `0700` (its parent
must exist -- on the container that is the volume). If it already exists
it must be mode `0700` and owned by the birdcage process; birdcage
refuses to start rather than loosen a directory it did not create. The
first time it finds no CA there, it generates one and writes exactly two
files: `ca-key.pem` (mode `0600`) and `ca.pem` (mode `0644`, the public
certificate). Every later start reuses that same CA. This replaces the
former `BIRDCAGE_INGEST_TLS_CERT` / `BIRDCAGE_INGEST_TLS_KEY` settings,
which took an operator-supplied cert/key pair on disk: as of #47 slice 1
(#62 owner decision), the CA key above is the *only* private key
birdcage ever writes to a file -- the listener's own serving certificate
is minted fresh in memory on every start and renewed the same way, never
touching disk.

As of #47 slice 3, this same CA also issues each canary's client
certificate at `POST /enrol/provision` time (`(*ca.CA).IssueClient`,
never written to disk either) and verifies it on every ingest
connection: the ingest listener requires one, matching the bearer
token's canary -- see
[SECURITY.md#network-exposure](../SECURITY.md#network-exposure).

### `BIRDCAGE_ADVERTISE_HOST`

The hostname or IP a canary's agent (#48) reaches this birdcage instance
on, for the ingest listener. Added as a SAN on the CA-minted serving
certificate, alongside `localhost` and `127.0.0.1` (always included), so
a canary connecting to that address passes certificate verification.
Unset is fine for same-host testing, where `localhost`/`127.0.0.1`
already cover it, but a canary reaching birdcage over the network needs
this set to the address it actually dials.

### `BIRDCAGE_ENROL_ADDR`

Issue #47's HTTPS enrolment listener -- `POST /enrol/hello` (slice 1b)
and `POST /enrol/provision` (slice 3), the only two places a freshly
minted deploy token or enrolment secret (`birdcage canary enrol`, see
[docs/enrolment.md](enrolment.md)) are ever accepted. Default `:8444`.
It is not a separate on/off switch: this listener starts whenever
`BIRDCAGE_INGEST_ADDR` is set, since enrolment exists only to hand a
canary the credentials it then uses on the ingest listener -- the two
are one feature. It shares the ingest listener's CA-minted serving
certificate (same SANs, from `BIRDCAGE_ADVERTISE_HOST` and
`BIRDCAGE_CA_DIR` above, same 24h lifetime/6h renewal), but -- unlike the
ingest listener -- never requires a client certificate of its own
callers: a canary has none until `POST /enrol/provision` issues its
first.

`POST /enrol/hello`'s response also carries `ingest_url` (slice 3):
`https://BIRDCAGE_ADVERTISE_HOST:<port of BIRDCAGE_INGEST_ADDR>`, where a
provisioned canary's agent should post. Empty when
`BIRDCAGE_ADVERTISE_HOST` is unset -- birdcage logs a boot warning naming
it, but still starts both listeners.

### Enrolment settings: `admin_approval_address` / `release_address`

Issue #54's two addresses, stored as settings (`birdcage settings set
admin_approval_address <value>` / `birdcage settings set release_address
<value>`, see #46's settings CLI) rather than environment variables,
since an operator may reasonably change either without a redeploy. Both
must be set before `birdcage canary enrol` will mint a session -- it
fails with a clear error naming the `settings set` command otherwise.
`POST /enrol/hello`'s success response carries both, so a freshly
enrolled canary's operator knows where an admin approval and a release
each go.

### `MOCKINGBIRD_IMAGE`

Overrides the image name `birdcage canary enrol` prints in its `docker
run` command. Default `mockingbird:latest` -- birdcage doesn't publish
this image anywhere yet (issue #69), so until then an operator builds
and tags it by hand and points this at whatever they called it.

### `MOCKINGBIRD_CA_PIN` / `MOCKINGBIRD_DEPLOY_TOKEN`

Issue #47's own two enrolment inputs -- the two values `birdcage canary
enrol` prints into the `docker run` command alongside `MOCKINGBIRD_BIRDCAGE_URL`
(see [docs/enrolment.md](enrolment.md)). `MOCKINGBIRD_CA_PIN` is birdcage's
CA certificate's SHA-256 fingerprint (lower-case hex); `MOCKINGBIRD_DEPLOY_TOKEN`
is the one-time, five-minute deploy token. Mockingbird reads both only at
startup, and only when its state directory (`MOCKINGBIRD_STATE_DIR`) holds
none of `ca.pem`, `client.pem`, `client-key.pem` or `token` yet -- when both
are set in that situation, it enrols before doing anything else: contacts
`MOCKINGBIRD_BIRDCAGE_URL` (birdcage's enrolment listener, pinned by
`MOCKINGBIRD_CA_PIN`), then writes everything enrolment hands back into the
state directory (mode `0600`):

| File | Contents |
| --- | --- |
| `ca.pem`, `client.pem`, `client-key.pem`, `token` | Same files a canary needs on every later start (`cmd/mockingbird/config.go`). |
| `ingest-url` | The ingest listener's own address, which `MOCKINGBIRD_BIRDCAGE_URL` no longer names once enrolled -- preferred over it for every request after enrolment. |
| `admin-approval-address`, `release-address` | Issue #54's two addresses, as `POST /enrol/hello` returned them. |

Once the state directory already holds all four of `ca.pem`, `client.pem`,
`client-key.pem` and `token`, both variables are ignored -- Mockingbird logs
that it is ignoring `MOCKINGBIRD_DEPLOY_TOKEN` (never its value) and boots
normally. A state directory holding *some* but not all of those four fails
closed at startup, naming which are missing, rather than guessing whether
to enrol or to boot.

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

### `BIRDCAGE_LOG_LEVEL` / `MOCKINGBIRD_LOG_LEVEL`

Each binary reads its own leveled-logging threshold from its own
environment variable, case-insensitively:

| Value | Effect |
| --- | --- |
| `debug` | Everything, including per-cycle detail. |
| `info` | Normal operation (the default -- unset or an unrecognized value both fall back to this). |
| `warn` | Only failures and degraded conditions. |
| `error` | Only failures that stop a subsystem. |

birdcage (`BIRDCAGE_LOG_LEVEL`) prints a startup banner and a boot
inventory (what was configured, what was skipped and why) ahead of its
usual per-request/per-batch lines. Mockingbird (`MOCKINGBIRD_LOG_LEVEL`)
deliberately prints neither: it runs on the honeypot box itself, so unlike
birdcage it never logs its own configuration, and its log lines are
limited to its own startup announcement, connection failures to
birdcage, and the OpenCanary child process starting or exiting.
