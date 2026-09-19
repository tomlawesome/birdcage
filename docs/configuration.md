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

## Dashboard TLS

Issue #63, owner decision: "we must never allow the GUI to run without
https in some form." `BIRDCAGE_HTTP_ADDR` (default `:8080`), together
with `BIRDCAGE_HTTP_TLS_CERT` / `BIRDCAGE_HTTP_TLS_KEY`, must describe
exactly one of three modes, or birdcage refuses to start -- it never
raises a plaintext listener reachable off loopback, and the default
address alone (no certificate) is one of the refusing combinations, not
a silent loopback fallback.

1. **Operator-supplied certificate.** Set both `BIRDCAGE_HTTP_TLS_CERT`
   and `BIRDCAGE_HTTP_TLS_KEY` to PEM file paths (both or neither -- one
   alone is a startup error). birdcage serves HTTPS on
   `BIRDCAGE_HTTP_ADDR`, TLS 1.3 minimum, HTTP/1.1 only -- the same
   floor as the canary ingest listener. The pair is reloaded from disk
   whenever either file's mtime changes, checked on every handshake, so
   renewing a certificate in place (a certbot hook, for example) takes
   effect on the next connection with no restart; if a reload fails
   (caught mid-write) birdcage keeps serving the last good pair and logs
   one warning per failed change, not per handshake.

   ```
   docker run \
     -v /etc/letsencrypt/live/birdcage.example.com:/tls:ro \
     -e BIRDCAGE_HTTP_ADDR=:8080 \
     -e BIRDCAGE_HTTP_TLS_CERT=/tls/fullchain.pem \
     -e BIRDCAGE_HTTP_TLS_KEY=/tls/privkey.pem \
     -p 8080:8080 \
     birdcage
   ```

2. **Plain HTTP bound strictly to loopback.** No certificate configured,
   and `BIRDCAGE_HTTP_ADDR`'s host is `127.0.0.1`, `::1` or `localhost`
   (e.g. `BIRDCAGE_HTTP_ADDR=127.0.0.1:8080`), or a unix socket written
   `unix:///path/to.sock` (created mode `0660`; a stale file from an
   unclean shutdown is removed automatically). This is for a reverse
   proxy that terminates TLS itself and reaches birdcage over loopback
   or a shared volume -- see the nginx example below.

3. **ACME** -- automatic certificate issuance/renewal -- is not
   implemented yet (a dependency decision the owner has not made).

Anything else -- an empty host (the documented default
`BIRDCAGE_HTTP_ADDR=:8080`), `0.0.0.0`, or any other non-loopback host,
with no certificate configured -- refuses to start with one message
naming all three modes and both TLS variables.

## Running as a different user

Issue #70: before anything else, birdcage checks that the data directory
(the parent of `BIRDCAGE_DB_PATH`) is writable, and that any configured
`BIRDCAGE_HTTP_TLS_CERT`/`BIRDCAGE_HTTP_TLS_KEY` are readable, by the uid
and gid it is actually running as. If not, it exits immediately with one
message naming the path, that uid and gid, and the fix -- never a
fallback, never a retry, and never a confusing failure later from
`db.Open` or `tls.LoadX509KeyPair` instead.

The Birdcage container runs as uid:gid `1000:1000`. There is no
`PUID`/`PGID` environment variable to change that: the runtime image is
distroless (no shell, no package manager -- see
`build/birdcage/Dockerfile`), and it never runs as root, so there is
nothing for such a variable to hand off to at startup. Two ways to match
it up with a mounted volume or certificate:

- **Run as yourself**, so whatever you mount in is already readable:
  `docker run --user $(id -u):$(id -g) ...`.
- **Match the default uid**, so the volume or certificate is readable by
  1000:1000 without changing how the container runs:
  `chown 1000:1000 /path/to/volume-or-cert`.

Mockingbird's container runs as uid:gid `65532:65532` (distroless's own
`nonroot`, not 1000 -- see `build/mockingbird/Dockerfile`'s comment for
why) and needs the same treatment for its two volumes,
`/var/lib/mockingbird` and `/var/log/opencanary`: either `chown
65532:65532` them, or run the container with `--user 65532:65532`.

## Reverse proxy: `/api/stream` and buffering

If you're using mode 2 above (plain HTTP on loopback, `BIRDCAGE_HTTP_ADDR=127.0.0.1:8080`)
behind nginx or another TLS-terminating reverse proxy, there's one more
thing to check. `GET /api/stream` (issue #44) is a server-sent-events
connection birdcage holds open and writes to as alerts arrive, so the
dashboard updates within a second instead of waiting for its 30s poll.
birdcage already sends `Cache-Control: no-cache` and
`X-Accel-Buffering: no` on this response, but a proxy with response
buffering on -- nginx's default -- can still hold every event in its own
buffer until it fills, which silently delays the stream by however long
that takes to happen rather than failing anything you'd notice. Confirm
your proxy honors `X-Accel-Buffering`, or disable buffering for this
location explicitly:

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

## Outbound mail

birdcage sends exactly one kind of email: a canary has presented a
credential birdcage had already revoked. That is the one state where the
right response is "go and look at that box now" rather than "it will be
on the dashboard in the morning", and nobody is looking at a dashboard
at three in the morning.

It is off unless you configure it, and nothing else about birdcage
changes if you leave it off. The dashboard's status strip says `mail
off` so the state is visible rather than assumed.

| Variable | Required | What it is |
| --- | --- | --- |
| `BIRDCAGE_MAIL_HOST` | yes | Your submission server as `host:port`, e.g. `smtp.example.net:465`. |
| `BIRDCAGE_MAIL_STARTTLS` | no | `1` to use STARTTLS (port 587). Unset or `0` uses implicit TLS (port 465). |
| `BIRDCAGE_MAIL_USERNAME` | yes | The SMTP username. |
| `BIRDCAGE_MAIL_PASSWORD_FILE` | one of the two | Path to a file containing the password. **Preferred** -- see below. |
| `BIRDCAGE_MAIL_PASSWORD` | one of the two | The password itself. |
| `BIRDCAGE_MAIL_FROM` | yes | The address the mail comes from. |
| `BIRDCAGE_MAIL_TO` | yes | The one administrator address it goes to. |

### All of them, or none of them

Set none and mail is off. Set any one and every required one must be set
and valid, or birdcage refuses to start and names the variable you need
to fix.

That is deliberate. A mailer that starts on a half-finished
configuration works perfectly right up until the moment it matters, and
then fails silently at exactly the moment a canary was cloned. Refusing
at startup, where you are watching, is the only useful time to fail.

The same check covers the values themselves: the two addresses must
parse as addresses, the host must have a real port, and no value may
contain a line break or a control character — a newline in an address
would let whoever chose it add headers of their own to the message.

### Prefer the password file

`BIRDCAGE_MAIL_PASSWORD_FILE` is the recommended one. An environment
variable is readable by anything that can look at `/proc/<pid>/environ`
and is inherited by every process birdcage starts; a file can be mounted
read-only and owned by the birdcage user alone. In Docker Compose that
is a `secrets:` entry, which lands as a file under `/run/secrets/`:

```yaml
services:
  birdcage:
    environment:
      BIRDCAGE_MAIL_HOST: smtp.example.net:465
      BIRDCAGE_MAIL_USERNAME: birdcage@example.net
      BIRDCAGE_MAIL_PASSWORD_FILE: /run/secrets/birdcage_smtp_password
      BIRDCAGE_MAIL_FROM: birdcage@example.net
      BIRDCAGE_MAIL_TO: you@example.net
    secrets:
      - birdcage_smtp_password

secrets:
  birdcage_smtp_password:
    file: ./secrets/smtp-password
```

If you set both, the file wins and birdcage logs a `WARN` saying so —
rather than choosing silently and leaving you convinced you had rotated
a password you had not.

The file must be readable by the user birdcage runs as and must not be
empty; either way it refuses to start, naming the path and this
process's uid and gid (see ["Running as a different
user"](#running-as-a-different-user)). One trailing newline is trimmed,
so a file written with `printf 'secret\n' > ...` or by any text editor
works as you would expect.

### Port 465 or port 587

Two ways in, and you pick by which port your provider gives you:

- **465, implicit TLS.** Leave `BIRDCAGE_MAIL_STARTTLS` unset. The
  connection is encrypted from the first byte.
- **587, submission with STARTTLS.** Set `BIRDCAGE_MAIL_STARTTLS=1`. The
  connection starts in the clear and is upgraded before anything is
  sent. If the server does not offer the upgrade, birdcage stops there:
  no password, no message. It never continues in the clear.

Set the wrong one for your port and the connection will hang or fail the
handshake, so birdcage logs a `WARN` at startup if the port and the
setting disagree.

**There is no plaintext mode, and no way to skip certificate
verification.** Both are deliberate and neither has a switch. If your
server's certificate does not verify, that is a problem with the server
worth fixing — accepting any certificate would hand your SMTP password
to anything sitting on the network path.

### What the mail says, and what it does not

The subject is always the same and names no canary. The body says what
happened, when, what it probably means, and what to do. It contains no
link, no token and no detail of what was actually seen.

Your mailbox is outside birdcage's control, so the message points at the
evidence rather than copying it: "open birdcage the way you always do".
See [SECURITY.md](../SECURITY.md#data-handling).

### How much mail to expect

Very little, by design. One canary can produce at most one message an
hour, and the whole fleet at most twenty an hour. Anything those limits
stop is counted, not dropped: the next message that does go out says how
many alerts were suppressed and since when.

None of this affects the dashboard. A canary's state is what it is
whether or not an email went out about it.

### Checking it works

`GET /api/mail` reports whether mail is configured, when the last
message went out, whether anything is stuck and since when. The
dashboard's status strip shows the same thing in a few words: `mail
off`, `mail ok · last 2 h ago`, or `mail failing since 3 h — <reason>`.

One thing birdcage cannot do is tell you it has died. A process that is
not running sends nothing, including a message about not running. If
that matters to you, your own monitoring has to watch birdcage from
outside it.

## Approval mailbox

An agent only upgrades itself when the administrator has approved it by
replying to birdcage's summary email, and every agent checks that
reply's DKIM signature for itself -- see
[ADR-0007](adr/0007-upgrade-approval-signed-email-and-published-checksums.md).
This is where birdcage collects those replies.

It is off unless you configure it, and nothing else about birdcage
changes if you leave it off. In this release nothing is applied either:
birdcage records what arrived and what it made of it, and the upgrade
command itself is still unmintable.

| Variable | Required | What it is |
| --- | --- | --- |
| `BIRDCAGE_APPROVAL_IMAP_HOST` | yes | Your IMAP server, as `imap.example.net` or `imap.example.net:993`. |
| `BIRDCAGE_APPROVAL_IMAP_USERNAME` | yes | The IMAP username. |
| `BIRDCAGE_APPROVAL_IMAP_PASSWORD_FILE` | one of the two | Path to a file containing the password. **Preferred** -- see below. |
| `BIRDCAGE_APPROVAL_IMAP_PASSWORD` | one of the two | The password itself. |
| `BIRDCAGE_APPROVAL_IMAP_MAILBOX` | no | Which mailbox to read. Defaults to `INBOX`. |

### All of them, or none of them

Set none and the mailbox is off. Set any one and every required one must
be set and valid, or birdcage refuses to start and names the variable you
need to fix -- the same rule, for the same reason, as ["Outbound
mail"](#outbound-mail) above.

The same check covers the values themselves: the host must parse, its
port must be a real port, and no value may contain a line break or a
control character. IMAP is a line protocol, so a newline in the username
or the mailbox name would be a command of whoever chose it.

### Port 993, and nothing else

The connection is TLS from the first byte, which is what port 993 is
for, so the port is filled in for you if you leave it out. There is no
STARTTLS option here, unlike outbound mail: submission genuinely splits
across 465 and 587, and IMAP does not.

**There is no plaintext mode, and no way to skip certificate
verification.** Neither has a switch. This credential reads the mailbox
that authorises upgrades, and accepting any certificate would hand it to
anything sitting on the network path.

### Prefer the password file

`BIRDCAGE_APPROVAL_IMAP_PASSWORD_FILE` is the recommended one, for the
reason given under ["Prefer the password
file"](#prefer-the-password-file) above: an environment variable is
readable by anything that can look at `/proc/<pid>/environ` and is
inherited by every process birdcage starts. In Docker Compose:

```yaml
services:
  birdcage:
    environment:
      BIRDCAGE_APPROVAL_IMAP_HOST: imap.example.net
      BIRDCAGE_APPROVAL_IMAP_USERNAME: birdcage@example.net
      BIRDCAGE_APPROVAL_IMAP_PASSWORD_FILE: /run/secrets/birdcage_imap_password
    secrets:
      - birdcage_imap_password

secrets:
  birdcage_imap_password:
    file: ./secrets/imap-password
```

Set both and the file wins, with a `WARN` saying so. The file must be
readable by the user birdcage runs as and must not be empty; either way
it refuses to start, naming the path and this process's uid and gid.
One trailing newline is trimmed.

### What a poll does

Once a minute birdcage logs in, looks for unread messages whose subject
contains `[birdcage `, downloads them, checks each one, and marks it
read. Everything is bounded, because anyone who learns the address can
put a message in that mailbox: fifty messages a poll, one megabyte a
message, sixty seconds for the whole poll. A message over the size limit
is marked read and skipped without being downloaded, so it cannot block
the mailbox.

A message is only marked read once birdcage has successfully written
down what it made of it. If the database is unavailable the message
stays unread and the next poll picks it up again.

### Checking your provider's signatures

Whether this works at all depends on your mail provider signing what you
send. Save one of your own replies as a `.eml` file and run:

```
birdcage approval check reply.eml
```

It runs exactly the checks an agent runs and tells you in plain words
what passed and the first thing that did not. Two things are relaxed,
and the output says so: it accepts a message up to thirty days old
rather than an hour, and it does not object to a message it has seen
before, because re-reading a saved file is the point.

Set the administrator's address first, or there is nothing to check
against:

```
birdcage settings set admin_approval_address you@example.net
```

One thing worth knowing before you pin an address: the signature has to
come from that address's own domain. If you are `you@mail.example.net`
but your provider signs with `example.net`, pin the address whose domain
matches what they sign with. birdcage will not accept a parent domain,
because working out which parent is legitimate needs a list of every
domain registry's rules, and getting that wrong would let anyone at the
same registry approve your upgrades.

## Other environment variables

See ["Outbound mail"](#outbound-mail) above for the `BIRDCAGE_MAIL_*`
variables, ["Dashboard TLS"](#dashboard-tls) above for `BIRDCAGE_HTTP_ADDR`,
`BIRDCAGE_HTTP_TLS_CERT` and `BIRDCAGE_HTTP_TLS_KEY`, and
[SECURITY.md](../SECURITY.md#network-exposure) for `BIRDCAGE_INGEST_ADDR`
(issue #32's HTTPS canary ingest listener) and its own network-exposure
guidance.

### `BIRDCAGE_HTTP_TLS_CERT` / `BIRDCAGE_HTTP_TLS_KEY`

The dashboard's operator-supplied certificate and key, PEM file paths --
mode 1 of ["Dashboard TLS"](#dashboard-tls) above. Both or neither; one
alone is a startup error. Reloaded automatically whenever either file's
mtime changes.

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
