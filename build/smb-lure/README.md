# The SMB lure

A real Samba, in its own container, serving read-only guest shares on a
canary's own address. Issue #87; the design decisions it implements are
numbered there and referred to by number below.

It is a separate image, not a second service inside Mockingbird, because
ADR-0008 draws the boundary that way and because this is the piece the
design *expects* to be attacked. The canary agent never runs Samba; it
only reads a file this container writes.

## Why nothing real is ever on the share

Every file on these shares is invented and is generated at build time
from the templates in `bait/`. No operator's data is ever mounted here,
and there is no configuration option to mount any — pointing the lure at
a real file server was ruled out permanently by the owner on 2026-09-20:
*"never acceptable because that's real user data as bait."*

The reasoning is short. Bait made of real data turns the alarm into the
breach: whoever trips it walks away with something, and the thing that
was supposed to warn you has instead cost you. What makes somebody open
`IT/vpn-setup.pdf` is its **name**, and opening it is the whole alarm —
the contents do no further work. So the contents are fabricated, and
deliberately contain nothing that is or resembles a credential, a key or
a token: addresses are the RFC 5737 documentation ranges, staff
references have no names attached, and the one file that talks about
passwords says they are held elsewhere.

## Build

```
docker build -f build/smb-lure/Dockerfile -t smb-lure .
```

Base `alpine:3.24` (3.24.2, the current stable release), `samba-server`
pinned to `4.23.8-r0`, the exact version in that release's `main`
repository on 2026-09-23. The pin is exact so that a rebuild is a
deliberate act naming the version it moved to. **Rebuild on every Alpine
security update to samba** — that is the trigger, and a pin that has aged
out of the repository fails the build loudly, which is the intended
behaviour rather than a nuisance.

Samba is GPL-3.0-or-later. It ships here unmodified, in its own image,
linked into nothing of ours — the same shape as `grype` in the scanner
image (AGENTS.md, "Shipped as a binary in an agent image").

## Run it beside the canary

The lure joins the Mockingbird container's network namespace (decision
3), so 445 sits on the canary's own address beside telnet, ssh and http:
one enrolment, one address, and a host offering all four *is* a small
NAS. It publishes no port of its own.

Create the audit volume first. It is a size-capped tmpfs: filling it
crashes the lure, which is an alarm, and never touches the host.

```
docker volume create --driver local \
  --opt type=tmpfs --opt device=tmpfs --opt o=size=16m,mode=0755 \
  smb-audit
```

Then the lure. `mockingbird` is the name `birdcage canary enrol` gives the
canary container; the lure joins its network namespace, so that container
has to exist first.

```
docker run -d --name smb-lure --restart unless-stopped \
  --network container:mockingbird \
  --read-only \
  --cap-drop ALL \
  --cap-add SETUID --cap-add SETGID --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  --memory 192m \
  --ulimit core=0 \
  --tmpfs /run:size=8m \
  --tmpfs /var/lib/samba:size=8m \
  --tmpfs /var/cache/samba:size=8m \
  --tmpfs /var/log:size=8m \
  -v smb-audit:/audit \
  -e SMB_WORKGROUP=WORKGROUP \
  -e SMB_SHARE_PUBLIC=public \
  -e SMB_SHARE_BACKUP=backup \
  -e SMB_SHARE_SCANS=scans \
  smb-lure:latest
```

This is the same text `birdcage canary enrol` prints and the same text
`docs/enrolment.md` shows; `TestSMBLureRunCommandMatchesTheDocs` in
`cmd/birdcage` fails if the three ever drift, because a hardening flag
quietly dropped from one copy is a lure running without it.

And Mockingbird mounts the same volume **read-only** and is told where to
read (decision 6: the volume is the only thing shared, and it is
one-way):

```
  -v smb-audit:/audit:ro \
  -e MOCKINGBIRD_SMB_AUDIT_PATH=/audit/smb.log
```

Without that variable the agent's SMB road does not run at all, which is
what a canary deployed without the lure looks like.

Either container may start first. The agent's tailer waits for the file
to appear and, unlike OpenCanary's own SMB module, reads from a saved
position rather than from the end of the file — so a restart of either
side loses nothing.

### What each flag is holding shut

smbd runs as root and switches to the guest uid per connection; there is
no unprivileged smbd. So rather than not running as root, the design
makes root worth as little as possible (decision 5).

| Flag | What it stops |
|---|---|
| `--read-only` | Nothing an attacker writes to the image's filesystem survives, or is even possible. |
| `--cap-drop ALL` plus four | Everything a compromised smbd could otherwise do with root. |
| `--security-opt no-new-privileges` | A setuid binary cannot raise privileges from inside. |
| default seccomp | Left on, deliberately not `unconfined`. |
| `--pids-limit 128` | A fork loop cannot exhaust the host; Samba's own `max smbd processes = 50` refuses first. |
| `--memory 192m` | The same for memory. |
| `--ulimit core=0` | No core dumps. Samba's own `dump core` option no longer exists, so this is the layer that can still refuse them. |
| `--tmpfs ...` | Every path Samba writes to is memory that vanishes on restart. |

**Which capabilities are actually needed**, tested by running the image
with each one removed (2026-09-23, Docker 29.7.2 rootless):

- `SETGID` — **required**. Without it smbd dies at start:
  `INTERNAL ERROR: sys_setgroups failed`.
- `SETUID` — **required**. Without it the server starts and every
  connection dies: `PANIC (pid 36): failed to set uid`.
- `NET_BIND_SERVICE` — **not needed under Docker**, which sets
  `net.ipv4.ip_unprivileged_port_start=0` in every container, so 445 is
  not a privileged port there. Kept in the command because that default
  is Docker's, not the kernel's, and another runtime binding 445 without
  it would fail.
- `CHOWN` — **not needed** and deliberately absent: the share is
  read-only and already owned by root. Decision 5 listed it before the
  image was run; the running image proved it unused, so it went.
- `DAC_OVERRIDE` — **not needed**, and deliberately absent. The bait
  files are world-readable (0444), so the guest account reads them
  without it.

## Configuration

Identity follows the operator's naming (decision 7), never ours. Sharing
the canary's network namespace shares its hostname too, so the defaults
are already the canary's own name and nothing needs setting.

| Variable | Default | |
|---|---|---|
| `SMB_WORKGROUP` | `WORKGROUP` | NT workgroup name |
| `SMB_SERVER_NAME` | the hostname, upper-cased, 15 characters | NetBIOS name |
| `SMB_SERVER_STRING` | the hostname | the description a client sees |
| `SMB_SHARE_PUBLIC` | `public` | name of the documents share |
| `SMB_SHARE_BACKUP` | `backup` | name of the backups share |
| `SMB_SHARE_SCANS` | `scans` | name of the scans share |
| `SMB_AUDIT_FILE` | `/audit/smb.log` | where the log is written |

Renaming a share changes only the name clients see; the directory behind
it is fixed, because what is on it is part of the image. Each value is
checked against a character set at start-up and a bad one is a loud exit,
not a silent fall back to the default.

No string inside the image says what the image is for. That is a rule
(decision 7), and it is why the configuration files copied into it carry
short, ordinary comments while the reasoning lives in this file, which is
not copied in.

## The audit file

`vfs_full_audit` writes straight to the file — there is no syslog daemon
here, because the `smbd_audit:` tag that OpenCanary's own parser needs is
syslog's ident and we do not use that parser (`docs/opencanary.md`). One
line per audited operation, captured from this image:

```
[2026/09/23 22:25:19.041076,  1]   root|172.21.0.3|shared|close|ok|/srv/shares/public/IT/vpn-setup.pdf
```

`close`, not `open`: on SMB2 an open arrives as `openat`, whose message
carries an extra `r`/`w` field ahead of the path (#78's note). The agent
refuses that shape loudly rather than reading the flag as a filename —
`internal/agent/smbaudit`.

smbd's own panic lines go to the same file and become their own kind of
alert. So does anything smbd writes to stderr, which is why `docker logs`
on this container is empty: read `/audit/smb.log` instead.

Two things worth knowing:

- One `get` of one file writes about five lines: closes on the share
  root, the directory and the file, some of them twice. They reach the
  operator as **one** alert naming the file — the agent collapses the
  walk (#123, `internal/agent/smbaudit/collapse.go`). Two files opened in
  the same second stay two alerts.
- Samba creates an empty `cores` directory next to the log file. Nothing
  is ever written into it (`--ulimit core=0`), and it is not
  configurable separately from the log path.

## What is not here

Writable shares (decision 2 keeps them out of M1; the RCE history
clusters there), SMB1, printing, `unix extensions`, the AD domain
controller role, nmbd, winbind, any VFS module but `full_audit`, and any
Samba client tool. The CVE pass behind each of those is in issue #87's
research note of 2026-09-23.
