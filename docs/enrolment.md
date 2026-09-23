# Enrolling a canary

Issue #47's flow for turning a fresh box into a canary: birdcage mints a
one-time deploy token, you paste one command on the canary host, and the
canary uses that token to introduce itself to birdcage exactly once
(`POST /enrol/hello`), then exchanges the enrolment secret that call
hands back for its actual credentials -- a bearer token and a client
certificate -- via `POST /enrol/provision` (slice 3). Both steps happen
automatically inside the canary's agent; there is nothing else to run by
hand.

## Before the first canary

Two things need to be set once, before `birdcage canary enrol` will do
anything:

**1. The two enrolment addresses (issue #54).** `POST /enrol/hello`
hands these to a freshly enrolled canary so its operator knows where an
admin approval and a release each go. Set them with:

```
birdcage settings set admin_approval_address "<your address>"
```

```
birdcage settings set release_address "<your address>"
```

`birdcage canary enrol` refuses to mint a token until both are set, and
tells you so.

**2. `BIRDCAGE_ADVERTISE_HOST`.** The hostname or IP the canary reaches
this birdcage instance on -- see
[docs/configuration.md](configuration.md#birdcage_advertise_host). Set it
in birdcage's own environment before starting it.

## Enrolling a canary

On the machine running birdcage, name the canary and the lane it belongs
to -- both are required:

```
birdcage canary enrol --name office-nas --lane front-door
```

This prints a `docker run` command and one line underneath it saying how
long the token is valid. It looks like this (values differ every time):

```
docker run -d --name mockingbird --restart unless-stopped --init \
  --sysctl net.ipv4.ip_unprivileged_port_start=0 \
  --cap-add NET_RAW \
  -v mockingbird-state:/var/lib/mockingbird -v mockingbird-log:/var/log/opencanary \
  -v smb-audit:/audit:ro \
  -e MOCKINGBIRD_SMB_AUDIT_PATH=/audit/smb.log \
  -e MOCKINGBIRD_BIRDCAGE_URL=https://203.0.113.10:8444 \
  -e MOCKINGBIRD_CA_PIN=<64 hex characters -- the CA's SHA-256 pin> \
  -e MOCKINGBIRD_DEPLOY_TOKEN=<64 hex characters -- shown once, single-use> \
  mockingbird:latest
```

followed by a second block for the SMB lure (see ["The SMB
lure"](#the-smb-lure) below), and then the line saying how long the token
is valid:

```
token valid for 5 minutes (until 2026-09-19T06:58:08Z); single use
```

`--cap-add NET_RAW` is what lets the canary notice being scanned: the
agent opens one raw socket inside the container to see connection
attempts aimed at ports none of its emulated services answer on, which
is the only way it can report a port sweep (OpenCanary's own port-scan
module needs firewall rules and a root process, and this container has
neither). Leave the flag off and everything else still works -- every
hit on an emulated service is still reported -- but a sweep of closed
ports goes unseen, and the agent says so in one line at startup:
`port-scan detection is OFF`.

The two `-v` flags are not optional. `mockingbird-state` holds the
canary's credentials and its place in the log; `mockingbird-log` holds
OpenCanary's log, which is the event store the agent replays from. Named
volumes survive `docker rm` and an image upgrade; the anonymous volumes
Docker would otherwise create do not. Lose the state volume and the
canary cannot start -- it refuses loudly rather than coming back healthy
with no credentials -- and has to be enrolled again. Lose the log volume
and any hits not yet delivered are gone.

### The SMB lure

A canary that offers a file share is the most ordinary thing on an office
network, and it is the thing an intruder looks for first. So `birdcage
canary enrol` also prints a second container: a real Samba, serving
read-only guest shares on the canary's own address.

Run these **after** the canary's own `docker run`, in this order. The
volume has to exist before either container touches it, and the lure joins
the canary container's network namespace, so that container has to be
there first.

```
docker volume create --driver local \
  --opt type=tmpfs --opt device=tmpfs --opt o=size=16m,mode=0755 \
  smb-audit

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

Port 445 then sits on the canary's own address beside telnet, ssh and
http: one enrolment, one address, and a machine offering all four *is* a
small NAS. The lure publishes no port of its own.

#### Why nothing real is ever on the share

Every file on those shares is invented, and is generated when the image is
built. **Nothing you own is ever mounted there, and there is no setting
that would let you.** Pointing a canary at a real file server was ruled
out permanently.

The reason is worth a sentence, because the temptation is real: bait made
of real data turns the alarm into the breach. Whoever trips it walks away
with something, and the thing that was supposed to warn you has cost you
instead. What makes somebody open `IT/vpn-setup.pdf` is its **name**, and
opening it is the whole alarm -- the contents do no further work. So the
contents are fabricated, and deliberately contain nothing that is or even
looks like a credential, a key or a token.

You will see files with promising names -- a VPN setup document, a router
configuration backup, a spreadsheet of salaries. All of them are invented.
The addresses in them are the ranges reserved for documentation, the staff
references have no names attached, and the one file that mentions
passwords says they are kept somewhere else.

#### Why every flag is there

The Samba process inside runs as root and switches user for each
connection -- there is no way to run it unprivileged. So the design makes
that root worth as little as possible rather than pretending it is not
root: a read-only filesystem, two capabilities out of about forty,
no way to gain privileges, caps on processes and memory, no core dumps,
and every path Samba writes to is memory that vanishes when the container
restarts. Nothing an intruder changes in there survives.

`build/smb-lure/README.md` has the per-flag table and the evidence for
which capabilities are actually needed.

#### Turning it off, and naming the shares

| Flag | Default | What it does |
| --- | --- | --- |
| `--lure smb=off` | on | Deploy no SMB lure. The enrol output then prints no second block and no `MOCKINGBIRD_SMB_AUDIT_PATH`, and smb stays **untested** on this canary's ledger. |
| `--smb-workgroup` | `WORKGROUP` | The workgroup the share announces. Use whatever the rest of your network uses; a share in a workgroup of its own is the one thing on the segment that looks odd. |
| `--smb-shares` | `public,backup,scans` | The three share names, in that order: documents, configuration backups, scanner output. Names only -- what is on each share is part of the image. |

A name outside `A-Z a-z 0-9 _ -` is refused when you enrol, rather than by
a container that will not start.

The lure's own NetBIOS name and description are not settable, on purpose:
sharing the canary's network namespace shares its hostname, so the share
already names itself after the canary, and a flag would only be a way to
get that wrong.

Copy the whole `docker run` block and paste it into a shell on the box
you want to turn into a canary. That's it -- the canary's agent
(mockingbird) takes it from there: it dials birdcage at the address and
pin given, presents the deploy token once (`POST /enrol/hello`), and gets
back an enrolment secret, birdcage's CA certificate, and `ingest_url` --
where it will post events once it has real credentials.

## What provisioning hands the canary

The agent immediately spends that enrolment secret at `POST
/enrol/provision`, within the 30-minute window `POST /enrol/hello`
granted. On success it gets, in one response, shown exactly once:

- a **bearer token** for `POST /ingest/events` and the rest of the
  ingest listener's routes;
- a **client certificate and private key**, issued by birdcage's own CA
  (`(*ca.CA).IssueClient`), whose subject names this canary -- the
  ingest listener now requires one on every connection, matching the
  bearer token (see
  [SECURITY.md](../SECURITY.md#network-exposure));
- the **heartbeat interval** it should use.

Nothing about this step needs an operator's attention -- it happens
automatically, seconds after the `docker run` command starts the
container.

### The certificate carries the agent's kind

Since [ADR-0011](adr/0011-certificate-kind-authorisation.md), the
certificate's subject also carries the agent's kind (`--kind honeypot`
or `--kind scanner`, whichever this node enrolled as) in its
Organizational Unit -- one value, fixed for the life of this identity.
The ingest listener authorises every route on it: a honeypot's
certificate cannot post vulnerability findings, and a scanner's cannot
post honeypot alerts. A refused kind reads as `403` in the agent's own
logs, never `401` -- the credential itself is fine, it is simply not the
right one for that route.

**Every node enrolled before this landed needs re-enrolling.** Its
certificate carries no kind at all, and is refused at every ingest
route the moment this ships -- there is no grace period and no
grandfather clause (the reasoning is in ADR-0011: nothing renews a
client certificate today, so "trust it until it renews" would mean
trusting it forever). The fix is the same `birdcage canary enrol`
command and printed `docker run` line described above; there is nothing
else to do.

## Pending until the first self-test passes

Provisioning hands the agent working credentials, but the dashboard
doesn't call the canary healthy yet -- it shows **pending**. A canary
that installs cleanly and never actually reports is exactly the failure
this whole design exists to prevent, and it looks identical to a healthy,
quiet one unless something proves the chain works.

So birdcage proves it once, automatically, the moment the agent's new
credential is first used for anything: it mints a self-test run for that
canary -- the same round trip [issue #46](https://gitlab.tomlawson.io/-/issues/46)
runs daily thereafter -- regardless of whether the operator has the daily
self-test schedule turned on. The agent picks the command up on its
ordinary poll and probes its own services. Most targets answer with a
marker OpenCanary logs verbatim; portscan is always one of them (it is
the agent's own detector, not a listening service, so every honeypot
canary gets one regardless of which ports it offers) and, like ntp when
enabled, carries no marker of its own -- the agent claims that hit
locally, from the network facts of its own probe, and birdcage
corroborates the claim independently before treating it the same as a
marked hit. Only once every target answers -- marked or claimed -- does
the canary flip from **pending** to registered; from then on it's an
ordinary canary, subject to the daily schedule like any other.

If that first run times out unanswered, the canary stays pending -- and
also shows self-test failed -- and birdcage mints another run every ten
minutes until one passes, whether or not the daily self-test is switched
on, with nothing to rebuild on the box. There is no operator action that
skips this step; it is the proof, not a formality.

A scanner has no self-test yet, so nothing could ever prove it this way:
it registers on provisioning, and its first heartbeat is the only proof
it works. [Issue #116](https://gitlab.tomlawson.io/ai/birdcage/-/issues/116)
gives the scanner kind a proof of its own.

## Why the token is single-use and five minutes

The deploy token is a bearer credential: whoever has it can claim the
canary identity it mints. Two limits keep the window it's dangerous in
as small as possible:

- **Five minutes.** If the `docker run` command isn't pasted and run
  within five minutes of printing, the token stops working and
  `birdcage canary enrol` has to be run again for a fresh one.
- **Single use.** The moment the canary presents the token, it is burned
  -- pasting the same command a second time (on the same box, or by
  mistake on a different one) is refused, and birdcage logs it as a
  token-reuse event.

## Where the token stays visible until it's burned

Until the canary makes contact, the raw token exists in a few places you
should be aware of:

- **Your shell history**, since you pasted the whole command.
- **`docker inspect mockingbird`**, since it's an environment variable on
  the running container -- anyone with access to the Docker daemon on
  that box can read it out.

Neither of these matters once the token is burned (it stops being usable
the instant first contact succeeds), but if you're worried about either
in the meantime, clear your shell history after pasting and treat the
box as holding a live credential until the container's logs show it
connected.

## Checking on enrolment sessions

```
birdcage canary enrol --status
```

Lists every enrolment session -- id, name, lane, state, when it was
minted, its deadlines -- without ever printing a token or a hash. Useful
for confirming a session was actually contacted, or for seeing one expire
after being forgotten.

## Enrolling a scanner (Nightjar)

Issue #108, slice 1. The scanner agent -- Nightjar (ADR-0010) -- is a
second agent kind: same `birdcage canary enrol` command, `--kind
scanner`:

```
birdcage canary enrol --name office-nas --lane front-door --kind scanner
```

The printed command looks like this (values differ every time):

```
docker run -d --name nightjar --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v /:/host:ro \
  -v /dev/null:/host/etc/shadow:ro \
  -v /dev/null:/host/etc/gshadow:ro \
  --tmpfs /host/etc/ssh:ro \
  --tmpfs /host/root:ro \
  --tmpfs /host/proc:ro \
  --tmpfs /host/run:ro \
  --tmpfs /host/sys:ro \
  --tmpfs /host/dev:ro \
  --tmpfs /host/tmp:ro \
  --tmpfs /host/var/tmp:ro \
  --tmpfs /host/home:ro \
  -v nightjar-state:/var/lib/nightjar -v nightjar-grype-db:/var/lib/nightjar-grype-db \
  -e NIGHTJAR_BIRDCAGE_URL=https://203.0.113.10:8444 \
  -e NIGHTJAR_CA_PIN=<64 hex characters -- the CA's SHA-256 pin> \
  -e NIGHTJAR_DEPLOY_TOKEN=<64 hex characters -- shown once, single-use> \
  nightjar:latest
token valid for 5 minutes (until 2026-09-19T06:58:08Z); single use
```

Nightjar has no listener, no published port and no capability at all --
`--cap-drop ALL` drops even the ones Mockingbird's own `--cap-add
NET_RAW` needs, because Nightjar has nothing analogous to detect. It
mounts the whole host filesystem read-only at `/host` and runs Grype
(the pinned scanner binary the image ships) against it on a timer,
posting a snapshot of what it finds back to birdcage.

### The mask flags are not optional either

The `-v /dev/null:...` and `--tmpfs ...:ro` flags cover secret-bearing
host paths -- `/etc/shadow`, SSH host keys, `/root`, `/proc` (where a
command line can carry a password), `/home`, and a handful of others --
so Grype never reads them even though it could otherwise see everything
on the host through `/host`. The full list and the reasoning behind each
entry live in `internal/hostmask` (issue #108's "second opinion on the
host mount" record has the complete history). Nightjar checks this
covering itself at startup, before it ever runs a scan: if a mask is
missing or if anything under `/host` is not mounted read-only, it posts
`status: "failed"` naming the offending path and does not scan, rather
than trusting the run command alone. So a hand-edited copy of this
command that drops a mask flag does not silently lose the covering --
it stops scanning instead, loudly.

**A snapshot is never complete host coverage.** Nightjar runs as an
unprivileged user; a non-root scan silently skips whatever that user
cannot read, on top of what the masks above deliberately hide.

### Two things that catch people out

**A mask flag over a path your host does not have fails the container
at start**, with a read-only-filesystem error, because Docker cannot
create a mountpoint under a read-only bind for something that was never
there. If your host has no `/etc/ssh` (no SSH installed at all, for
instance), delete that one `--tmpfs /host/etc/ssh:ro \` line from the
pasted command and try again -- do not delete the whole mount, and do
not drop `--read-only` to work around it.

**Docker 25 or newer is required.** `ro` on a whole-root bind mount is
only *recursively* read-only from Docker 25 onward (kernel 5.12+); on an
older engine a host submount -- a separate `/home` partition, `/boot`,
its own `/run` -- can stay writable underneath `/host` even though the
top-level bind itself reports read-only. Nightjar's own startup check
(above) is the backstop for this: it inspects every mount under `/host`
individually and refuses to scan if any of them is not read-only, so an
old engine fails loudly at every scan rather than silently scanning
through a gap. Upgrading the engine is still the real fix.

### The vulnerability database volume

`nightjar-grype-db` is a second named volume, separate from
`nightjar-state`: it holds Grype's own vulnerability database, which
Grype fetches and refreshes itself on every scan -- birdcage never
fetches, vendors or bakes this in. It grows to roughly a gigabyte and is
worth keeping around between restarts (a fresh volume means a slow cold
re-download before the first scan can run); do not delete it casually.

If the database cannot be fetched or refreshed, or is older than five
days, Grype refuses to run against it -- Nightjar reports that scan as
`status: "failed"` with the reason, never as a clean host with zero
findings.

## Tuning port-scan detection

These settings belong in `docs/configuration.md` with the rest of the
canary's environment variables; they are here for now because that file
was being edited elsewhere when this landed, and should move across when
both changes have settled.

All three are optional. Set them the same way as the variables in the
`docker run` block above (`-e NAME=value`).

| Variable | Default | What it does |
| --- | --- | --- |
| `MOCKINGBIRD_PORTSCAN` | on | Set to `0` to turn port-scan detection off entirely. Any other value, including unset, leaves it on. |
| `MOCKINGBIRD_PORTSCAN_IGNORE_PORTS` | empty | Comma-separated extra ports to treat as yours, on top of the ones OpenCanary is configured to answer on. For something else sharing the container's network, or a monitoring probe that would otherwise look like a sweep. |
| `MOCKINGBIRD_OPENCANARY_CONF` | `/etc/opencanaryd/opencanary.conf` | Where to read OpenCanary's configuration from. Only change this if you bind-mount your own configuration somewhere else. |

The agent reads the OpenCanary configuration once at startup to work out
which ports it is answering on, so enabling or disabling a service in
that file also changes what counts as a scan -- you do not have to keep
a second list in step.

### What counts as a scan

Five different ports that nothing answers on, touched by the same source
within thirty seconds. That produces one alert; while the scan
continues, at most one more per minute from the same source. The canary
is built to be flooded, so it reports the fact of a sweep rather than
one alert per packet.

### What it does not see

- **A scan of only the ports your canary answers on.** Those are hits on
  the emulated services and are reported as such, not as a scan.
- **A fragmented scan.** The agent reads the first fragment of a packet
  and ignores continuations, because reassembling fragments would mean
  holding unbounded state on the one box built to attract attacks.
- **IPv6.** Today it watches IPv4 only.
- **Anything outside the container's own network.** The socket sees the
  container's interfaces and nothing else.

### If you also use `--security-opt no-new-privileges`

You cannot have both. `no-new-privileges` tells the kernel to ignore
file capabilities, and the file capability on the agent binary is
exactly how a process running as an ordinary user gets `NET_RAW` without
the container ever being root. Docker does not hand the capability to a
non-root process any other way. Pick one:

- **Keep `--cap-add NET_RAW`, drop `no-new-privileges`** -- the default,
  and what the printed command does. The container still drops every
  other capability, still runs as uid 65532, and still has no shell.
- **Keep `no-new-privileges`, drop `--cap-add NET_RAW`** -- port-scan
  detection is off, and the agent logs one line saying so at startup.
