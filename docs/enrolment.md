# Enrolling a canary

Issue #47's flow for turning a fresh box into a canary: birdcage mints a
one-time deploy token, you paste one command on the canary host, and the
canary uses that token to introduce itself to birdcage exactly once
(`POST /enrol/hello`), then exchanges the enrolment secret that call
hands back for its actual credentials -- a bearer token and a client
certificate -- via `POST /enrol/provision` (slice 3). Both steps happen
automatically inside the canary's agent; there is nothing else to run by
hand.

The commands below are `birdcage agent ...`: ADR-0009 gave a node a kind
(honeypot, scanner), so `agent` is the noun for the CLI, not `canary` --
which still works as an alias for every one of these subcommands (#107).

## Before the first canary

Two things need to be set once, before `birdcage agent enrol` will do
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

`birdcage agent enrol` refuses to mint a token until both are set, and
tells you so.

**2. `BIRDCAGE_ADVERTISE_HOST`.** The hostname or IP the canary reaches
this birdcage instance on -- see
[docs/configuration.md](configuration.md#birdcage_advertise_host). Set it
in birdcage's own environment before starting it.

## Enrolling a canary

On the machine running birdcage, name the canary and the lane it belongs
to -- both are required:

```
birdcage agent enrol --name office-nas --lane front-door
```

This prints a `docker run` command and one line underneath it saying how
long the token is valid. Since issue #132, OpenCanary is always its own
container, so there are always at least three blocks: the address holder
first (see ["The address holder"](#the-address-holder) below for what it
is and why it comes first), then the canary (the Mockingbird agent), then
OpenCanary itself. With the SMB lure on (the default) a fourth block
follows for the lure (see ["The SMB lure"](#the-smb-lure) below). It
looks like this (values differ every time):

```
docker volume create --driver local \
  --opt type=tmpfs --opt device=tmpfs --opt o=size=16m,mode=0755 \
  smb-audit

docker run -d --name holder --restart unless-stopped \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 16 \
  --memory 32m \
  -v smb-audit:/audit:ro \
  holder:latest

docker run -d --name mockingbird --restart unless-stopped \
  --cap-add NET_RAW \
  --security-opt no-new-privileges \
  -v mockingbird-state:/var/lib/mockingbird -v mockingbird-log:/var/log/opencanary:ro \
  --network container:holder \
  -v smb-audit:/audit:ro \
  -e MOCKINGBIRD_SMB_AUDIT_PATH=/audit/smb.log \
  -e MOCKINGBIRD_BIRDCAGE_URL=https://203.0.113.10:8444 \
  -e MOCKINGBIRD_CA_PIN=<64 hex characters -- the CA's SHA-256 pin> \
  -e MOCKINGBIRD_DEPLOY_TOKEN=<64 hex characters -- shown once, single-use> \
  mockingbird:latest

docker run -d --name opencanary --restart unless-stopped --init \
  --network container:holder \
  --sysctl net.ipv4.ip_unprivileged_port_start=0 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 32 \
  --memory 128m \
  --tmpfs /var/tmp:size=8m \
  -v mockingbird-log:/var/log/opencanary \
  opencanary:latest
```

followed by a fourth block for the SMB lure (see ["The SMB
lure"](#the-smb-lure) below), and then the line saying how long the token
is valid:

```
token valid for 5 minutes (until 2026-09-19T06:58:08Z); single use
```

`--cap-add NET_RAW` is what lets the canary notice being scanned: the
agent opens one raw socket inside the container's own network namespace
(the holder's -- every honeypot canary joins it now, issue #132) to see
connection attempts aimed at ports none of its emulated services answer
on, which is the only way it can report a port sweep (OpenCanary's own
port-scan module needs firewall rules and a root process, and this
container has neither). Leave the flag off and everything else still
works -- every hit on an emulated service is still reported -- but a
sweep of closed ports goes unseen, and the agent says so in one line at
startup: `port-scan detection is OFF`.

The two `-v` flags on the agent's own command are not optional.
`mockingbird-state` holds the canary's credentials and its place in the
log, and never anything else -- OpenCanary's own container never mounts
it, in either direction (see ["OpenCanary"](#opencanary) below).
`mockingbird-log` holds OpenCanary's log, which is the event store the
agent replays from; the agent only reads it (`:ro`), and OpenCanary's own
command above mounts the same volume read-write, since it is the writer.
Named volumes survive `docker rm` and an image upgrade; the anonymous
volumes Docker would otherwise create do not. Lose the state volume and
the canary cannot start -- it refuses loudly rather than coming back
healthy with no credentials -- and has to be enrolled again. Lose the log
volume and any hits not yet delivered are gone.

### The address holder

The holder (issue #126) does nothing at all -- it just sits there holding
a network address, so the canary, OpenCanary and the lure (if deployed)
can each be restarted independently without taking any of the others'
listening sockets down. It is what all of their own `--network
container:` flags join, in place of joining each other directly. Issue
#132 made it unconditional: before that, it was printed only when the SMB
lure was being deployed, since a lure-less canary had nothing else ever
joining its own namespace; now OpenCanary always does.

Run it **first**, before the canary, OpenCanary or the lure: all of them
join its network namespace, so it has to exist before they do. With the
SMB lure on it also holds the lure's audit volume (below); without the
lure it prints with no volume at all:

```
docker run -d --name holder --restart unless-stopped \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 16 \
  --memory 32m \
  holder:latest
```

It never needs restarting, upgrading only when a new birdcage release
says so, and answers nothing on the network itself -- the canary,
OpenCanary and the lure are what actually listen, on the address it
holds.

### OpenCanary

Before issue #132, OpenCanary ran as the agent's own child process inside
the Mockingbird container (issue #69). The owner's decision on #132,
recorded in the ADR-0008 amendment
(`docs/adr/0013-opencanary-own-container.md`): *"direct attack surfaces
are sensibly segregated into containers."* OpenCanary is now its own
image (`build/opencanary`) and its own container, with no access
whatsoever to `/var/lib/mockingbird` -- the agent's bearer token and its
mTLS client key -- in either direction. It joins the address holder's
network namespace exactly the way the agent does, and its own log volume
is the only thing it shares with the agent.

Restarting OpenCanary alone -- `docker restart opencanary` -- leaves the
agent's heartbeat and the SMB lure (if deployed) running and reporting,
the same guarantee the holder already gives the canary and the lure
(below). What restarting OpenCanary does *not* leave alone is the agent's
own opinion of it: OpenCanary no longer being this agent's own child
process, the agent can no longer notice it die by watching a process
exit (#69's own mechanism, superseded). Instead the agent dials
OpenCanary's own configured ports once per heartbeat and reports what it
finds; a dead OpenCanary shows up on the canary's tile within one
heartbeat interval as `opencanary_down`, and clears on the next heartbeat
that finds it answering again.

`build/opencanary/README.md` has the per-flag hardening evidence, the
same way `build/smb-lure/README.md` has it for the lure below.

### The SMB lure

A canary that offers a file share is the most ordinary thing on an office
network, and it is the thing an intruder looks for first. So `birdcage
canary enrol` also prints a real Samba, serving read-only guest shares on
the canary's own address, when the lure is on (the default). With it on,
the address holder above also carries the audit volume both this
container and the canary read from:

```
docker volume create --driver local \
  --opt type=tmpfs --opt device=tmpfs --opt o=size=16m,mode=0755 \
  smb-audit

docker run -d --name holder --restart unless-stopped \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 16 \
  --memory 32m \
  -v smb-audit:/audit:ro \
  holder:latest
```

#### The lure itself

Run this **after** both the holder and the canary's own `docker run`: the
lure joins the holder's network namespace, so the holder has to exist
first, and the canary has to be enrolled (its state volume created)
before there is anything for the lure to sit beside.

```
docker run -d --name smb-lure --restart unless-stopped \
  --network container:holder \
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

#### Restarting the canary, or the lure, takes nothing else down

Before issue #126, the lure joined the canary container's own network
namespace directly, and restarting the canary destroyed the namespace its
Samba was listening in -- the lure stayed `running` with nothing
answering on port 445, the most misleading state it could be in, because
`docker ps` said it was fine, and only `docker restart smb-lure` fixed it.

With the holder in place, neither the canary nor the lure owns the
namespace the other depends on, so a plain `docker restart mockingbird`
or `docker restart smb-lure` -- on its own, no companion command needed
-- leaves the other one running and the share still answering. The
holder itself is never restarted as part of this; it has nothing to lose
by staying up.

Nothing is lost in the gap either way: the agent picks up where it left
off in the audit file, so an access either side of a restart still
reaches birdcage, and a line it reads twice raises one alert rather than
two. The audit file's own lines also survive a longer gap than one
restart -- the holder keeps the volume mounted even while both the
canary and the lure are stopped, so nothing unread is wiped.

A host reboot, or stopping the holder, is the one thing that does wipe
it: the volume lives in memory. Only lines the agent had not yet sent
are lost, and those pile up only while birdcage is unreachable -- a gap
birdcage already shows as the canary going quiet. This is deliberate
(issue #131): keeping the volume in memory is what caps its size in a
way a compromised Samba cannot get around.

#### Turning it off, and naming the shares

| Flag | Default | What it does |
| --- | --- | --- |
| `--lure smb=off` | on | Deploy no SMB lure. The holder and OpenCanary still print -- issue #132 made the holder unconditional -- but with no audit volume: the enrol output prints no `docker volume create`, no lure block, no `-v smb-audit:/audit:ro` on the holder or the canary, and no `MOCKINGBIRD_SMB_AUDIT_PATH`, and smb stays **untested** on this canary's ledger. |
| `--smb-workgroup` | `WORKGROUP` | The workgroup the share announces. Use whatever the rest of your network uses; a share in a workgroup of its own is the one thing on the segment that looks odd. |
| `--smb-shares` | `public,backup,scans` | The three share names, in that order: documents, configuration backups, scanner output. Names only -- what is on each share is part of the image. |

A name outside `A-Z a-z 0-9 _ -` is refused when you enrol, rather than by
a container that will not start.

The lure's own NetBIOS name and description are not settable, on purpose:
sharing a network namespace shares its hostname too (Docker shares both
together), so the canary, the holder and the lure all present the same
hostname -- Docker's own default (the holder's container id, since
nothing here sets `--hostname`) unless you set one yourself. Nothing
about this reveals what the lure is any more than the unnamed default
already did before #126, and a flag on the lure alone would only be a
way to get it out of step with the address it actually answers on.

Copy the whole `docker run` block and paste it into a shell on the box
you want to turn into a canary. That's it -- the canary's agent
(mockingbird) takes it from there: it dials birdcage at the address and
pin given, presents the deploy token once (`POST /enrol/hello`), and gets
back an enrolment secret, birdcage's CA certificate, and `ingest_url` --
where it will post events once it has real credentials.

## What provisioning hands the canary

The agent generates its own key -- birdcage never sees it, not even for
a second ([ADR-0012](adr/0012-scanner-enrolment-proof.md) Part B1) --
and sends a certificate signing request (CSR) over it along with the
enrolment secret to `POST /enrol/provision`, within the 30-minute window
`POST /enrol/hello` granted. On success it gets, in one response, shown
exactly once:

- a **bearer token** for `POST /ingest/events` and the rest of the
  ingest listener's routes;
- a **client certificate**, signed by birdcage's own CA
  (`(*ca.CA).SignClient`) over the agent's own key -- its subject is
  rewritten from the registry, never taken from the CSR, so nothing the
  agent asked for survives but its public key. The ingest listener
  requires this certificate on every connection, matching the bearer
  token (see [SECURITY.md](../SECURITY.md#network-exposure));
- the **heartbeat interval** it should use.

Nothing about this step needs an operator's attention -- it happens
automatically, seconds after the `docker run` command starts the
container.

## Certificate renewal, and what a stalled one means

A client certificate lives seven days. From half-life (day 3.5) the
agent tries `POST /ingest/renew` on every heartbeat tick until one
succeeds: a fresh key, a fresh CSR, same subject. The old certificate
stays valid until the new one's first use, at which point birdcage
revokes it -- so a renewal never has a moment where the agent is left
holding nothing usable.

If renewal keeps failing, the canary's state moves through two stages,
visible on its tile and its history the same way `rotation_stalled`
already is for bearer tokens:

- **`renewal_stalled`** -- the certificate is past half-life and no
  renewal has landed yet. Nothing is broken yet; check the agent's own
  logs for why `POST /ingest/renew` is failing (usually a network or
  clock problem between the canary and birdcage).
- **`not_delivering`** -- the certificate has now expired outright.
  Every request from this canary is refused. Treat this like any other
  `not_delivering` canary: something on the box needs fixing, or it
  needs re-enrolling.

## Credential conflicts: two holders of one credential

Two states mean the same credential is answering from more than one
place, which is what a copied key or token looks like:

- **`token_conflict`** / **`credential_conflict`** -- a token or
  certificate birdcage already revoked (because its successor is live)
  is still being presented. Expected once, briefly, during an honest
  rotation or renewal race; if it keeps recurring, something still holds
  the old credential.
- **`credential_conflict`** also covers the same live certificate being
  used from two source addresses, or by two different agent build
  versions, within one heartbeat interval (60 seconds). A canary whose
  address legitimately changes (DHCP, a container restart onto a new
  IP) flips this once and clears within a minute; the history keeps the
  flap either way. The one exception is an upgrade run from the upgrade
  command (below): its change of build shows as
  `upgrade_in_progress` for five minutes instead.

Neither state revokes anything by itself -- a copied key must never be
a button that silences the real canary. Both mean: **look at this node,
then revoke if the second holder isn't yours.**

## Revoking a canary's credentials

```
birdcage agent revoke <agent-id>
```

Ends every token and every certificate that canary has, in one action:
from that moment, every request from any holder -- the honest agent or
a copy of its credentials -- is refused, and the honest agent's own log
says so. There is no way to revoke just one credential; a copied key
means the token and certificate must die together.

Recovery is re-enrolling: the same `birdcage agent enrol` command and
printed `docker run` line as a first enrolment. The canary keeps its
name and its history, but gets a new id and a new credential -- a
second enrolment under an existing name never takes over the live
node's credential, it starts a new one.

**Every node enrolled before this landed needs re-enrolling once.**
Nothing about its certificate or token changes on upgrade by itself;
the fix is the same `birdcage agent enrol` command described above.

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
trusting it forever). The fix is the same `birdcage agent enrol`
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

A scanner proves itself the same way, on the same machinery, differently
shaped -- see ["Proving a scanner
works"](#proving-a-scanner-works) below, under its own `--kind scanner`
section.

## Why the token is single-use and five minutes

The deploy token is a bearer credential: whoever has it can claim the
canary identity it mints. Two limits keep the window it's dangerous in
as small as possible:

- **Five minutes.** If the `docker run` command isn't pasted and run
  within five minutes of printing, the token stops working and
  `birdcage agent enrol` has to be run again for a fresh one.
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
birdcage agent enrol --status
```

Lists every enrolment session -- id, name, lane, state, when it was
minted, its deadlines -- without ever printing a token or a hash. Useful
for confirming a session was actually contacted, or for seeing one expire
after being forgotten.

## Enrolling a scanner (Nightjar)

Issue #108, slice 1. The scanner agent -- Nightjar (ADR-0010) -- is a
second agent kind: same `birdcage agent enrol` command, `--kind
scanner`:

```
birdcage agent enrol --name office-nas --lane front-door --kind scanner
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

### Proving a scanner works

A freshly enrolled scanner is **pending**, same as a honeypot, but it
clears pending differently: not on its first heartbeat, on its first
*passing ordered scan*. The moment its credential is first used,
birdcage mints a scan command; Nightjar picks it up on its usual poll,
runs its ordinary job -- mount check, database refresh, Grype over
`/host` -- and posts the result tagged with that command's run id. Only
a pass clears pending. Nothing else does, and nothing about it needs
operator action.

While that run is open, the scanner's tile and its canary page show
which stage it has reached:

| stage | set by | what it means if the run stops here |
| --- | --- | --- |
| `ordered` | birdcage, at mint | connected, but the order was never collected -- the poll loop isn't reaching birdcage, or the build predates it |
| `collected` | birdcage, on claim | collected and nothing came back: the agent died, or ignores `scan` commands |
| `mounts_checked` | Nightjar | the mount covering passed; the database refresh is running (a cold download can sit here for minutes) |
| `db_refreshed` | Nightjar | `grype db update` finished, pass or fail; Grype itself hasn't run yet |
| `scanning` | Nightjar | Grype is running over `/host` |
| `answered` | birdcage | the result landed; pass or fail is on the run |

**Thirty minutes is the outer cap, not the ordinary wait** -- long enough
to cover a cold database download, short enough that a scanner gone
quiet doesn't sit unexplained for hours. A run that reaches the cap
unanswered fails the scanner as **self-test failed**, naming the target
(`scan`) and the last stage reached, and birdcage mints another run
every thirty minutes until one passes -- the honeypot's own retry,
spaced to the scanner's longer cap. A failure Nightjar can see for itself (a missing mask,
Grype exiting non-zero) is reported at once as a failed scan, with no
stage reports in between; the cap only matters for a run that goes
silent.

Every ordered run -- pass, fail or expired -- stays on the canary page's
**Runs** list: trigger, when, verdict, last stage, reason, and a link to
the snapshot that answered it. The tile clears on a pass; the list
never does, so a scanner that failed three times before finally proving
itself still shows those three failures.

Once registered, nothing re-proves a scanner on its own -- there is no
daily self-test the way a honeypot gets one. An admin-ordered scan from
the canary page, behind a fresh sign-in, is planned
([#129](https://gitlab.tomlawson.io/ai/birdcage/-/issues/129)); it will
run the same proof again without touching pending.

### The database refresh is loud, not just late

Every scan -- timer, proof or admin-ordered -- starts with `grype db
update` as its own step, before Grype ever runs. A refresh that fails is
reported at once, not after some delay: the scanner's heartbeat carries
it, and the canary page shows "database refresh failing since `<time>`:
`<error>`" from the very first failed attempt.

A failing refresh doesn't stop scanning by itself. While Grype's own
database is still under its five-day age limit, the scan runs on the
last good list and the snapshot says so -- real data on an aging
database, not a scan withheld (#46's rule: when in doubt, it is real).
Past five days Grype refuses outright, and the scan fails closed instead
of reporting a clean host.

**Twenty-four hours of a failing refresh turns the tile amber**, state
`db_stale`, sentence "vulnerability database not refreshed for `<n>`
hours" -- birdcage's own clock decides this, not the scanner's, so a
wrong clock on the box can't hide or hasten it. It clears on the next
refresh that succeeds; either way, the failing span stays on the
canary's history.

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

### no-new-privileges and `--init`

The printed command runs the agent with `--security-opt
no-new-privileges` (issue #137): nothing in its container can gain
privileges through a setuid or file-capability program. It does not
cost port-scan detection, as long as you do not add `--init` to the
agent's container.

The agent binary carries `NET_RAW` as a file capability: that is how a
process running as an ordinary user gets the capability without the
container ever being root. `no-new-privileges` stops a program from
gaining capabilities its parent did not already have. The agent is the
container's first process, so its parent is Docker's own container
runtime, which already holds `NET_RAW` because of `--cap-add NET_RAW`,
and the agent keeps it. Put `--init` in front of the agent and that init
runs as uid 65532 with no capabilities at all, so the agent started from
it gets none either: port-scan detection is off, and the agent logs one
line saying so at startup.

## Tuning SNMP detection

These settings belong in `docs/configuration.md` with the rest of the
canary's environment variables; they are here for now, alongside the
other detection knobs above, for the same reason.

Both are optional. Set them the same way as the variables in the
`docker run` block above (`-e NAME=value`).

| Variable | Default | What it does |
| --- | --- | --- |
| `MOCKINGBIRD_SNMP` | on | Set to `0` to turn SNMP detection off entirely. Any other value, including unset, leaves it on. |
| `MOCKINGBIRD_SNMP_LISTEN` | `:161` | Where the SNMP UDP socket binds. Point it elsewhere if something else on the host -- a real SNMP agent, for example -- already answers on the standard port. |

## Catching a poisoner on your segment

When a Windows machine cannot find a name in DNS, it asks the whole
local network instead: "does anyone know `fileserver`?" Nothing checks
who answers. Tools like Responder sit on the network and answer every
such question, claiming to be whatever was asked for, and the machine
that asked then tries to log in to the attacker.

Your canary asks for names that do not exist. Nothing on a clean
network should ever answer. Anything that does answer is an attacker
impersonating that name, so this alert almost never fires by mistake.

The canary never connects to whatever answered. The answer itself is
the proof an attacker is listening; connecting to it would be walking
into the trap the attacker set.

| Variable | Default | What it does |
| --- | --- | --- |
| `MOCKINGBIRD_POISONER` | on | Set to `0` to turn the whole thing off, including the listening part. Any other value, including unset, leaves it on. |
| `MOCKINGBIRD_POISONER_NAMES` | empty | Two or three names in your own naming style, comma-separated. If you set none, the canary invents neighbours of its own hostname (a canary called `fs-lon-03` asks for things like `fs-lon-02`). |
| `MOCKINGBIRD_POISONER_PROFILE` | `windows` | `windows`, `linux` or `off`. See below. |
| `MOCKINGBIRD_POISONER_FLOOR` | `2h` | The longest the canary goes without asking anything during working hours. Provisional -- see below. |
| `MOCKINGBIRD_POISONER_CEILING` | `30m` | The shortest gap between one round of questions and the next. Provisional -- see below. |
| `MOCKINGBIRD_POISONER_HOURS` | `08:00-18:00` Mon-Fri | When the canary asks anything at all, in its own timezone. Write it as `HH:MM-HH:MM`, optionally followed by `/` and a comma-separated list of three-letter day names, for example `06:00-22:00/Mon,Tue,Wed,Thu,Fri,Sat`. |

### Setting the names when you enrol

`birdcage agent enrol` takes two optional flags, `--bait-names` and
`--segment-profile`, which put the matching `-e` lines into the
`docker run` command it prints for you:

```
birdcage agent enrol --name fs-lon-04 --lane prod \
  --bait-names old-fs-01,printer-7 --segment-profile linux
```

A name must be 1 to 15 characters of letters, digits and hyphens, and
cannot start or end with a hyphen; at most three are used. The command
checks the names before it mints anything, so a typo does not waste a
deploy token.

Pick names that would have been plausible on your network and no
longer exist -- a file server that was retired, a printer that moved.
The canary also always asks for `wpad`, on top of whatever you set,
because every Windows machine asks for that one and attackers answer
it by name as a matter of course.

These names are deliberately not written into the product anywhere
and are not in this documentation: if an attacker knew which names
were bait, they would simply not answer them. So do not put your real
bait names into a shared runbook or a ticket either.

### The segment profile

- **`windows`** (the default): the canary asks over all three of the
  protocols a Windows machine uses -- LLMNR, NBT-NS and mDNS -- shaped
  the way Windows sends them.
- **`linux`**: only the two a Linux machine uses, LLMNR and mDNS,
  shaped the way `systemd-resolved` and Avahi send them. Use this if
  your network is all Linux -- one Windows-looking machine on an
  all-Linux network is itself conspicuous.
- **`off`**: the canary asks nothing, so nothing is caught. It still
  listens, which costs nothing and means the rate is already measured
  if you turn it on later.

### How often it asks

A fixed timer would be a giveaway: one machine asking the same thing
every ninety minutes all night is the easiest thing on the network to
spot. So the canary listens to how much the other machines on the
segment ask, and matches the middle one -- never the busiest, so one
noisy machine cannot make the canary the loudest thing there. It asks
in bursts of two to five questions inside a minute, like somebody
retrying a share that will not open, only during working hours, plus
one burst shortly after it starts up.

The floor and ceiling defaults above are **provisional guesses**, not
measured values. They will be replaced with real numbers taken from a
packet capture (issue #121). Meanwhile you can change them yourself
with the two variables above.

### Changing these later

These are per-canary settings, and issue #124 gives them a second way to
change: `birdcage agent settings set <agent_id> <key>=<value> [<key>=<value> ...]`,
run on the birdcage host, reaches the running canary on its next
heartbeat with no restart and no new release. For example:

```
birdcage agent settings set fs-lon-04 segment_profile=off
```

The keys are `segment_profile`, `bait_names`, `pace_floor`,
`pace_ceiling` and `working_hours`, validated by the same rules as the
`-e` variables and the enrolment flags above. `birdcage agent settings
show <agent_id>` prints the current value of each, its version, and
whether the agent has actually confirmed running with it (its own
next heartbeat has to report back that it applied the change -- that
takes one heartbeat interval more than applying it does).

The environment variables above still work and are still the only way
to set a starting value the canary boots with -- an operator who never
runs `birdcage agent settings set` for a canary sees exactly the
behaviour this section already describes. Once a value has been set
this way, though, it is what the agent runs with, not the environment.

This cannot yet be done from the canary page in the dashboard: the
dashboard API stays read-only until the login the whole product needs
(#8) exists, so a page that could reprogram a canary's settings with
no authentication at all would be worse than not having the page. The
canary page is issue #134, waiting on that login.

### What the alert says

When something answers, you get an alert under the service name
`poisoner`, naming the address that answered, the hardware (MAC)
address read from the canary's own neighbour table, which of the
three protocols carried the answer, and which name was answered for.
The canary reads the MAC passively and never sends anything to the
answering machine.

## Upgrading a canary

The canary page names an agent that is running an older build than
birdcage itself (issue #54). This is not the same problem revoking and
re-enrolling solves above: nothing is wrong with this canary's
credential, its containers are just running old images.

**Getting the command.** The canary page shows the command to run on
the birdcage host; it prints the agent's upgrade command:

```
birdcage agent upgrade-command <agent-id>
```

Run it the way you run `birdcage agent enrol` (with `docker exec` into
the birdcage container). It prints one block: copy all of it, and paste
it on the agent's host in one go. The block is one grouped shell
command, `( set -e` to `)`, so the shell reads the whole paste before
running any of it, runs every step in order, stops at the first step
that fails and names it ("birdcage upgrade stopped at: ..."), and ends
with "birdcage upgrade: done". It runs the same in bash or plain sh.

**It carries a single-use upgrade token, valid for 15 minutes.** The
note above the block says until when. Each run of the command mints a
new one and makes any earlier unused one useless, so if you let one
expire, just run it again. The token is only ever printed, never shown
on the dashboard: minting one is a change of state, and the dashboard
stays read-only until it has a login (#8). An agent that is not behind
gets no token and no command.

**Why a token: no `credential_conflict` during a normal upgrade.** The
old agent and the new one report two different builds on the same
credential within a minute of each other, which on its own is exactly
what a copied credential looks like (ADR-0012 B4). The upgrade command
hands the token to the new agent image straight after the old agent is
removed and before the new one starts; birdcage accepts it once, and
for the next five minutes that one change of build on that one canary
is expected rather than a conflict. The canary shows
**`upgrade_in_progress`** meanwhile, with the time the window ends.
After it, detection is exactly as before: an old build still running
five minutes on shows `credential_conflict` as usual. The window never
covers a third build, and never a second address.

The token goes to the agent on standard input, piped from the shell's
own `echo`, into a throwaway container of the new image that has the
agent's state volume mounted read-only: it is never in a container's
environment (which Docker keeps for the life of the container), never
a command-line argument, and never written anywhere. That container
presents it with the agent's own certificate and bearer token, prints
one line (accepted, or refused and why), and exits. A refused or
expired token does not stop the upgrade -- the rest of the block runs,
and the worst case is the `credential_conflict` the token exists to
avoid, clearing within two minutes of the old agent's last heartbeat.
Every mint, acceptance and refusal is in the audit log
(`canary.upgrade_token_minted`, `ingest.upgrade_token_accepted`,
`ingest.upgrade_token_refused`).

**A plain `docker restart` does not fix this.** Restarting a container
starts the same image it already had; it never pulls anything newer.
The upgrade command instead pulls every image this canary uses, removes
every one of its containers, and re-runs them -- the same containers
`birdcage agent enrol` printed originally, with the same flags, against
whatever images birdcage's own environment now names.

**No new deploy token is minted, and nothing is asked for one.** Each
agent's credential lives in its own named volume --
`mockingbird-state` for a honeypot, `nightjar-state` for a scanner --
which `docker rm` never touches (only naming a volume in `docker rm -v`
would, and the upgrade command never does that). Both agents check that
volume before looking at `MOCKINGBIRD_DEPLOY_TOKEN`/
`NIGHTJAR_DEPLOY_TOKEN` at all (`ensureEnrolled`, cmd/mockingbird/
config.go and cmd/nightjar/enrol.go): once the state is there, an agent
enrols itself only once, ever, and every later boot -- including this
one -- reads the credential already on disk and ignores the
environment variable entirely. Printing a deploy token here would do
nothing but confuse whoever reads it later into thinking it mattered.
(The upgrade token above is a different thing: it re-enrols nothing,
and only tells birdcage the change of build is expected.)

**The order matters for a honeypot**, which can run up to four
containers sharing one network namespace (owned by the address holder,
"The address holder" above): every image is pulled first, then every
container is removed -- the three that joined the holder's namespace
before the holder itself, since removing a namespace something is still
attached to fails outright -- and then each is re-run in the same order
enrolment used: holder, Mockingbird, OpenCanary, the SMB lure -- with
the upgrade token presented between the holder and Mockingbird, from
inside the holder's network namespace so birdcage sees it from the
canary's own address. A scanner has none of this: Nightjar is a single
standalone container, so its upgrade command is just pull, remove,
present the token, re-run.

**Anything you added to the enrolment lines by hand, add again.** The
upgrade command reprints what `birdcage agent enrol` printed, nothing
more. If you edited those lines when you first ran them -- a
`--network` or `--ip` on the holder to give the canary its own address
on your network, say -- make the same edit to the holder's line here,
or the canary comes back on a different address.

**A canary enrolled before this shipped may have an SMB lure birdcage
never recorded.** Issue #54 is the first thing that ever wrote a
canary's lure decision anywhere durable; before it, `--lure`/
`--smb-workgroup`/`--smb-shares` only decided what that one enrolment
run printed, nothing more. The upgrade command refuses to guess whether
one of these older canaries has a lure running: it prints that
container's own pull/remove/run lines commented out, with a note to
check the host (`docker ps -a --filter name=smb-lure`) and fill in the
workgroup and share names by hand, since those were never recorded
either. A canary enrolled after this shipped never sees this: its lure
decision, on or off, is always known, and the command either includes
the lure's lines plainly or says in one line that this canary has none.

The command is built by `internal/runcmd.Upgrade` from the same
line-building functions `birdcage agent enrol` itself uses (moved into
`internal/runcmd` for exactly this reason: one wrong flag and the two
could never quietly drift apart from each other).

**The server's half comes from the birdcage container's own
environment.** The address, port and pin in the command are the ones
birdcage enrols canaries with -- `BIRDCAGE_ADVERTISE_HOST`, the port of
`BIRDCAGE_ENROL_ADDR`, and its own CA's pin -- and the images are
whatever `MOCKINGBIRD_IMAGE`, `NIGHTJAR_IMAGE`, `HOLDER_IMAGE`,
`OPENCANARY_IMAGE` and `SMB_LURE_IMAGE` name, each falling back to the
same default enrolment uses. `docker exec` inherits the container's
environment, so set an image override on the birdcage container itself
and both the page and the command agree. A birdcage that could not
enrol anything (ingest off, or no `BIRDCAGE_ADVERTISE_HOST`) prints no
command, and the page points here instead.

`scripts/e2e/upgrade.sh` runs this for real on every merge request: it
reports an older release from the canary's own credential, gets the
command from `birdcage agent upgrade-command`, feeds the block to `sh`
as one unit, and checks that the token is accepted, `upgrade_in_progress`
shows and `credential_conflict` never does, and the same canary comes
back on the same certificate with its self-test passing. It then
presents the spent token again and checks it is refused, audited, and
opens nothing.
