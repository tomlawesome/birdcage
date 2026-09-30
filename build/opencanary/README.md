# OpenCanary

Upstream OpenCanary alone, in its own container. Issue #132 split it out
of Mockingbird, which used to run it as the agent's own child process
(issue #69); the ADR-0008 amendment recorded alongside this issue is why
it is a separate image rather than staying a second process inside one
container: *"direct attack surfaces are sensibly segregated into
containers."*

This is the container built to be attacked. The agent (Mockingbird) never
runs any of this; it only reads the log this container writes.

## Why it has no access to the agent's own state

Before this split, the same container that ran OpenCanary also held
`/var/lib/mockingbird` -- the agent's bearer token and its mTLS client
key. A compromise of any OpenCanary module (a memory-safety bug in a
Twisted protocol handler, or a Python dependency's own CVE) ran in the
same filesystem as those credentials, one `open()` away. This image never
mounts that volume, in either direction, and never will: there is no
configuration option that adds it. `scripts/e2e/opencanary-isolation.sh`
proves it by trying to read the volume from inside a container started
from this image and expecting the attempt to fail.

## Build

```
docker build -f build/opencanary/Dockerfile -t opencanary .
```

Base `python:3.13-slim-trixie` for the pip install stage, runtime
`gcr.io/distroless/python3-debian13:nonroot` -- both unchanged from
Mockingbird's own choices before this split. `requirements.txt` is the
same file, uv-compiled from `requirements.in` with hashes for every wheel
and sdist, gated by the same `scripts/licence-check-python.sh` (#95).
Nothing about the Python dependency set changed in this move.

## Run it beside the canary

This container, the agent and the SMB lure (if deployed) all join the
address holder's network namespace (issue #126) rather than owning one
directly, so restarting any one of them alone never takes another's
listening sockets down. Start the holder first, then the agent
(Mockingbird), then this image -- in that order, because OpenCanary's
webhook handler makes one attempt to reach the agent's receiver as each
module starts, and upstream's application loader treats a refused
connection as fatal, not as a dropped event: started before the agent is
listening, this container exits immediately and Docker's restart policy
retries it until the agent comes up. Reproduced directly against this
image (2026-09-26): started alongside a bare network namespace with
nothing on 127.0.0.1:9919, `docker logs` showed
`ConnectionError ... Connection refused` and the container exited 1
before a single module bound its port; started once something answered
that address, every module started normally within a second. This is
upstream's own behaviour, unchanged by the split -- the single-container
design avoided it entirely by starting the receiver first, in-process,
before ever starting OpenCanary as its child.

```
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

This is the same text `birdcage agent enrol` prints and the same text
`docs/enrolment.md` shows; `TestOpenCanaryRunCommandMatchesTheDocs` in
`cmd/birdcage` fails if the copies ever drift.

The agent joins the same holder namespace and mounts the same log volume
**read-only**, tailing it exactly the way it already tails the SMB lure's
audit file over a second shared volume:

```
  --network container:holder \
  -v mockingbird-log:/var/log/opencanary:ro
```

### What each flag is holding shut

Unlike the SMB lure, nothing here runs as anything but the distroless
image's own nonroot user throughout -- OpenCanary never needs to become
another uid, so there is no root process to make "worth little" the way
the lure's design does. The starting point is therefore stricter: every
capability dropped, and none added back.

| Flag | What it stops |
|---|---|
| `--read-only` | Nothing an attacker writes to the image's filesystem survives, or is even possible. |
| `--cap-drop ALL`, no `--cap-add` | Everything a compromised module could otherwise do with any Linux capability. See below for the evidence this is enough. |
| `--security-opt no-new-privileges` | Nothing in this image is setuid, but the flag costs nothing and closes the class outright. |
| default seccomp | Left on, deliberately not `unconfined`. |
| `--pids-limit 32` | A fork bomb in a compromised module cannot exhaust the host. OpenCanary itself never forks. |
| `--memory 128m` | The same for memory. |
| `--sysctl net.ipv4.ip_unprivileged_port_start=0` | Lets a non-root process bind 21, 22, 23, 80 and the rest without `CAP_NET_BIND_SERVICE` -- a namespace-wide floor, not a capability grant, so dropping every capability does not undo it. |
| `--tmpfs /var/tmp:size=8m` | The one path OpenCanary writes to at runtime (the SSH module's host key, regenerated every start) -- required, not optional; see below. |

**Which capabilities are actually needed**, tested by running the image
with `--cap-drop ALL` and nothing added back, alongside a real address
holder and the sysctl above (2026-09-26, Docker 29.8.1 rootless): every
module `opencanary.conf` enables -- including the seven bound to ports
under 1024 -- started and bound its port. Nothing failed, so nothing was
added back. Binding a low port needs `CAP_NET_BIND_SERVICE` or the
sysctl above; with the sysctl set, ports stop being "privileged" for the
whole namespace and the capability is not consulted at all. OpenCanary
itself opens no raw socket and sets no other uid or gid -- there was no
capability left to test removing.

**`--read-only` alone is not enough**, found by the same run: the SSH
module generates a fresh host key pair on every start (`ssh.py`'s
hard-coded `SSH_PATH`, `/var/tmp/id_rsa`), and with the root filesystem
read-only that write failed --
`OSError: [Errno 30] Read-only file system: '/var/tmp/id_rsa.pub'` --
which upstream treats as fatal to the whole application, not a dropped
event: every module refused to start, not only SSH's. This is not a
capability question (writing to a path this image owns needs no
capability at all, only a writable filesystem there), so the fix is
`--tmpfs /var/tmp:size=8m` -- memory that vanishes on restart, which is
exactly right for a key that never needs to survive one. Confirmed
by re-running with it: every module, including SSH, started cleanly.

### Restarting OpenCanary alone

The whole point of the holder (issue #126) extended to a third container:
`docker restart opencanary` on its own leaves the agent's heartbeat and
the SMB lure (if deployed) running and reporting, because neither of them
owns the network namespace this container only joins. The agent notices
OpenCanary going away on its own, though -- see the next section -- which
is different from, and in addition to, the namespace surviving.

### How the agent notices this container is gone

Before this split, OpenCanary dying was this agent's own child process
exiting, and the agent noticed immediately (#69) because it was the
parent. Splitting the two into separate containers removes that signal
entirely -- a `wait4` on a process in a different container is not a
thing -- so the agent now dials this container's own configured ports
once per heartbeat instead (`internal/agent/readiness`, reused from
issue #65's boot-time check) and reports what it finds in the same
self-report queue-depth and log-read-ok already ride in
(`opencanary_up`). One port not answering is enough to call it down
(`internal/store/health.go`'s `StateOpenCanaryDown`); the state clears on
the next heartbeat that finds every port answering again. This is a
plain TCP dial, not the self-test that already exists for a different
purpose (proving from birdcage's own side, over the network, that a
module answers correctly) -- reusing the self-test round trip here would
mean waiting for birdcage to mint a command, deliver it and receive the
answer, a multi-minute path where a local dial answers in the time one
heartbeat takes.

## Configuration

Unchanged from before this split: `opencanary.conf` inside the image is
the same file, and `docs/opencanary.md` is still the record of which
parts of upstream this product relies on and which it routes round.
`MOCKINGBIRD_LOG_PATH` and `MOCKINGBIRD_LISTEN` keep their pre-split
names -- they are this image's side of a wire contract with the agent
(the shared log volume's path, and the loopback address this container's
webhook handler posts to), not a claim that this image belongs to
Mockingbird.
