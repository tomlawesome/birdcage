# ADR-0013: OpenCanary is its own image and container, not the agent's child

**Status:** Accepted
**Date:** 2026-09-26
**Relates to:** #132, #69 (superseded -- OpenCanary as the agent's child
process), #126 (the address holder), #87 (the SMB lure, the same design
this extends to a second attack surface).
**Amends:** ADR-0008 decision 2 -- the clause naming Mockingbird as "the
agent container -- OpenCanary plus the Mockingbird agent, and nothing
else." The rest of ADR-0008 stands, including decision 4's dependency
fence and decision 2's own boundary between the agent and the server.

## Context

ADR-0008 drew Mockingbird's boundary around the server: OpenCanary and
the agent could share a container because neither of them was the
server, and the server was the thing that had to stay out. That left
OpenCanary sharing a filesystem with the agent's own state --
`/var/lib/mockingbird`, the bearer token and the mTLS client key -- for
as long as both ran as one process tree in one container. Issue #69 made
the agent OpenCanary's supervisor: start it, forward signals to it, and
take the whole container down if it dies, so a dead honeypot could never
sit next to a heartbeat still claiming to be healthy.

Issue #126 built the address holder for a related but distinct problem
-- restarting the canary or the SMB lure must not take the other one's
listening socket down -- and in doing so put three containers on one
network address, none of them owning it directly. That design already
proved a container can share an address with another and still be
independently restartable, and it already drew one line between "faces
the network" (the lure) and "does the isolating" (the agent, reading a
volume the lure only writes).

Issue #132 asks the same question ADR-0008 asked about the server,
about OpenCanary: does the honeypot itself need to share a filesystem
with the credentials that let the agent talk to birdcage? OpenCanary is
the emulated-service code accepting connections from whoever finds the
canary -- exactly the surface a Twisted protocol handler bug, or a CVE
in one of its Python dependencies, would land in. Before this change, a
compromise there was one `open()` away from the agent's own bearer
token and client key.

## Decision

**1. OpenCanary is its own image (`build/opencanary`) and its own
container, with no access whatsoever to `/var/lib/mockingbird` in
either direction.** No configuration option adds it, and none should:
this is the boundary the split exists to draw. The Mockingbird image
(`build/mockingbird`) keeps the agent alone -- no Python runtime, no
OpenCanary code.

**2. The owner's rule, stated for the record in the words it was
given: direct attack surfaces are sensibly segregated into
containers.** OpenCanary joining a Twisted reactor to the agent's own
process was never required by anything OpenCanary or the agent
actually need from each other; it was inherited from a time before the
agent existed to supervise anything. The SMB lure already lived by this
rule (ADR-0008's own precedent, "the canary is an attack surface"); this
extends it to the second attack surface the product ships.

**3. The limit this rule runs into: containers sharing an address are
isolated by files and processes, not by network.** OpenCanary,
Mockingbird and the SMB lure (when deployed) all join one network
namespace through the address holder (#126), because the product's own
design puts one honeypot's services on one address. A network boundary
between them was never on the table -- macvlan gives one address to one
segment-facing identity, and splitting that identity across several
addresses would be a different, larger redesign #132 does not ask for.
What separates them instead is the ordinary Unix kind of isolation: a
volume mounted read-only on one side and read-write on the other (the
log, here; the SMB audit file, already), and no volume at all where
there is nothing to share (`/var/lib/mockingbird`). Two containers on
one address can still keep secrets from each other; they do it with
mount lists, not firewalls.

**4. OpenCanary's log reaches the agent over a shared volume, the same
pattern as the SMB lure's audit file.** `mockingbird-log` is mounted
read-write in OpenCanary's container and read-only in the agent's;
OpenCanary is the only writer, the agent's tailer the only reader. The
loopback webhook OpenCanary's own logger config also posts to
(`http://127.0.0.1:9919/event`) keeps working unmodified, because
127.0.0.1 is the shared network namespace's own loopback, not either
container's: it reaches the agent's receiver in the other container the
same way it reached it in-process before this split, as long as the
agent's container is already listening when OpenCanary starts (see
consequence 3).

**5. The agent stops supervising OpenCanary (#69, superseded) and
instead dials its ports once per heartbeat.** There is no `wait4` across
a container boundary, so the agent can no longer notice OpenCanary die
by watching a child process exit. Two ways to replace that signal were
available: a plain TCP dial against OpenCanary's own configured ports,
reused from issue #65's existing boot-time readiness check
(`internal/agent/readiness`) and simply run every heartbeat tick instead
of once; or routing the question through the self-test round trip that
already proves a canary answers, from birdcage's own side, over the
network. The self-test exists to prove something different -- that
birdcage can reach a module through the real network path an attacker
would use -- and answering it means minting a command, delivering it on
the next command poll, and waiting for the result, a path measured in
minutes (`internal/selftestsched`'s own `selfTestWindow`, 10 minutes).
A local dial answers in the time one heartbeat takes, and the readiness
package already existed to do exactly this dial. The port probe is the
simpler fit, so that is what is built: `internal/agent/readiness`'s dial
runs once per heartbeat, and the result rides the heartbeat's own
self-report (`opencanary_up`) into a new ranked state,
`internal/store/health.go`'s `StateOpenCanaryDown`, next to
`not_delivering`.

## Consequences

- Two images build where one did (`build/opencanary`,
  `build/mockingbird`), each smaller than the combined image was: the
  Python runtime and OpenCanary's dependency closure no longer reach
  the agent image, and the agent's Go binary and its state volume no
  longer reach the OpenCanary image.
- OpenCanary's own pip packages (`requirements.in`/`requirements.txt`)
  move unchanged -- same pins, same hashes, same licence gate
  (`scripts/licence-check-python.sh`, now pointed at
  `build/opencanary/requirements.txt`).
- The address holder (#126) becomes mandatory for every honeypot canary
  rather than optional on the SMB lure alone: OpenCanary always needs
  something else's namespace to join, so there is always something for
  the holder to protect. `printHolderRunCommand` still omits the audit
  volume when no lure is deployed -- the holder's own reason to exist
  does not imply the lure's.
- The two containers' start order matters in a way it did not when one
  process controlled both: OpenCanary's webhook handler treats a
  refused connection to the agent's receiver as fatal to loading the
  whole Twisted application, not as one dropped event, so it must start
  after the agent (`docs/enrolment.md`, `build/opencanary/README.md`
  has the reproduction). `birdcage agent enrol` prints the agent's
  command before OpenCanary's for this reason; a restart policy retries
  a container started out of order until the other one catches up.
- `--sysctl net.ipv4.ip_unprivileged_port_start=0` moves from the
  combined container to OpenCanary's own -- it is OpenCanary that binds
  ports under 1024, not the agent, and the sysctl can only be set once
  per network namespace.
- OpenCanary's container is hardened the same way the SMB lure's is
  (`--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`,
  `--pids-limit`, `--memory`), with evidence for what it needs recorded
  in `build/opencanary/README.md`: nothing, tested by dropping every
  capability and adding none back.
- `StateOpenCanaryDown`'s exact rank among the other health states, and
  its frontend presentation, are this change's own implementation
  choice, not a ratified design -- flagged as contested per
  `docs/security-by-design.md`, the same footing several existing
  states in `internal/store/health.go` were added on before their own
  later ratification.
