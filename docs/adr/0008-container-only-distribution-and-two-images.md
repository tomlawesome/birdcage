# ADR-0008: Birdcage ships only as container images, and the canary is its own image

**Status:** Accepted
**Date:** 2026-09-18
**Relates to:** #48 (the agent as a deliverable), #47 (enrolment),
#54 (upgrades), #62 (key material), #61 (credential hygiene), ADR-0001,
ADR-0005.
**Amends:** ADR-0003, decision 1 -- the clause deploying birdcage "in
the same compose stack as mikroview", and the "sidecar" framing of its
title. The rest of ADR-0003 stands.

## Context

Earlier design work assumed the canary was a host machine that
birdcage installed software onto: a systemd unit, a system user, log
rotation, a deploy script that fetched a binary and checked its hash.
#47 and #48 were both designed against that assumption.

The owner settled the deployment shape on 2026-09-18, and it
invalidates those assumptions. ADR-0001 already had the birdcage
server building into a distroless image, but the delivery model for
the whole product was never written down. This ADR states it.

## Decision

1. **Birdcage is distributed only as container images we build and
   publish, pulled to a host.** No `.deb`, no OS packaging, no apt
   repository, now or later. The owner: "Birdcage will never be
   released as a Debian package. It will be our own container, pulled
   to a host."
2. **Two images, not one.** **Birdcage** is the main container --
   dashboard, store, ingest listener, CA and key material. It stands
   on its own and is not a sidecar to anything. **Mockingbird** is the
   agent container -- OpenCanary plus the Mockingbird agent, and
   nothing else. The owner: "The canary is an attack surface. It
   should be an isolated build with no birdcage code within it." The
   precise boundary: the Mockingbird container does run Mockingbird,
   which is birdcage code. What is excluded is the *server* --
   dashboard, database, ingest listener, CA and key handling.
3. **The deployment unit is one Mockingbird container per network
   segment**, on a VM already present in that segment, attached by
   macvlan. Not one per VM: real machines carry legitimate traffic and
   the signal dies in the noise.
4. **The image boundary is enforced in code, not by habit.**
   `go list -deps ./cmd/birdcage-agent | grep tomlawesome` must return
   only `internal/agent/*`, `internal/opencanary`,
   `internal/selftest` and the command itself. Verified 2026-09-18 at
   `456d3d5`. This check should become a CI gate.

## Consequences

- The two images version and upgrade independently. #54's approval
  mechanism should be rebuilt around registry content digests instead
  of hashes of loose binaries: an image already carries an immutable
  digest, and the house rules already promote a tested digest rather
  than rebuild.
- Most of #47's deploy script disappears: no system user, no systemd
  unit, no package install, no host log rotation. "Paste one command"
  becomes a container run command carrying the enrolment credentials,
  and the pipe-to-shell CVE and prior-art burden largely stops
  applying.
- #61 credential hygiene gets substantially easier -- no host shell
  history, process table or journal to keep clean.
- #62 (only the CA key touches disk) becomes a statement about the
  server image alone.
- The Mockingbird image carries OpenCanary's Python runtime; the
  birdcage image does not and should not gain it.
- The two images are not built from wholly disjoint source.
  `internal/selftest` compiles into both binaries -- it is the shared
  wire contract (`Params{RunID, Address, Targets[]}`), a small
  data-only package describing the shape of a self-test request. That
  is not the server riding along inside the canary, but the isolation
  is not total, and a change to that contract touches both images.
- **ADR-0003 is amended, not overturned.** Its decision that birdcage
  stays its own repository, binary, container, database and port, and
  that neither app is required for the other to run, is precisely the
  separation this ADR builds on -- and folding birdcage into mikroview
  was already considered and rejected there. What does not survive is
  the single clause deploying birdcage "in the same compose stack as
  mikroview", and the word "sidecar" in its title. Mikroview stays its
  own project, with its own deployment. The two are expected to share
  a Go authentication module (`gauntlet`, ADR-0005), but each runs it
  in its own process; sharing a library is not sharing a deployment.
- **Closer ties to mikroview remain a direction, not a requirement.**
  Birdcage is expected to eventually call mikroview to use its
  capabilities, so it is worth keeping integration in view when
  shaping interfaces. Nothing in v1 depends on it, and birdcage must
  run fully without mikroview present.
- ADR-0003's title and status need correcting, and the compose-stack
  and sidecar wording also appears in `docs/architecture.md`,
  `README.md`, `SECURITY.md`, `docs/v1-scope.md`,
  `docs/security-by-design.md` and ADR-0001. Correcting those is
  follow-up work, not part of this ADR.
