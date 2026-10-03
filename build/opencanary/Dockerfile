# The OpenCanary image (issue #132, splitting it out of build/mockingbird
# -- ADR-0008 amendment, docs/adr/0013-opencanary-own-container.md): the
# emulated services alone, with no access whatsoever to the agent's own
# state (/var/lib/mockingbird -- the mTLS client key and the bearer
# token). This is the container built to be attacked, so the runtime
# layer has no shell, no package manager, no compiler and no root:
# distroless python3, everything owned by and running as the nonroot user
# (65532), and the honeypot's low ports reached with a per-container
# sysctl rather than a privileged start. Build from the repository root:
#
#     docker build -f build/opencanary/Dockerfile -t opencanary .
#
# Run shape (the enrol renderer, cmd/birdcage/canary_lure.go's
# printOpenCanaryRunCommand, prints the real image name and values):
#
#     docker run -d --name opencanary --restart unless-stopped --init \
#       --network container:holder \
#       --sysctl net.ipv4.ip_unprivileged_port_start=0 \
#       --read-only --cap-drop ALL --security-opt no-new-privileges \
#       --pids-limit 32 --memory 128m \
#       -v mockingbird-log:/var/log/opencanary \
#       opencanary:latest
#
# --init: this container's PID 1 is now twistd itself (before this split
# it was the agent, supervising twistd as its own child) -- Docker's init
# handles orphan reaping and default signal disposition for a raw PID 1,
# which OpenCanary itself does not.
#
# --network container:holder: this container and the agent (mockingbird)
# both join the address holder's namespace (issue #126) rather than
# owning one directly, so restarting either one alone never takes the
# other's listening sockets down (docs/enrolment.md). Its log reaches the
# agent over the mockingbird-log volume, mounted read-write here and
# read-only on the agent's side -- the same shared-volume pattern the SMB
# lure's audit file uses, and the loopback webhook below still works
# across the two containers because they share one network namespace.
# --sysctl: OpenCanary listens on 21, 22, 23, 80 and friends. Upstream
# starts as root and has twistd drop to nobody after binding; here
# nothing is ever root, so the namespace's privileged-port floor is
# lowered instead -- see build/mockingbird/Dockerfile's own historical
# comment (before this split, the same sysctl sat on the combined
# container for the same reason). The sysctl can only be set once per
# network namespace, so it goes on whichever of the two containers a
# deployment starts -- the enrol renderer puts it here, on this image's
# own run command, since this is the one that needs it; the agent's own
# command carries none.
# --cap-drop ALL, no --cap-add: unlike the SMB lure, nothing here needs a
# capability. Binding low ports is the sysctl's job, not
# CAP_NET_BIND_SERVICE's, and nothing else this image does (accepting
# connections, writing its own log and SSH host key) needs any
# capability at all. build/opencanary/README.md has the evidence.
# No -v mockingbird-state: this image never mounts the agent's state
# volume, in either direction -- the whole point of the split (ADR-0008
# amendment decision: "direct attack surfaces are sensibly segregated
# into containers"). An e2e step proves it cannot read the credentials
# even if pointed at the volume by hand.

# --- honeypot -----------------------------------------------------------
# Installed into a plain directory, not a venv, so the runtime stage can
# copy it onto Debian's own Python 3.13 and point PYTHONPATH at it.
# requirements.txt is uv-compiled from requirements.in with hashes for
# every wheel and sdist, so a swapped artefact on PyPI fails the build --
# unchanged from before this split (same file, same pins, same licence
# gate: scripts/licence-check-python.sh).
FROM python:3.13-slim-trixie AS honeypot
COPY build/opencanary/requirements.txt /tmp/requirements.txt
# --no-deps: the lock is the full resolved closure (uv pip compile above),
# so nothing is missing. Needed because ntlmlib still declares ordereddict
# in install_requires even though it's a Python-2-only fallback the image's
# Python 3.13 never takes; without --no-deps, --require-hashes would make
# pip resolve that declared dependency and fail on its absence from the
# lock (#101).
RUN pip install --no-cache-dir --require-hashes --no-deps --target /opt/opencanary -r /tmp/requirements.txt
# Directories the runtime user must own, made here because distroless has
# no mkdir: this image's own log (mounted from the mockingbird-log
# volume the agent also mounts, read-only, on its side) and /var/tmp,
# where OpenCanary's SSH module writes its host key (the path is
# hard-coded upstream, ssh.py SSH_PATH). No /var/lib/mockingbird here at
# all -- that volume, and everything in it, belongs to the agent alone.
RUN mkdir -p /var/log/opencanary /var/tmp

# The release stamp, for `docker run <image> version` (#125, and #132's
# own "answer version like the others" -- #54's version-tracking column
# is not built yet, so this is the whole of what tracking exists). Built
# here, in a stage with a shell, and read by entrypoint.py in the
# runtime stage, which has none. Owned by root, readable by everybody,
# writable by nobody -- matching build/smb-lure/Dockerfile's own
# convention for the same file exactly.
ARG VERSION=dev
RUN printf '%s\n' "$VERSION" > /etc/image-version && chmod 444 /etc/image-version

# --- runtime --------------------------------------------------------------
FROM gcr.io/distroless/python3-debian13:nonroot
COPY --from=honeypot /opt/opencanary /opt/opencanary
COPY --from=honeypot --chown=65532:65532 /var/log/opencanary /var/log/opencanary
COPY --from=honeypot --chown=65532:65532 /var/tmp /var/tmp
COPY --from=honeypot /etc/image-version /etc/image-version
COPY build/opencanary/opencanary.conf /etc/opencanaryd/opencanary.conf
COPY build/opencanary/entrypoint.py /opt/opencanary/bin/entrypoint.py
# 65532 (distroless's nonroot), not 1000 as the birdcage image uses: this
# container is meant to be broken into, and 1000 is the operator's own
# uid on most hosts, so a uid that maps to nobody outside the container
# is the safer one here -- matching mockingbird's own choice before this
# split. Nothing the operator owns is ever mounted in.
USER 65532:65532
# MOCKINGBIRD_LOG_PATH and MOCKINGBIRD_LISTEN keep their pre-split names
# on purpose: opencanary.conf expands them by name (see that file's own
# comment), and it is copied here unchanged -- issue #132's own
# instruction that OpenCanary moves "unchanged". They are this image's
# side of a wire contract with the agent (the log path both containers
# share, and the loopback address OpenCanary's webhook posts to, which
# still reaches the agent's receiver once both containers join the same
# holder network namespace), not a claim that this image belongs to
# mockingbird.
ENV PYTHONPATH=/opt/opencanary \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MOCKINGBIRD_LOG_PATH=/var/log/opencanary/opencanary.log \
    MOCKINGBIRD_LISTEN=127.0.0.1:9919
VOLUME ["/var/log/opencanary"]
# The services opencanary.conf enables by default. Unlike before this
# split, nothing here belongs to the agent's own roads: 137, 161, 5353
# and 5355/udp (the snmp and poisoner roads, #88/#86) are Go code
# listening in the agent's own container, not an OpenCanary module, and
# stay documented on build/mockingbird/Dockerfile instead.
EXPOSE 21/tcp 22/tcp 23/tcp 69/udp 80/tcp 1433/tcp 3306/tcp 3389/tcp 5060/udp 6379/tcp
ENTRYPOINT ["/usr/bin/python3", "/opt/opencanary/bin/entrypoint.py"]
CMD ["-noy", "/opt/opencanary/bin/opencanary.tac", "--pidfile="]
