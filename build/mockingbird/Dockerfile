# The Mockingbird image: OpenCanary plus the mockingbird agent, and
# nothing else (ADR-0008). This is the container built to be attacked,
# so the runtime layer has no shell, no package manager, no compiler and
# no root: distroless python3, everything owned by and running as the
# nonroot user (65532), and the honeypot's low ports reached with a
# per-container sysctl rather than a privileged start. Build from the
# repository root:
#
#     docker build -f build/mockingbird/Dockerfile -t mockingbird .
#
# Run shape (the enrolment command #47 mints carries the real values):
#
#     docker run --init --sysctl net.ipv4.ip_unprivileged_port_start=0 \
#       -v mockingbird-state:/var/lib/mockingbird \
#       -v mockingbird-log:/var/log/opencanary \
#       -e MOCKINGBIRD_BIRDCAGE_URL=https://birdcage.example:8443 mockingbird
#
# --sysctl: OpenCanary listens on 21, 22, 23, 80 and friends. Upstream
# starts as root and has twistd drop to nobody after binding; here
# nothing is ever root, so the namespace's privileged-port floor is
# lowered instead. The sysctl is per network namespace (kernel
# ip-sysctl docs) and Docker allows net.* sysctls per container off
# host networking, which macvlan is. Forget it and every module fails
# to bind, which the self-test (#46) reports rather than hides.
# --init: the agent supervises OpenCanary as its child and forwards
# signals; Docker's init handles orphan reaping, which the agent
# deliberately does not.

# --- honeypot ---------------------------------------------------------------
# Installed into a plain directory, not a venv, so the runtime stage can
# copy it onto Debian's own Python 3.13 and point PYTHONPATH at it.
# requirements.txt is uv-compiled from requirements.in with hashes for
# every wheel and sdist, so a swapped artefact on PyPI fails the build.
FROM python:3.13-slim-trixie AS honeypot
COPY build/mockingbird/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes --target /opt/opencanary -r /tmp/requirements.txt

# --- agent ------------------------------------------------------------------
# The agent's dependency closure is fenced (scripts/agent-deps-check.sh,
# CI job lint:agent-deps): no server package can be linked in here.
FROM golang:1.27.0-alpine AS agent
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/mockingbird ./cmd/mockingbird
# cap_net_raw, and nothing else, for the port-scan detector (#65): the
# agent opens one AF_PACKET socket in the container's own network
# namespace so it can see SYNs aimed at ports no OpenCanary module
# answers on. OpenCanary's own portscan module cannot do this here --
# it reads iptables LOG lines out of /var/log/kern.log, which needs
# iptables-legacy rules and a root process to install them, neither of
# which this image has or should gain.
#
# A *file* capability, not a container-wide one: +ep means the binary
# gets it on exec regardless of the uid running it, so the runtime stays
# uid 65532 with no shell and no root, and the capability is attached to
# the one executable that needs it rather than to everything in the
# container. The operator still passes --cap-add NET_RAW, because a file
# capability can only grant what the container's bounding set already
# permits; without it the socket call returns EPERM, the agent logs one
# WARN and runs on with detection off.
#
# libcap is installed only in this build stage and never reaches the
# runtime image.
RUN apk add --no-cache libcap \
    && setcap cap_net_raw+ep /out/mockingbird \
    && getcap /out/mockingbird
# Directories the runtime user must own, made here because distroless
# has no mkdir: the agent's state (token, certificates, acknowledged log
# position -- #68 says these outlive the container, so both are volume
# mount points and a fresh named volume inherits this ownership), the
# OpenCanary log, and /var/tmp where OpenCanary's SSH module writes its
# host key (the path is hard-coded upstream, ssh.py SSH_PATH).
RUN mkdir -p /var/lib/mockingbird /var/log/opencanary /var/tmp

# --- runtime ----------------------------------------------------------------
FROM gcr.io/distroless/python3-debian13:nonroot
COPY --from=honeypot /opt/opencanary /opt/opencanary
COPY --from=agent /out/mockingbird /mockingbird
COPY --from=agent --chown=65532:65532 /var/lib/mockingbird /var/lib/mockingbird
COPY --from=agent --chown=65532:65532 /var/log/opencanary /var/log/opencanary
COPY --from=agent --chown=65532:65532 /var/tmp /var/tmp
COPY build/mockingbird/opencanary.conf /etc/opencanaryd/opencanary.conf
COPY build/mockingbird/run-twistd.py /opt/opencanary/bin/run-twistd.py
# 65532 (distroless's nonroot), not 1000 as the Birdcage image uses: this
# container is meant to be broken into, and 1000 is the operator's own
# uid on most hosts, so a uid that maps to nobody outside the container
# is the safer one here. Nothing the operator owns is ever mounted in.
USER 65532:65532
ENV PYTHONPATH=/opt/opencanary \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MOCKINGBIRD_STATE_DIR=/var/lib/mockingbird \
    MOCKINGBIRD_LOG_PATH=/var/log/opencanary/opencanary.log \
    MOCKINGBIRD_LISTEN=127.0.0.1:9919
VOLUME ["/var/lib/mockingbird", "/var/log/opencanary"]
# The services opencanary.conf enables by default. There is no EXPOSE for
# the agent's receiver: it is loopback-only by design.
EXPOSE 21/tcp 22/tcp 23/tcp 69/udp 80/tcp 1433/tcp 3306/tcp 3389/tcp 5060/udp 6379/tcp
# The agent is PID 1's child (see --init above) and runs OpenCanary as
# its own child from these arguments: twistd in the foreground, on the
# .tac file pip installed beside it, with no pidfile (see run-twistd.py
# for why twistd is started this way).
ENTRYPOINT ["/mockingbird"]
CMD ["/usr/bin/python3", "/opt/opencanary/bin/run-twistd.py", "-noy", "/opt/opencanary/bin/opencanary.tac", "--pidfile="]
