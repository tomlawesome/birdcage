# The Mockingbird image: the agent alone (issue #132 split OpenCanary out
# into its own image, build/opencanary -- ADR-0008 amendment,
# docs/adr/0013-opencanary-own-container.md). This is still a container
# built to be attacked -- the receiver, the event roads and OpenCanary's
# own webhook all still face the network -- so the runtime layer keeps
# the same shape as before the split: distroless, no shell, no package
# manager, no compiler, everything owned by and running as the nonroot
# user (65532). What changed is what it no longer carries: no Python
# runtime, no OpenCanary code, and critically, no access to
# OpenCanary's own container or its log except through the one volume
# named below. Build from the repository root:
#
#     docker build -f build/mockingbird/Dockerfile -t mockingbird .
#
# Run shape (the enrolment command #47 mints carries the real values; the
# holder and OpenCanary run alongside it -- see
# cmd/birdcage/canary_lure.go's printHolderRunCommand and
# printOpenCanaryRunCommand, and docs/enrolment.md):
#
#     docker run -d --name mockingbird --restart unless-stopped \
#       --network container:holder \
#       --cap-add NET_RAW \
#       --security-opt no-new-privileges \
#       -v mockingbird-state:/var/lib/mockingbird \
#       -v mockingbird-log:/var/log/opencanary:ro \
#       -e MOCKINGBIRD_BIRDCAGE_URL=https://birdcage.example:8443 mockingbird
#
# Since #137 the printed command also carries --security-opt
# no-new-privileges, which keeps NET_RAW only because --init is absent
# (docs/enrolment.md, "no-new-privileges and --init", has why). What
# #132 changed: no more --sysctl and no more --init. The sysctl moved to OpenCanary's
# own line; the agent's own privileged ports (137, 161, 5353, 5355) still
# bind because Docker already sets net.ipv4.ip_unprivileged_port_start=0
# in the holder's namespace, which this container joins. --init went
# because the agent spawns no child process to reap or forward signals
# to any more (OpenCanary is no longer
# this agent's child -- #69, superseded; see cmd/mockingbird/main.go's
# package doc comment for what replaces its liveness signal). The log
# volume is now read-only here: OpenCanary writes it from its own
# container, this one only tails it, and MOCKINGBIRD_LOG_PATH names the
# same file OpenCanary is told to write (build/opencanary/Dockerfile's
# own ENV) -- the same shared-volume, one-writer-one-reader shape the SMB
# lure's audit file already uses.

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
# has no mkdir: the agent's own state (token, certificates, acknowledged
# log position -- #68 says these outlive the container, so this is a
# volume mount point and a fresh named volume inherits this ownership),
# and a matching /var/log/opencanary mount point -- empty here, and
# mounted read-only at runtime, but still created with the same
# ownership as build/opencanary/Dockerfile's own copy of the same path,
# so the shared named volume initialises identically whichever of the
# two containers happens to mount it first.
RUN mkdir -p /var/lib/mockingbird /var/log/opencanary

# --- runtime ----------------------------------------------------------------
FROM gcr.io/distroless/python3-debian13:nonroot
COPY --from=agent /out/mockingbird /mockingbird
COPY --from=agent --chown=65532:65532 /var/lib/mockingbird /var/lib/mockingbird
COPY --from=agent --chown=65532:65532 /var/log/opencanary /var/log/opencanary
# This agent's own copy of OpenCanary's configuration -- the same file,
# from the same source, that build/opencanary/Dockerfile bakes into
# OpenCanary's own image. Not shared over a volume: it is a static,
# non-secret build artifact both images need to read locally, not
# runtime state -- the port-scan road (#65), the snmp road's node id
# (#88), the poisoner road's bait naming (#86) and this agent's own
# OpenCanary liveness probe (#132, readiness.go) all read it to learn
# which services and ports are configured. It governs nothing here: only
# OpenCanary's own copy decides what it actually emulates, and the two
# must be kept identical by hand -- one file in the repository, copied
# into two images, exactly like build/opencanary/entrypoint.py's own
# "unchanged" pins carry the honeypot's pip dependencies into one image
# rather than the other now owning them both.
COPY build/opencanary/opencanary.conf /etc/opencanaryd/opencanary.conf
# 65532 (distroless's nonroot), not 1000 as the birdcage image uses: this
# container is meant to be broken into, and 1000 is the operator's own
# uid on most hosts, so a uid that maps to nobody outside the container
# is the safer one here. Nothing the operator owns is ever mounted in.
USER 65532:65532
ENV MOCKINGBIRD_STATE_DIR=/var/lib/mockingbird \
    MOCKINGBIRD_LOG_PATH=/var/log/opencanary/opencanary.log \
    MOCKINGBIRD_LISTEN=127.0.0.1:9919
VOLUME ["/var/lib/mockingbird", "/var/log/opencanary"]
# 161, 137, 5353 and 5355/udp are this agent's own roads, not an
# OpenCanary module: 161/udp is the plain Go UDP listener behind the
# SNMP road (#88; opencanary.conf keeps "snmp.enabled": false -- see
# internal/agent/snmp's package doc for why), and 137/5353/5355 are the
# poisoner road's own receive-only sockets (#86), counting the segment's
# own name lookups. Those three are shut for writing the moment they
# open, so the kernel refuses any send from them: the canary cannot
# answer another machine's lookup even if something in this image tried
# to. OpenCanary's own service ports (21, 22, 23, 80 and the rest) moved
# to build/opencanary/Dockerfile's own EXPOSE with it. There is no EXPOSE
# for the agent's receiver: it is loopback-only by design.
EXPOSE 137/udp 161/udp 5353/udp 5355/udp
ENTRYPOINT ["/mockingbird"]
