# The Nightjar image: the scanner agent (ADR-0010, issue #108). Its own
# image, its own binary, never inside Mockingbird (ADR-0010 decision 3:
# "a honeypot is deliberately attackable; a scanner needs the Docker
# socket and the host's package database" -- putting privileged host
# read access inside the container attackers are invited into would hand
# them the box the decoy was meant to protect). Build from the
# repository root so the Go module is in context:
#
#     docker build -f build/nightjar/Dockerfile -t nightjar .
#
# Run shape (the enrol renderer, cmd/birdcage/canary.go's
# printScannerEnrolRunCommand, prints the real values and the full mask
# flag list from internal/hostmask):
#
#     docker run -d --name nightjar --restart unless-stopped \
#       --read-only --cap-drop ALL --security-opt no-new-privileges \
#       -v /:/host:ro <mask flags> \
#       -v nightjar-state:/var/lib/nightjar -v nightjar-grype-db:/var/lib/nightjar-grype-db \
#       -e NIGHTJAR_BIRDCAGE_URL=https://birdcage.example:8443 nightjar
#
# No --sysctl, no --cap-add, no published port: Nightjar listens on
# nothing (ADR-0010 decision 3), so unlike Mockingbird it needs no
# privileged-port floor and no capability at all.

# --- grype ------------------------------------------------------------------
# Pinned by version AND SHA-256 (#108, section 5) -- never a floating
# tag, never trusted on TLS alone. The checksum was verified against the
# release's own grype_<version>_checksums.txt and against a fresh
# download of the artifact itself before this file was written; both
# matched (see the commit that introduced this file for the record).
# grype's vulnerability database is never fetched here and never baked
# into this image -- it is a runtime feed (ADR-0010 decision 2), fetched
# by grype itself into GRYPE_DB_CACHE_DIR below, on the operator's own
# device.
FROM alpine:3.24 AS grype
ARG GRYPE_VERSION=0.119.0
ARG GRYPE_SHA256=3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b
WORKDIR /grype
RUN apk add --no-cache curl \
    && curl -fsSL -o grype.tar.gz \
       "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" \
    && echo "${GRYPE_SHA256}  grype.tar.gz" | sha256sum -c - \
    && tar xzf grype.tar.gz grype \
    && chmod 0755 grype

# --- agent --------------------------------------------------------------
# The agent's dependency closure is fenced (scripts/agent-deps-check.sh,
# CI job lint:agent-deps, run once per agent kind since #108): no server
# package, and no other kind's own package (internal/opencanary), can be
# linked in here.
FROM golang:1.27.0-alpine AS agent
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/nightjar ./cmd/nightjar
# Directories the runtime user must own, made here because distroless
# has no mkdir: the agent's own state (token, certificates -- outlives
# the container, so it is a volume mount point and a fresh named volume
# inherits this ownership, the same reasoning build/mockingbird's
# Dockerfile records) and the Grype vulnerability database cache, a
# second, separate volume so the two lifecycles (credentials; a
# multi-hundred-MB database refreshed on every run) never collide.
RUN mkdir -p /var/lib/nightjar /var/lib/nightjar-grype-db

# --- runtime ------------------------------------------------------------
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=grype /grype/grype /usr/local/bin/grype
COPY --from=agent /out/nightjar /nightjar
COPY --from=agent --chown=65532:65532 /var/lib/nightjar /var/lib/nightjar
COPY --from=agent --chown=65532:65532 /var/lib/nightjar-grype-db /var/lib/nightjar-grype-db
# 65532 (distroless's nonroot), matching Mockingbird's own choice and
# for a sharper reason here: this container reads the whole host
# filesystem, so its uid must not collide with the operator's own uid on
# the host (typically 1000) or every world-writable assumption a
# masked-path decision relies on changes.
USER 65532:65532
ENV NIGHTJAR_STATE_DIR=/var/lib/nightjar \
    GRYPE_DB_CACHE_DIR=/var/lib/nightjar-grype-db \
    GRYPE_CHECK_FOR_APP_UPDATE=false \
    TMPDIR=/var/lib/nightjar-grype-db
# GRYPE_CHECK_FOR_APP_UPDATE=false suppresses only Grype's own
# *application* version check (a phone-home Nightjar has no use for and
# does not want on a privileged host agent); the vulnerability *database*
# update stays on Grype's own default (db.auto-update: true) -- #108's
# owner-accepted condition on the cache volume, "as long as it gets
# updated."
#
# TMPDIR is load-bearing, not cosmetic, and was found by running this
# exact image with the run command's own --read-only flag rather than
# assumed: Grype writes a scratch "listing" file to the OS temp
# directory (Go's os.CreateTemp("", ...) default, $TMPDIR or /tmp) every
# time it checks for a database update, which is every run past the
# first two hours (db.max-update-check-frequency). Under --read-only
# with no writable /tmp, that write fails -- with an empty cache this is
# fatal ("database does not exist": there was never a database to fall
# back on), and even with a warm cache it silently stops refreshing,
# which is exactly the "cache that quietly stopped updating" #108's own
# owner-decision comment says must show up as failed scans, not a clean
# host. Pointing TMPDIR at the already-writable, already-required DB
# cache volume fixes this without adding a new writable tmpfs (a
# read-write scratch area a compromised scanner could use) and without
# lengthening the printed run command -- verified against this image
# with a cold cache under the run command's exact flags before this
# comment was written, not assumed to work.
VOLUME ["/var/lib/nightjar", "/var/lib/nightjar-grype-db"]
# No EXPOSE: Nightjar binds no port (ADR-0010 decision 3). No shell, no
# package manager -- distroless static, same runtime family as
# build/birdcage/Dockerfile.
ENTRYPOINT ["/nightjar"]
