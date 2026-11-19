# The Birdcage image: the server -- dashboard, store, ingest listener, CA
# and key material. Never the canary; that is build/mockingbird, a
# separate image with no server code in it (ADR-0008). Build from the
# repository root so both the frontend and the Go module are in context:
#
#     docker build -f build/birdcage/Dockerfile -t birdcage .
#
# Same shape as mikroview's Dockerfile, deliberately: one static Go
# binary with the frontend embedded, on distroless, as uid 1000.

# --- frontend build -------------------------------------------------------
FROM node:26-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# --- backend build ----------------------------------------------------------
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS backend
WORKDIR /src
# github.com/tomlawesome/gauntlet (sign-in, #8) is fetched from its Git
# host, never through proxy.golang.org or sum.golang.org: the first
# lookup there records a version for good, which is publishing it
# (ADR-0016 decision 1). GOPRIVATE turns both off for the owner's
# modules; go.sum still pins the exact content. Fetching direct needs
# git, which this Alpine image lacks, so it is added here -- this stage
# only (owner, 2026-10-10, on #8, answer 3a). It never reaches the
# shipped image: the runtime stage copies only /out/birdcage and
# /var/lib/birdcage from here. Pinned to the 2.54 series, not one
# revision: Alpine keeps only the current revision of a package in a
# release branch, so an exact pin broke this build on Alpine's schedule
# (#210; owner 33, 2026-11-16). go.sum still pins what git fetches.
# Upgrade trigger: the base image moves to an Alpine release whose git
# is not 2.54 (`apk policy git`); the build then fails here, and the
# bump is deliberate. scripts/go-fetch-guard.py (lint:ci)
# refuses a Go build stage without GOPRIVATE, and git anywhere else.
ENV GOPRIVATE=github.com/tomlawesome/*
RUN apk add --no-cache git~=2.54
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# web/embed.go's `//go:embed all:dist` picks the built UI up from here;
# the checkout carries only a .gitkeep placeholder.
COPY --from=frontend /src/frontend/dist ./web/dist
# modernc.org/sqlite is pure Go, so CGO can stay off and the binary is
# genuinely static -- which is what lets the runtime stage be distroless
# static rather than base.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/birdcage ./cmd/birdcage
# The SQLite file defaults under here (BIRDCAGE_DB_PATH below). Created
# in this stage because distroless has no shell to mkdir with, and
# copied in owned by the runtime user: Docker seeds a fresh named volume
# from what the image has at that path, ownership included, so a
# directory the image never created arrives root-owned and uid 1000
# cannot write to it (mikroview #537 learned this the hard way).
RUN mkdir -p /var/lib/birdcage

# --- runtime ------------------------------------------------------------
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=backend /out/birdcage /birdcage
COPY --from=backend --chown=1000:1000 /var/lib/birdcage /var/lib/birdcage
# uid 1000 rather than distroless's own nonroot (65532), for the reason
# mikroview's Dockerfile gives: 1000 is almost always the operator on an
# ordinary Linux host, so a file they mount in is readable without a
# chown. Still unprivileged: ports below 1024 stay unbindable, which is
# why the listeners are on 8080 and 8443.
USER 1000:1000
ENV BIRDCAGE_DB_PATH=/var/lib/birdcage/birdcage.db
# 8080/tcp is the dashboard and its API (BIRDCAGE_HTTP_ADDR). Issue #63:
# it never serves plain HTTP off loopback. A bare `docker run` with no
# other configuration serves HTTPS on a certificate birdcage mints from
# its own CA; bind-mount a certificate and set BIRDCAGE_HTTP_TLS_CERT/
# BIRDCAGE_HTTP_TLS_KEY to use your own instead. Plain HTTP needs
# BIRDCAGE_HTTP_ADDR itself set to a loopback host or a unix socket --
# see docs/configuration.md's "Dashboard TLS" section for all four
# modes. 8443/tcp is the HTTPS ingest listener
# canaries report to (BIRDCAGE_INGEST_ADDR); it only starts once its TLS
# material is configured -- see cmd/birdcage/main.go.
EXPOSE 8080/tcp 8443/tcp
ENTRYPOINT ["/birdcage"]
