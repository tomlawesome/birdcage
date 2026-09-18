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
FROM golang:1.27.0-alpine AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# web/embed.go's `//go:embed all:dist` picks the built UI up from here;
# the checkout carries only a .gitkeep placeholder.
COPY --from=frontend /src/frontend/dist ./web/dist
# modernc.org/sqlite is pure Go, so CGO can stay off and the binary is
# genuinely static -- which is what lets the runtime stage be distroless
# static rather than base.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/birdcage ./cmd/birdcage
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
# 8080/tcp is the dashboard and its API (BIRDCAGE_HTTP_ADDR). 8443/tcp
# is the HTTPS ingest listener canaries report to (BIRDCAGE_INGEST_ADDR);
# it only starts once its TLS material is configured -- see
# cmd/birdcage/main.go -- so a bare `docker run` serves the dashboard
# alone until enrolment (#47) lands.
EXPOSE 8080/tcp 8443/tcp
ENTRYPOINT ["/birdcage"]
