# The address holder (issue #126): a do-nothing container whose only job
# is to own a network address and the SMB lure's audit volume, so
# restarting the canary (Mockingbird) or the SMB lure never destroys a
# namespace or a volume mount the other one needs. cmd/holder's whole
# program is "block until SIGTERM or SIGINT, then exit 0" -- see that
# package's doc comment for the problem this replaces. Build from the
# repository root so the Go module is in context:
#
#     docker build -f build/holder/Dockerfile -t holder .
#
# Run shape (the enrol renderer, cmd/birdcage/canary_lure.go's
# printHolderRunCommand, prints the real image name):
#
#     docker run -d --name holder --restart unless-stopped \
#       --read-only --cap-drop ALL --security-opt no-new-privileges \
#       --pids-limit 16 --memory 32m \
#       -v smb-audit:/audit:ro holder:latest
#
# No --sysctl, no --cap-add, no published port, no --init: this container
# never binds a socket, never forks and is never PID 1 for anything but
# itself, so none of the flags the canary or the lure need apply here.

FROM golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/holder ./cmd/holder

# --- runtime ------------------------------------------------------------
# scratch, not distroless: this binary imports nothing but the standard
# library and opens no network connection of its own (unlike Mockingbird
# and Nightjar, which need distroless's CA bundle to reach birdcage over
# TLS). Nothing here to update, patch or scan beyond the one binary.
FROM scratch
COPY --from=build /out/holder /holder
# 65532, matching Mockingbird's and Nightjar's own choice of a uid that
# maps to nobody outside the container. scratch has no /etc/passwd, but
# Docker's USER accepts a bare numeric uid:gid without one.
USER 65532:65532
# No EXPOSE: this container listens on nothing. No VOLUME either -- the
# run command's own -v flag is what makes the smb-audit mount permanent;
# declaring it here would only invite an anonymous volume if that flag
# were ever dropped by mistake.
ENTRYPOINT ["/holder"]
