# A CI-only stand-in for the administrator's mail provider, for issue
# #80's DKIM leg: a real DNS server (unbound) that publishes one DKIM key
# for e2e.invalid and nothing else, and cmd/e2e-dkim-sign, which made
# that key at run time and signs the approval replies with it. birdcage
# is started with this container as its DNS server (Docker's --dns) so
# approval.Verify's net.LookupTXT asks a real server for the key rather
# than a function in a test. It never ships and is never anywhere near
# build/birdcage or build/mockingbird. scripts/e2e/mail-stack.sh builds
# and runs it, on demand, for scripts/e2e/mail.sh.
#
#     docker build -f build/e2e-dns/Dockerfile -t e2e-dns .
#
# ---------------------------------------------------------------------
# Versions, and how they were chosen
#
# alpine:3.24 is the base build/e2e-mail already uses. unbound is pinned
# to the exact version in that release's `main` repository on 2026-09-25
# (read with `apk policy`), BSD-3-Clause: owner, 2026-09-25, on #80 --
# "the test DNS server is unbound (Alpine main, BSD-3-Clause)". No other
# apk package is added.
#
# 1.25.2-r2 is deliberately behind upstream's 1.26.1. Alpine backports
# two of 1.26.1's nine fixes into -r2 (CVE-2026-82717, CVE-2026-81642);
# the other seven are open in this version and unreachable here because
# of how unbound.conf runs it -- the advisory recheck is on #80:
#
#   CVE-2026-81634  DNSSEC canonicalisation  validator module off
#                                            (module-config: "iterator")
#   CVE-2026-77955  ZONEMD verification      no auth-zone
#   CVE-2026-78227  DNS-over-QUIC            no QUIC listener
#   CVE-2026-82720  DNS-over-HTTPS           no HTTPS listener
#   CVE-2026-80225  TCP/DoT degradation      no DoT listener; the TCP
#                                            side is a slowdown only,
#                                            from inside the job's own
#                                            network
#   CVE-2026-85501  recursion complexity     no recursion: local data
#                                            only, everything else refused
#   CVE-2026-77860  serve-expired            serve-expired off
#
# Upgrade trigger: `apk policy unbound` on alpine:3.24 shows 1.26.1 or
# later. The pin fails this build loudly once 1.25.2-r2 leaves the
# repository, which forces that bump -- a deliberate, visible change.
#
# The signer is built from this repository's own source with the Go
# toolchain image and only github.com/emersion/go-msgauth (approved, #54)
# beyond the standard library; it is copied in as one static binary.
#
# BASE_IMAGE and GO_IMAGE default to the plain Docker Hub tags for a
# workstation build; scripts/e2e/mail-stack.sh passes CI's
# dependency-proxy pins (refs #128, .gitlab-ci.yml's ALPINE_IMAGE and
# GOLANG_IMAGE) as build args.
ARG BASE_IMAGE=alpine:3.24
ARG GO_IMAGE=golang:1.27
FROM ${GO_IMAGE} AS signer
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd/e2e-dkim-sign/ ./cmd/e2e-dkim-sign/
RUN CGO_ENABLED=0 go build -trimpath -o /out/e2e-dkim-sign ./cmd/e2e-dkim-sign

FROM ${BASE_IMAGE}

RUN apk add --no-cache unbound=1.25.2-r2

COPY build/e2e-dns/unbound.conf /etc/unbound/unbound.conf
COPY build/e2e-dns/entrypoint.sh /entrypoint.sh
COPY --from=signer /out/e2e-dkim-sign /usr/local/bin/e2e-dkim-sign
RUN chmod 755 /entrypoint.sh

# 53/udp and 53/tcp on the container's own address, nothing else.
# Starts as root to bind port 53; unbound then drops to its own user.
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/entrypoint.sh"]
