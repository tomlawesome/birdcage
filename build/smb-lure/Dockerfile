# The SMB lure (issue #87): a real Samba, on Alpine, serving read-only
# guest shares beside a Mockingbird canary and built on the assumption
# that it will be attacked. README.md beside this file holds the run
# command, the hardening flags and the reasoning; ADR-0008 is why this is
# its own image and not a second service inside build/mockingbird.
#
#     docker build -f build/smb-lure/Dockerfile -t smb-lure .
#
# Nothing inside the image says what the image is for. The commentary
# lives here, in README.md and in the templates' own generator -- none of
# which is copied into the final stage.
#
# ---------------------------------------------------------------------
# Versions, and how they were chosen
#
# alpine:3.24 is the current Alpine stable release (3.24.2, checked
# 2026-09-23) and the base build/nightjar/Dockerfile already uses.
#
# samba 4.23.8-r0 is the exact version in that release's `main`
# repository on the same date. Pinned exactly, not floating, because this
# is the one shipped component whose CVE history the design turns on: a
# rebuild has to be a deliberate act that names the version it moved to,
# so the dependency bot's bump and the promotion of the new digest are
# the same visible change. A pinned version that has aged out of the
# repository fails the build loudly, which is the intended behaviour --
# an Alpine security update for samba is exactly when this image should
# be rebuilt.
#
# `samba-server` rather than the `samba` meta-package: the meta-package
# pulls the client tools, winbind and the AD server pieces, none of which
# this image runs. samba-common-tools (testparm, smbpasswd) is left out
# for the same reason -- fewer binaries in the one container built to be
# attacked -- which is why the entrypoint checks its inputs with grep
# rather than asking testparm to validate the generated configuration.

# ---------------------------------------------------------------------
# Stage 1: the share content, generated from the templates. Discarded --
# neither python3 nor the templates reach the shipped image.
FROM alpine:3.24 AS content

RUN apk add --no-cache python3=3.14.7-r1

COPY build/smb-lure/make-bait.py /make-bait.py
COPY build/smb-lure/bait /templates
RUN python3 /make-bait.py /templates /content

# ---------------------------------------------------------------------
# Stage 2: the image that runs.
FROM alpine:3.24

RUN apk add --no-cache samba-server=4.23.8-r0

COPY build/smb-lure/smb.conf /etc/samba/smb.conf.in
COPY build/smb-lure/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

# Owned by root, readable by everybody, writable by nobody. The share is
# `read only` in the configuration, the root filesystem is mounted
# read-only in the run command, and the files themselves are 0444: three
# independent reasons a visitor cannot change what is here.
COPY --from=content /content /srv/shares
RUN chown -R root:root /srv/shares \
    && find /srv/shares -type d -exec chmod 555 {} + \
    && find /srv/shares -type f -exec chmod 444 {} +

# 445/tcp. Never published: the container joins the canary's network
# namespace (README.md), so this is documentation of what it listens on,
# not a port mapping.
EXPOSE 445/tcp

# smbd runs as root and switches to the guest uid per connection -- there
# is no unprivileged smbd, so the design makes root worth little instead:
# read-only root filesystem, four capabilities, no-new-privileges, and
# every writable path a tmpfs. All of that is in the run command, where an
# operator can see it, rather than hidden in here where they cannot.
ENTRYPOINT ["/entrypoint.sh"]
