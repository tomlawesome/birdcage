# A CI-only Samba image: a real smbd (vfs_full_audit) and a real
# smbclient, built from Debian packages on the same base image the rest
# of this repository uses. It exists only to prove the front half of
# issue #78's Samba journey -- that a real SMB client against a real
# smbd produces the smbd_audit line OpenCanary parses -- and it is never
# anywhere near build/mockingbird/Dockerfile (ADR-0008: Samba never
# reaches the shipped image). scripts/e2e/smb-stack.sh is what runs
# this, on demand, only for scripts/e2e/smb.sh.
#
#     docker build -f build/e2e-samba/Dockerfile -t e2e-samba .
#
# rsyslog is here for one reason, worked out by running it rather than
# guessed: vfs_full_audit's audit line only carries the `smbd_audit:` tag
# samba.py's regex needs when it actually goes through syslog(3) (see
# smb.conf's comment); something has to be listening on /dev/log for
# that call to go anywhere.
# BASE_IMAGE defaults to the plain Docker Hub tag for a workstation
# build; scripts/e2e/smb-stack.sh passes CI's dependency-proxy pin
# (refs #128, .gitlab-ci.yml's DEBIAN_TRIXIE_SLIM_IMAGE) as a build arg.
ARG BASE_IMAGE=debian:trixie-slim
FROM ${BASE_IMAGE}

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       samba samba-common-bin smbclient rsyslog \
    && rm -rf /var/lib/apt/lists/*

COPY build/e2e-samba/smb.conf /etc/samba/smb.conf
COPY build/e2e-samba/rsyslog-audit.conf /etc/rsyslog.d/60-audit.conf
COPY build/e2e-samba/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

# 445/tcp: SMB. Runs as root -- this image never ships, and smbd itself
# needs root to bind a port below 1024 and to open per-connection
# effective-uid switches for guest access.
EXPOSE 445/tcp
ENTRYPOINT ["/entrypoint.sh"]
