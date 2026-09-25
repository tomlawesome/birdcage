# A CI-only mail server: a real Postfix (submission on 587, STARTTLS,
# AUTH via Dovecot SASL, delivery to a Maildir) and a real Dovecot (IMAP
# over TLS on 993) for one throwaway account. It exists only to drive
# issue #80's live check -- birdcage's outbound mail (internal/mail) and
# its approval mailbox (internal/mailbox) against servers that were not
# written in this repository -- and it never ships and is never anywhere
# near build/birdcage or build/mockingbird. scripts/e2e/mail-stack.sh is
# what builds and runs it, on demand, for scripts/e2e/mail.sh.
#
#     docker build -f build/e2e-mail/Dockerfile -t e2e-mail .
#
# ---------------------------------------------------------------------
# Versions, and how they were chosen
#
# alpine:3.24 is the base build/smb-lure and build/e2e-smbclient already
# use. The three packages are pinned to the exact versions in that
# release's `main` repository on 2026-09-25 (read with `apk policy`),
# the same way build/smb-lure pins Samba: owner, 2026-09-25, on #80 --
# "a test-only image built from Alpine's own postfix and dovecot
# packages, pinned to exact versions". Licences and the CVE check for
# these exact versions are recorded on #80. libsasl arrives as postfix's
# own dependency and is not named here; Postfix is told to use Dovecot's
# SASL, not Cyrus's, so it is linked but never asked to authenticate.
#
# openssl is the command-line tool, for the one thing the entrypoint
# needs it for: a throwaway CA and server certificate made at first
# start. A pinned version that has aged out of the repository fails the
# build loudly, which is the intended behaviour -- the bump is a
# deliberate, visible change.
#
# BASE_IMAGE defaults to the plain Docker Hub tag for a workstation
# build; scripts/e2e/mail-stack.sh passes CI's dependency-proxy pin
# (refs #128, .gitlab-ci.yml's ALPINE_IMAGE) as a build arg.
ARG BASE_IMAGE=alpine:3.24
FROM ${BASE_IMAGE}

RUN apk add --no-cache postfix=3.11.7-r0 dovecot=2.4.5-r0 openssl=3.5.8-r0

COPY build/e2e-mail/main.cf /etc/postfix/main.cf
COPY build/e2e-mail/dovecot.conf /etc/dovecot/dovecot.conf
COPY build/e2e-mail/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

# 587/tcp: submission, STARTTLS then AUTH (unless MAIL_MODE says
# otherwise -- see entrypoint.sh). 993/tcp: IMAP, TLS from the first
# byte. Runs as root: this image never ships, and both daemons start as
# root to bind these ports and then drop to their own users per process.
EXPOSE 587/tcp 993/tcp
ENTRYPOINT ["/entrypoint.sh"]
