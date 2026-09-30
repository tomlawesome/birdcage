#!/bin/sh
# entrypoint.sh -- sets the test account up, makes the throwaway TLS
# certificate if this is the first start, applies MAIL_MODE, starts
# Dovecot and then execs Postfix in the foreground as PID 1.
#
# Mounts (scripts/e2e/mail-stack.sh makes all three):
#   /client        the files the CLIENT side needs: the stack script
#                  writes `password` here before the first start, and
#                  this script writes `ca.pem` -- the certificate to
#                  trust -- back. birdcage mounts it read-only.
#   /etc/mail-tls  the CA-signed server certificate and its key, kept
#                  across restarts so a mode switch does not change the
#                  certificate the client already trusts.
#   /var/mail      the Maildirs, kept across restarts so a message
#                  delivered in one mode can still be read in the next.
#
# Environment:
#   MAIL_HOSTNAME   the name clients connect to; the certificate's SAN.
#   MAIL_USER       the one account (default e2e-admin), e2e.invalid.
#   MAIL_MODE       what kind of server to be, for issue #80's cases:
#     normal        STARTTLS required before anything else; AUTH only
#                   after it. What a submission server should look like.
#     no-starttls   STARTTLS never offered, and AUTH offered in the
#                   clear instead -- the downgrade a client must refuse,
#                   made as tempting as possible.
#     reject-auth   as normal, but the account's password is not the
#                   one in /client/password, so every login fails.
#     size-cap      as normal, with message_size_limit at
#                   MAIL_SIZE_LIMIT bytes (default 1024) -- smaller than
#                   any alert birdcage writes.
set -eu

MAIL_USER="${MAIL_USER:-e2e-admin}"
MAIL_MODE="${MAIL_MODE:-normal}"
MAIL_SIZE_LIMIT="${MAIL_SIZE_LIMIT:-1024}"
: "${MAIL_HOSTNAME:?MAIL_HOSTNAME must name the host clients connect to}"

log() { echo "e2e-mail: $*"; }
die() { echo "e2e-mail: $*" >&2; exit 1; }

[ -s /client/password ] || die "/client/password is missing or empty -- the stack script writes it before the first start"

# ---------------------------------------------------------------------
# The certificate: a throwaway CA and one leaf, made once. The CA key
# is deleted as soon as the leaf is signed -- nothing else is ever
# issued from it -- the same rule scripts/e2e/stack.sh's generate_tls
# follows for the dashboard's.
mkdir -p /etc/mail-tls
if [ ! -s /etc/mail-tls/server.pem ]; then
  log "making the throwaway CA and a certificate for $MAIL_HOSTNAME"
  work="$(mktemp -d)"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$work/ca-key.pem" -out /etc/mail-tls/ca.pem -days 1 \
    -subj "/CN=e2e-mail throwaway CA" 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout /etc/mail-tls/server-key.pem -out "$work/server.csr" \
    -subj "/CN=$MAIL_HOSTNAME" 2>/dev/null
  printf 'subjectAltName=DNS:%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' \
    "$MAIL_HOSTNAME" > "$work/server.ext"
  openssl x509 -req -in "$work/server.csr" -CA /etc/mail-tls/ca.pem -CAkey "$work/ca-key.pem" \
    -CAcreateserial -days 1 -extfile "$work/server.ext" -out /etc/mail-tls/server.pem 2>/dev/null
  rm -rf "$work"
  chmod 644 /etc/mail-tls/ca.pem /etc/mail-tls/server.pem
  chmod 600 /etc/mail-tls/server-key.pem
fi
cp /etc/mail-tls/ca.pem /client/ca.pem
chmod 444 /client/ca.pem

# ---------------------------------------------------------------------
# The account. One password file, read by Dovecot for IMAP and -- over
# the SASL socket -- for Postfix's AUTH, so the two can never disagree.
password="$(cat /client/password)"
case "$password" in
  *:*) die "/client/password must not contain ':' (passwd-file separator)" ;;
esac
if [ "$MAIL_MODE" = reject-auth ]; then
  # Anything but the password the client was given.
  password="rejected-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
fi
umask 027
printf '%s:{PLAIN}%s::::::\n' "$MAIL_USER" "$password" > /etc/dovecot/users
chgrp dovecot /etc/dovecot/users
umask 022

printf '%s@e2e.invalid %s/Maildir/\n' "$MAIL_USER" "$MAIL_USER" > /etc/postfix/vmailbox
# vmail is the account Alpine's postfix package makes; its uid and gid
# are read here rather than assumed, and handed to both daemons.
vmail_uid="$(id -u vmail)"
vmail_gid="$(id -g vmail)"
printf 'mail_uid = %s\nmail_gid = %s\nfirst_valid_uid = %s\n' "$vmail_uid" "$vmail_gid" "$vmail_uid" > /etc/dovecot/vmail.conf
mkdir -p "/var/mail/$MAIL_USER"
chown "$vmail_uid:$vmail_gid" "/var/mail/$MAIL_USER"

# ---------------------------------------------------------------------
# Postfix: submission on 587 and nothing on 25. The mode decides the
# rest.
postconf -M submission/inet="submission inet n - n - - smtpd"
postconf -MX smtp/inet
postconf -e "message_size_limit = 10240000" \
  "virtual_uid_maps = static:$vmail_uid" "virtual_gid_maps = static:$vmail_gid"
case "$MAIL_MODE" in
  normal|reject-auth)
    postconf -e "smtpd_tls_security_level = encrypt" "smtpd_tls_auth_only = yes" ;;
  no-starttls)
    postconf -e "smtpd_tls_security_level = none" "smtpd_tls_auth_only = no" ;;
  size-cap)
    postconf -e "smtpd_tls_security_level = encrypt" "smtpd_tls_auth_only = yes" \
      "message_size_limit = $MAIL_SIZE_LIMIT" ;;
  *) die "unknown MAIL_MODE=$MAIL_MODE (want normal, no-starttls, reject-auth or size-cap)" ;;
esac
log "mode $MAIL_MODE for $MAIL_USER@e2e.invalid on $MAIL_HOSTNAME"

# Dovecot's auth socket lives in Postfix's queue directory; make sure
# the directory exists before Dovecot tries to create the socket in it.
mkdir -p /var/spool/postfix/private
chown postfix /var/spool/postfix/private
chmod 700 /var/spool/postfix/private

# Daemonises itself; --init in the run command reaps it.
dovecot

i=0
while [ ! -S /var/spool/postfix/private/auth ]; do
  i=$((i + 1))
  [ "$i" -le 50 ] || die "Dovecot's auth socket never appeared"
  sleep 0.1
done

exec postfix start-fg
