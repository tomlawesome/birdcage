#!/usr/bin/env bash
# mail-stack.sh -- the infrastructure scripts/e2e/mail.sh needs (#80): a
# real Postfix and Dovecot (build/e2e-mail) on the stack's network, and
# birdcage restarted with its outbound mail (internal/mail) and its
# approval mailbox (internal/mailbox) both pointed at them.
#
#   eval "$(scripts/e2e/stack.sh up)"
#   eval "$(scripts/e2e/mail-stack.sh up)"
#   scripts/e2e/mail.sh
#   scripts/e2e/mail-stack.sh down
#   scripts/e2e/stack.sh down
#
# `mode <m>` restarts the mail server as a different kind of server --
# see build/e2e-mail/entrypoint.sh for the four -- without touching
# birdcage. That is the point of it: birdcage's configuration is the one
# an operator would write, set once, and the server is what changes
# underneath it, which is how each failure turns up in real life.
#
# Everything is named from stack.sh's own E2E_PREFIX, so `down` only ever
# touches what this file created and two parallel pipelines never collide.
set -eu

[ -n "${E2E_PREFIX:-}" ] || {
  echo "mail-stack: E2E_PREFIX unset -- run: eval \"\$(scripts/e2e/stack.sh up)\" first" >&2
  exit 2
}

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

MAIL="${E2E_PREFIX}-mail"
MAIL_IMAGE="${E2E_PREFIX}-mail-image"
# Three volumes, for the three lifetimes build/e2e-mail/entrypoint.sh
# describes: what the client is handed (the CA and the password),
# the server's certificate and key, and the Maildirs. The last two
# outlive a `mode` restart on purpose.
CLIENT_VOL="${E2E_PREFIX}-mail-client"
TLS_VOL="${E2E_PREFIX}-mail-tls"
SPOOL_VOL="${E2E_PREFIX}-mail-spool"
# stack.sh names its birdcage container this way; `down` has to be able
# to find it with nothing but E2E_PREFIX set (see down below).
BIRDCAGE_CONTAINER="${E2E_BIRDCAGE:-${E2E_PREFIX}-birdcage}"

# The one account. Clearly fake placeholders: e2e.invalid can never be a
# real domain, and the password opens a mailbox that exists only inside
# this job. It is still handled like a real one -- written to a file, and
# never put on a command line -- because the point of the journey is to
# exercise the password-file path an operator is told to use.
MAIL_USER=e2e-admin
MAIL_ADDRESS=e2e-admin@e2e.invalid
MAIL_FROM=birdcage@e2e.invalid
MAIL_PASSWORD_PLACEHOLDER=e2e-placeholder-not-a-real-password

log() { echo "mail-stack: $*" >&2; }
die() { echo "mail-stack: $*" >&2; exit 1; }

build_mail_image() {
  if docker image inspect "$MAIL_IMAGE" >/dev/null 2>&1; then
    log "using existing image $MAIL_IMAGE"
    return 0
  fi
  log "building $MAIL_IMAGE from build/e2e-mail/Dockerfile"
  # --build-arg BASE_IMAGE: CI's dependency-proxy pin (refs #128,
  # .gitlab-ci.yml) when set, the Dockerfile's own default on a workstation.
  docker build --build-arg BASE_IMAGE="${ALPINE_IMAGE:-alpine:3.24}" \
    --file "$REPO_ROOT/build/e2e-mail/Dockerfile" --tag "$MAIL_IMAGE" "$REPO_ROOT" >/dev/null \
    || die "building $MAIL_IMAGE failed"
}

# create_volumes makes the three volumes and writes the password into the
# client one. uid 1000 is what the birdcage image runs as: it must be able
# to read the file, and nobody else needs to. The mail server reads it as
# root.
create_volumes() {
  local vol
  for vol in "$CLIENT_VOL" "$TLS_VOL" "$SPOOL_VOL"; do
    docker volume create "$vol" >/dev/null || die "creating volume $vol failed"
  done
  printf '%s\n' "$MAIL_PASSWORD_PLACEHOLDER" | docker run --rm --interactive \
    --volume "$CLIENT_VOL:/client" "${ALPINE_IMAGE:-alpine:3.24}" \
    sh -c 'cat > /client/password && chown 1000:1000 /client/password && chmod 400 /client/password' \
    || die "writing the test account's password into $CLIENT_VOL failed"
}

# run_mail starts the server container in the given mode. --init reaps
# the Dovecot daemon the entrypoint starts before it execs Postfix.
run_mail() {
  docker run --detach --name "$MAIL" --network "$E2E_NET" --init \
    --pids-limit 256 --memory 256m \
    --volume "$CLIENT_VOL:/client" \
    --volume "$TLS_VOL:/etc/mail-tls" \
    --volume "$SPOOL_VOL:/var/mail" \
    --env "MAIL_HOSTNAME=$MAIL" \
    --env "MAIL_USER=$MAIL_USER" \
    --env "MAIL_MODE=$1" \
    "$MAIL_IMAGE" >/dev/null || die "starting $MAIL ($1) failed"
}

# postfix_started waits for Postfix's own "daemon started" line: by then
# the entrypoint has made the certificate, written the CA out, and
# started Dovecot.
postfix_started() {
  local attempt
  for attempt in $(seq 1 30); do
    if docker logs "$MAIL" 2>&1 | grep -q "daemon started"; then
      return 0
    fi
    sleep 1
  done
  log "$MAIL never started; its log follows"
  docker logs "$MAIL" >&2 || true
  die "the mail server did not start"
}

# smtp_ready and imap_ready ask the server a real question from another
# container on the stack's network, verified against the exported CA --
# not merely whether a port is open -- and each expects the answer the
# mode says it should give. In no-starttls mode there is no TLS to
# verify, so an EHLO answered is enough; in reject-auth mode the login
# is meant to fail, so a TLS greeting is. Every probe ends with QUIT or
# LOGOUT so the server closes the session: `s_client -quiet` ignores end
# of input, and a probe that only sent nothing sat open until Dovecot's
# own three-minute login timeout -- which is how this was found.
smtp_ready() {
  if [ "$1" = no-starttls ]; then
    "$E2E_STACK" helper "{ sleep 1; printf 'EHLO probe\\r\\n'; sleep 1; printf 'QUIT\\r\\n'; sleep 1; } | nc -w 5 $MAIL 587 | grep -q '^221'"
  else
    "$E2E_STACK" helper "echo QUIT | openssl s_client -quiet -verify_return_error -CAfile /work/mail-ca.pem -verify_hostname $MAIL -starttls smtp -connect $MAIL:587 2>/dev/null | grep -q '^221'"
  fi
}

imap_ready() {
  if [ "$1" = reject-auth ]; then
    "$E2E_STACK" helper "printf 'a LOGOUT\\r\\n' | openssl s_client -quiet -verify_return_error -CAfile /work/mail-ca.pem -verify_hostname $MAIL -connect $MAIL:993 2>/dev/null | grep -q '^\\* OK'"
  else
    "$E2E_STACK" helper "curl -sS --max-time 5 --cacert /work/mail-ca.pem --netrc-file /work/mail-netrc 'imaps://$MAIL/INBOX' -X NOOP"
  fi
}

wait_for_mail() {
  local attempt
  for attempt in $(seq 1 30); do
    if smtp_ready "$1" >/dev/null 2>&1 && imap_ready "$1" >/dev/null 2>&1; then
      log "$MAIL answered SMTP and IMAP as mode $1 on attempt $attempt"
      return 0
    fi
    sleep 1
  done
  log "$MAIL never answered as mode $1; its log follows"
  docker logs "$MAIL" >&2 || true
  die "the mail server did not become ready"
}

# export_client_files puts what a journey-side client needs into the
# stack's work volume: the CA to trust, and the account as a netrc file
# so curl never carries the password on its command line.
export_client_files() {
  docker run --rm --volume "$CLIENT_VOL:/client:ro" "${ALPINE_IMAGE:-alpine:3.24}" cat /client/ca.pem \
    | "$E2E_STACK" write-work mail-ca.pem || die "could not copy the mail CA into the work volume"
  printf 'machine %s login %s password %s\n' "$MAIL" "$MAIL_USER" "$MAIL_PASSWORD_PLACEHOLDER" \
    | "$E2E_STACK" write-work mail-netrc || die "could not write the mail netrc into the work volume"
}

# restart_birdcage_with_mail restarts birdcage (stack.sh restart-birdcage)
# with both mail subsystems configured the way docs/configuration.md tells
# an operator to: password from a file, STARTTLS on 587, IMAP on 993.
#
# SSL_CERT_FILE is Go's own, standard way to say which roots to trust
# (crypto/x509 reads it on Linux); birdcage has no setting of its own for
# this and must not grow one -- internal/mail's tlsConfig comment says
# why. An operator whose mail server has a private CA does exactly this.
# Verification itself is untouched: the certificate is checked against
# that CA and against the host name in BIRDCAGE_MAIL_HOST.
restart_birdcage_with_mail() {
  "$E2E_STACK" restart-birdcage \
    --volume "$CLIENT_VOL:/mail:ro" \
    --env SSL_CERT_FILE=/mail/ca.pem \
    --env "BIRDCAGE_MAIL_HOST=$MAIL:587" \
    --env BIRDCAGE_MAIL_STARTTLS=1 \
    --env "BIRDCAGE_MAIL_USERNAME=$MAIL_USER" \
    --env BIRDCAGE_MAIL_PASSWORD_FILE=/mail/password \
    --env "BIRDCAGE_MAIL_FROM=$MAIL_FROM" \
    --env "BIRDCAGE_MAIL_TO=$MAIL_ADDRESS" \
    --env "BIRDCAGE_APPROVAL_IMAP_HOST=$MAIL" \
    --env "BIRDCAGE_APPROVAL_IMAP_USERNAME=$MAIL_USER" \
    --env BIRDCAGE_APPROVAL_IMAP_PASSWORD_FILE=/mail/password \
    >&2 || die "restarting birdcage with mail configured failed"
}

# mode restarts the server as another kind of server. The certificate and
# the Maildirs are in volumes, so the client's trust and any mail already
# delivered survive it.
mode() {
  [ $# -eq 1 ] || die "usage: $0 mode {normal|no-starttls|reject-auth|size-cap}"
  docker rm --force "$MAIL" >/dev/null 2>&1 || true
  run_mail "$1"
  postfix_started
  wait_for_mail "$1"
}

up() {
  command -v docker >/dev/null 2>&1 || die "docker is not on PATH"
  [ -n "${E2E_STACK:-}" ] && [ -n "${E2E_NET:-}" ] && [ -n "${E2E_BIRDCAGE:-}" ] \
    || die "E2E_STACK/E2E_NET/E2E_BIRDCAGE unset -- run: eval \"\$(scripts/e2e/stack.sh up)\" first"
  down_mail >/dev/null 2>&1 || true

  build_mail_image
  create_volumes
  run_mail normal
  postfix_started
  export_client_files
  wait_for_mail normal
  restart_birdcage_with_mail

  cat <<EOF
export MAIL_SERVER=$MAIL
export MAIL_USER=$MAIL_USER
export MAIL_ADDRESS=$MAIL_ADDRESS
export MAIL_FROM=$MAIL_FROM
export MAIL_STACK=$(cd "$(dirname "$0")" && pwd)/mail-stack.sh
EOF
}

# down_mail removes what this file made, except the client volume while
# birdcage still has it mounted.
down_mail() {
  docker rm --force "$MAIL" >/dev/null 2>&1 || true
  local vol
  for vol in "$TLS_VOL" "$SPOOL_VOL" "$CLIENT_VOL"; do
    docker volume rm --force "$vol" >/dev/null 2>&1 || true
  done
  # Only an image this file built, and only one carrying the prefix.
  case "$MAIL_IMAGE" in
    "$E2E_PREFIX"*) docker image rm --force "$MAIL_IMAGE" >/dev/null 2>&1 || true ;;
  esac
}

# down also removes the birdcage container, which stack.sh owns and would
# remove a moment later anyway: restart_birdcage_with_mail started it with
# this file's client volume mounted, and Docker will not delete a volume a
# container still holds -- so without this the volume would outlive both
# `down`s. Removing a container twice is harmless; stack.sh down tolerates
# it being gone.
down() {
  docker rm --force "$BIRDCAGE_CONTAINER" >/dev/null 2>&1 || true
  down_mail
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  mode) shift; mode "$@" ;;
  *)
    echo "usage: $0 {up|down|mode <normal|no-starttls|reject-auth|size-cap>}" >&2
    exit 2 ;;
esac
