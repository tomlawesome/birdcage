#!/usr/bin/env bash
# Exercises scripts/e2e/smb-stack.sh itself, the same way stack.test.sh
# exercises scripts/e2e/stack.sh: not the smb journey's assertions, but
# the harness underneath it -- a `down` that assumes something is up, a
# run killed half way, and a real `up` actually producing a working
# Samba server and second canary.
#
# smb-stack.sh needs a real stack.sh stack underneath it (it enrols its
# second canary against a real birdcage), so this brings one up first,
# under its own E2E_PREFIX so it never touches a stack somebody has up,
# and every leftover assertion is scoped to that same prefix.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK="$HERE/stack.sh"
SMB_STACK="$HERE/smb-stack.sh"
export E2E_PREFIX="birdcage-e2e-smbselftest"

fail=0
check() { # check <actual> <expected> <label>
  if [ "$1" = "$2" ]; then
    echo "ok - $3"
  else
    echo "FAIL - $3: expected [$2] got [$1]"
    fail=1
  fi
}

# leftovers, scoped to the smb-stack names specifically (E2E_PREFIX-smb*
# and E2E_PREFIX-samba*) so this never reports stack.sh's own
# -birdcage/-canary/-net objects as something smb-stack.sh failed to
# clean up -- those are stack.sh's to clean, and its own self-test
# already covers that.
leftovers() {
  {
    docker ps -a --format '{{.Names}}'
    docker volume ls --format '{{.Name}}'
    docker images --format '{{.Repository}}'
  } 2>/dev/null | grep -E "^$E2E_PREFIX-(smb|samba)" | sort -u
}

check_clean() { # check_clean <label>
  local left
  left="$(leftovers)"
  if [ -z "$left" ]; then
    echo "ok - $1"
  else
    echo "FAIL - $1: left behind:"
    echo "$left" | sed 's/^/    /'
    fail=1
  fi
}

cleanup() {
  "$SMB_STACK" down >/dev/null 2>&1 || true
  "$STACK" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== down is safe when nothing is up =="
"$SMB_STACK" down >/dev/null 2>&1
check "$?" "0" "down exits 0 with nothing up"
check_clean "down with nothing up leaves nothing behind"

echo "== up refuses without E2E_PREFIX =="
( unset E2E_PREFIX; "$SMB_STACK" up >/dev/null 2>&1 )
check "$?" "2" "up exits 2 with E2E_PREFIX unset"

echo "== up refuses without a running stack.sh stack =="
( "$SMB_STACK" up >/dev/null 2>&1 )
check "$?" "1" "up exits 1 without E2E_STACK/E2E_NET/E2E_BIRDCAGE/E2E_CANARY set"

echo "== down cleans up after a run killed half way =="
# Roughly what an interrupted `up` leaves: the image built and one
# volume created, the container never started.
docker volume create "$E2E_PREFIX-smb-log" >/dev/null
printf 'FROM alpine:3.24\n' | docker build --quiet --tag "$E2E_PREFIX-samba-image" - >/dev/null
[ -n "$(leftovers)" ] && echo "ok - the partial run really did leave objects behind" \
  || { echo "FAIL - the partial-run fixture created nothing"; fail=1; }
"$SMB_STACK" down >/dev/null 2>&1
check "$?" "0" "down exits 0 after a partial up"
check_clean "down after a partial up leaves nothing behind"

echo "== a real up produces a working Samba server and second canary =="
stack_env="$("$STACK" up 2>/dev/null)"
check "$?" "0" "stack.sh up succeeds"
eval "$stack_env"

smb_env="$("$SMB_STACK" up 2>/dev/null)"
check "$?" "0" "smb-stack.sh up succeeds"
case "$smb_env" in
  *SMB_CANARY_ID=*) echo "ok - up prints a canary id" ;;
  *) echo "FAIL - up did not print SMB_CANARY_ID"; fail=1 ;;
esac
case "$smb_env" in
  *MOCKINGBIRD_DEPLOY_TOKEN*|*TOKEN=*) echo "FAIL - up printed something token-shaped"; fail=1 ;;
  *) echo "ok - up prints no credential" ;;
esac
eval "$smb_env"

# smbclient -L, not just a container that stayed running: this is the
# same distinction test:image:mockingbird's own comment draws -- a
# container can be "up" with nothing behind the port.
docker run --rm --network "$E2E_NET" --entrypoint smbclient "$SMB_SAMBA_IMAGE" -L "//$SMB_SAMBA" -N 2>/dev/null | grep -q "Disk"
check "$?" "0" "smbd answers a real smbclient -L"

docker exec "$E2E_BIRDCAGE" /birdcage canary enrol --status 2>/dev/null | grep -q "canary=$SMB_CANARY_ID"
check "$?" "0" "the second canary is provisioned and known to birdcage"

"$SMB_STACK" down >/dev/null 2>&1
check "$?" "0" "smb-stack.sh down succeeds"
check_clean "down after up leaves nothing behind"

"$STACK" down >/dev/null 2>&1

echo "== an unknown subcommand is a usage error =="
E2E_STACK=x E2E_NET=x E2E_BIRDCAGE=x E2E_CANARY=x "$SMB_STACK" wibble >/dev/null 2>&1
check "$?" "2" "unknown subcommand exits 2"

exit "$fail"
