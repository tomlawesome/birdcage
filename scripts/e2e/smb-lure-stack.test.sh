#!/usr/bin/env bash
# Exercises scripts/e2e/smb-lure-stack.sh itself, the same way
# smb-stack.test.sh exercises its own harness: not the journey's
# assertions, but the harness underneath it -- a `down` that assumes
# something is up, a run killed half way, and a real `up` actually
# producing the shipped lure serving SMB on a canary's own address.
#
# It needs a real stack.sh stack underneath (it enrols a canary against a
# real birdcage), so it brings one up, under its own E2E_PREFIX so it never
# touches a stack somebody has up.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK="$HERE/stack.sh"
LURE_STACK="$HERE/smb-lure-stack.sh"
export E2E_PREFIX="birdcage-e2e-lureselftest"

fail=0
check() { # check <actual> <expected> <label>
  if [ "$1" = "$2" ]; then
    echo "ok - $3"
  else
    echo "FAIL - $3: expected [$2] got [$1]"
    fail=1
  fi
}

# leftovers, scoped to this harness's own names (E2E_PREFIX-lure* and
# E2E_PREFIX-smbclient*) so it never reports stack.sh's own objects as
# something this file failed to clean up.
leftovers() {
  {
    docker ps -a --format '{{.Names}}'
    docker volume ls --format '{{.Name}}'
    docker images --format '{{.Repository}}'
  } 2>/dev/null | grep -E "^$E2E_PREFIX-(lure|smbclient)" | sort -u
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
  "$LURE_STACK" down >/dev/null 2>&1 || true
  "$STACK" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== down is safe when nothing is up =="
"$LURE_STACK" down >/dev/null 2>&1
check "$?" "0" "down exits 0 with nothing up"
check_clean "down with nothing up leaves nothing behind"

echo "== up refuses without E2E_PREFIX =="
( unset E2E_PREFIX; "$LURE_STACK" up >/dev/null 2>&1 )
check "$?" "2" "up exits 2 with E2E_PREFIX unset"

echo "== up refuses without a running stack.sh stack =="
( "$LURE_STACK" up >/dev/null 2>&1 )
check "$?" "1" "up exits 1 without E2E_STACK/E2E_NET/E2E_BIRDCAGE/E2E_CANARY set"

echo "== down cleans up after a run killed half way =="
docker volume create "$E2E_PREFIX-lure-audit" >/dev/null
printf 'FROM alpine:3.24\n' | docker build --quiet --tag "$E2E_PREFIX-lure-image" - >/dev/null
[ -n "$(leftovers)" ] && echo "ok - the partial run really did leave objects behind" \
  || { echo "FAIL - the partial-run fixture created nothing"; fail=1; }
"$LURE_STACK" down >/dev/null 2>&1
check "$?" "0" "down exits 0 after a partial up"
check_clean "down after a partial up leaves nothing behind"

echo "== a real up produces the shipped lure serving SMB on the canary's address =="
stack_env="$("$STACK" up 2>/dev/null)"
check "$?" "0" "stack.sh up succeeds"
eval "$stack_env"

lure_env="$("$LURE_STACK" up 2>/dev/null)"
check "$?" "0" "smb-lure-stack.sh up succeeds"
case "$lure_env" in
  *SMB_LURE_CANARY_ID=*) echo "ok - up prints a canary id" ;;
  *) echo "FAIL - up did not print SMB_LURE_CANARY_ID"; fail=1 ;;
esac
case "$lure_env" in
  *MOCKINGBIRD_DEPLOY_TOKEN*|*TOKEN=*) echo "FAIL - up printed something token-shaped"; fail=1 ;;
  *) echo "ok - up prints no credential" ;;
esac
eval "$lure_env"

# The share has to answer on the CANARY's address, not the lure's own:
# that is decision 3, and a harness that checked the lure container's name
# would pass while the design was broken.
docker run --rm --network "$E2E_NET" "$SMB_LURE_CLIENT_IMAGE" -L "//$SMB_LURE_CANARY" -N 2>/dev/null | grep -q "$SMB_LURE_SHARE"
check "$?" "0" "the lure answers a real smbclient -L on the canary's own address"

# The lure publishes no port of its own, so it has no network settings at
# all -- it is using the canary's. A lure with its own IP would mean the
# --network container: flag had silently stopped applying.
lure_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SMB_LURE" 2>/dev/null)"
check "$lure_ip" "" "the lure has no address of its own"

# The canary mounts the audit volume read-only. If that ever became
# read-write, a compromised smbd could reach the canary's own filesystem.
docker inspect --format '{{range .Mounts}}{{if eq .Destination "/audit"}}{{.RW}}{{end}}{{end}}' "$SMB_LURE_CANARY" 2>/dev/null | grep -qx false
check "$?" "0" "the canary's /audit mount is read-only"

docker exec "$E2E_BIRDCAGE" /birdcage canary enrol --status 2>/dev/null | grep -q "canary=$SMB_LURE_CANARY_ID"
check "$?" "0" "the canary is provisioned and known to birdcage"

echo "== restart-canary brings both back =="
"$LURE_STACK" restart-canary >/dev/null 2>&1
check "$?" "0" "restart-canary exits 0"
docker run --rm --network "$E2E_NET" "$SMB_LURE_CLIENT_IMAGE" -L "//$SMB_LURE_CANARY" -N 2>/dev/null | grep -q "$SMB_LURE_SHARE"
check "$?" "0" "the lure answers again after the canary restarted"

"$LURE_STACK" down >/dev/null 2>&1
check "$?" "0" "smb-lure-stack.sh down succeeds"
check_clean "down after up leaves nothing behind"

"$STACK" down >/dev/null 2>&1

echo "== an unknown subcommand is a usage error =="
E2E_STACK=x E2E_NET=x E2E_BIRDCAGE=x E2E_CANARY=x "$LURE_STACK" wibble >/dev/null 2>&1
check "$?" "2" "unknown subcommand exits 2"

exit "$fail"
