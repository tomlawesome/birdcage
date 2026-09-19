#!/usr/bin/env bash
# Exercises scripts/e2e/stack.sh itself -- the harness, not the
# journeys. What it covers is what has actually gone wrong with a
# harness of this shape: a `down` that assumes something is up, a run
# killed half way leaving containers and volumes behind, and a second
# `up` wedging on the first one's leftovers.
#
# It uses its own E2E_PREFIX, so it never touches a stack somebody has
# up, and every assertion about leftovers is scoped to that prefix.
# Images are built under that prefix too (cached layers, so it is
# re-tagging rather than rebuilding), which is why this takes a couple
# of minutes rather than seconds.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK="$HERE/stack.sh"
export E2E_PREFIX="birdcage-e2e-selftest"

fail=0
check() { # check <actual> <expected> <label>
  if [ "$1" = "$2" ]; then
    echo "ok - $3"
  else
    echo "FAIL - $3: expected [$2] got [$1]"
    fail=1
  fi
}

# leftovers prints every docker object this harness would have created,
# so "nothing left behind" is checked against the daemon rather than
# against the script's own idea of what it removed.
leftovers() {
  {
    docker ps -a --format '{{.Names}}'
    docker volume ls --format '{{.Name}}'
    docker network ls --format '{{.Name}}'
    docker images --format '{{.Repository}}'
  } 2>/dev/null | grep "^$E2E_PREFIX" | sort -u
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

trap '"$STACK" down >/dev/null 2>&1 || true' EXIT

echo "== down is safe when nothing is up =="
"$STACK" down >/dev/null 2>&1
check "$?" "0" "down exits 0 with nothing up"
check_clean "down with nothing up leaves nothing behind"

echo "== down cleans up after a run killed half way =="
# Exactly the state an interrupted `up` leaves: the network and volumes
# made, one container started, the rest never reached.
docker network create "$E2E_PREFIX-net" >/dev/null
for vol in data tls work state log; do docker volume create "$E2E_PREFIX-$vol" >/dev/null; done
docker run --detach --name "$E2E_PREFIX-birdcage" --network "$E2E_PREFIX-net" \
  --volume "$E2E_PREFIX-data:/data" alpine:3.24 sleep 600 >/dev/null
printf 'FROM alpine:3.24\n' | docker build --quiet --tag "$E2E_PREFIX-helper" - >/dev/null
[ -n "$(leftovers)" ] && echo "ok - the partial run really did leave objects behind" \
  || { echo "FAIL - the partial-run fixture created nothing"; fail=1; }
"$STACK" down >/dev/null 2>&1
check "$?" "0" "down exits 0 after a partial up"
check_clean "down after a partial up leaves nothing behind"

echo "== up twice does not wedge =="
first="$("$STACK" up 2>/dev/null)"
check "$?" "0" "first up succeeds"
case "$first" in
  *BIRDCAGE_URL=https://*) echo "ok - up prints an eval-able environment" ;;
  *) echo "FAIL - up did not print BIRDCAGE_URL"; fail=1 ;;
esac
case "$first" in
  *MOCKINGBIRD_DEPLOY_TOKEN*|*TOKEN=*) echo "FAIL - up printed something token-shaped"; fail=1 ;;
  *) echo "ok - up prints no credential" ;;
esac

second="$("$STACK" up 2>/dev/null)"
check "$?" "0" "second up succeeds"
case "$second" in
  *BIRDCAGE_URL=https://*) echo "ok - the second up prints an environment too" ;;
  *) echo "FAIL - the second up did not print BIRDCAGE_URL"; fail=1 ;;
esac
# And the stack it left is the working one, not the first run's
# half-removed remains: ask the dashboard over its real certificate.
"$STACK" helper "curl -sS --cacert /tls/dashboard-ca.pem https://$E2E_PREFIX-birdcage:8080/api/alerts" 2>/dev/null | grep -q '"alerts"'
check "$?" "0" "the dashboard answers after the second up"

"$STACK" down >/dev/null 2>&1
check "$?" "0" "down after up succeeds"
check_clean "down after up leaves nothing behind"

echo "== an unknown subcommand is a usage error =="
"$STACK" wibble >/dev/null 2>&1
check "$?" "2" "unknown subcommand exits 2"

exit "$fail"
