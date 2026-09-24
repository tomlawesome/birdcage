#!/usr/bin/env bash
# Exercises scripts/e2e/poisoner-stack.sh itself, the same way
# smb-stack.test.sh exercises scripts/e2e/smb-stack.sh: not the poisoner
# journey's assertions, but the harness underneath it -- a `down` that
# assumes something is up, a run killed half way, and a real `up` actually
# producing a listening Responder and a canary whose detector is running.
#
# poisoner-stack.sh needs a real stack.sh stack underneath it (it enrols
# its canary against a real birdcage), so this brings one up first, under
# its own E2E_PREFIX so it never touches a stack somebody has up, and
# every leftover assertion is scoped to that same prefix.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK="$HERE/stack.sh"
POISONER_STACK="$HERE/poisoner-stack.sh"
export E2E_PREFIX="birdcage-e2e-poisonerselftest"
# The Responder image comes from the private fixtures project, pulled by
# digest (AGENTS.md, "Attack-tool fixtures"); the harness never builds it.
: "${E2E_RESPONDER_IMAGE:?set E2E_RESPONDER_IMAGE to the responder image from the fixtures project}"

fail=0
check() { # check <actual> <expected> <label>
  if [ "$1" = "$2" ]; then
    echo "ok - $3"
  else
    echo "FAIL - $3: expected [$2] got [$1]"
    fail=1
  fi
}

# leftovers, scoped to poisoner-stack.sh's own names
# (E2E_PREFIX-poisoner*) so this never
# reports stack.sh's own -birdcage/-canary/-net objects as something
# poisoner-stack.sh failed to clean up -- those are stack.sh's to clean,
# and its own self-test already covers that.
leftovers() {
  {
    docker ps -a --format '{{.Names}}'
    docker volume ls --format '{{.Name}}'
    docker images --format '{{.Repository}}'
  } 2>/dev/null | grep -E "^$E2E_PREFIX-poisoner" | sort -u
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
  "$POISONER_STACK" down >/dev/null 2>&1 || true
  "$STACK" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== down is safe when nothing is up =="
"$POISONER_STACK" down >/dev/null 2>&1
check "$?" "0" "down exits 0 with nothing up"
check_clean "down with nothing up leaves nothing behind"

echo "== up refuses without a running stack.sh stack =="
( "$POISONER_STACK" up >/dev/null 2>&1 )
check "$?" "1" "up exits 1 without E2E_STACK/E2E_NET/E2E_BIRDCAGE/E2E_CANARY set"

echo "== down cleans up after a run killed half way =="
# Roughly what an interrupted `up` leaves: one volume created, the
# containers never started. (The Responder image is pulled, never built,
# so it is not a leftover -- AGENTS.md, "Attack-tool fixtures".)
docker volume create "$E2E_PREFIX-poisoner-log" >/dev/null
[ -n "$(leftovers)" ] && echo "ok - the partial run really did leave objects behind" \
  || { echo "FAIL - the partial-run fixture created nothing"; fail=1; }
"$POISONER_STACK" down >/dev/null 2>&1
check "$?" "0" "down exits 0 after a partial up"
check_clean "down after a partial up leaves nothing behind"

echo "== a real up produces a listening Responder and a canary with the detector on =="
stack_env="$("$STACK" up 2>/dev/null)"
check "$?" "0" "stack.sh up succeeds"
eval "$stack_env"

poisoner_env="$("$POISONER_STACK" up 2>/dev/null)"
check "$?" "0" "poisoner-stack.sh up succeeds"
case "$poisoner_env" in
  *POISONER_CANARY_ID=*) echo "ok - up prints a canary id" ;;
  *) echo "FAIL - up did not print POISONER_CANARY_ID"; fail=1 ;;
esac
# The deploy token and the bait names are both things `up` handles and
# neither may appear in what it prints: a token is a credential, and a
# bait name is the one value this whole feature keeps out of anything an
# attacker might read.
case "$poisoner_env" in
  *MOCKINGBIRD_DEPLOY_TOKEN*|*TOKEN=*) echo "FAIL - up printed something token-shaped"; fail=1 ;;
  *) echo "ok - up prints no credential" ;;
esac
case "$poisoner_env" in
  *MOCKINGBIRD_POISONER_NAMES*|*e2e-oldfs*) echo "FAIL - up printed a bait name"; fail=1 ;;
  *) echo "ok - up prints no bait name" ;;
esac
eval "$poisoner_env"

# Responder listening, not just a container that stayed running -- the
# same distinction smb-stack.test.sh's smbclient check draws.
docker logs "$POISONER_RESPONDER" 2>&1 | grep -q "Listening for events..."
check "$?" "0" "Responder reports itself listening"

# And the canary's own detector is running, which is what makes the
# journey's first step meaningful rather than a wait on nothing.
docker logs "$POISONER_CANARY" 2>&1 | grep -q "poisoner detection active"
check "$?" "0" "the canary reports its poisoner detector active"

docker exec "$E2E_BIRDCAGE" /birdcage canary enrol --status 2>/dev/null | grep -q "canary=$POISONER_CANARY_ID"
check "$?" "0" "the canary is provisioned and known to birdcage"

"$POISONER_STACK" down >/dev/null 2>&1
check "$?" "0" "poisoner-stack.sh down succeeds"
check_clean "down after up leaves nothing behind"

"$STACK" down >/dev/null 2>&1

echo "== an unknown subcommand is a usage error =="
E2E_STACK=x E2E_NET=x E2E_BIRDCAGE=x E2E_CANARY=x "$POISONER_STACK" wibble >/dev/null 2>&1
check "$?" "2" "unknown subcommand exits 2"

exit "$fail"
