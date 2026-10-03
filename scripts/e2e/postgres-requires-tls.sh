#!/usr/bin/env bash
# postgres-requires-tls.sh -- issue #84 journey: a DATABASE_URL that
# could connect to Postgres without authenticating the server is
# refused before any listener binds, not on the first query.
#
# Standalone rather than sourcing journey.sh: every other journey in
# this directory asserts something about a stack that came up, but this
# one asserts the opposite -- that with a bad DATABASE_URL, birdcage
# never comes up at all, so there is no `stack.sh up` to build on.
# internal/startcheck.PostgresRequiresVerifyFull only parses the URL
# (pgconn.ParseConfig); it never dials, so this needs no Postgres
# server anywhere, real or fake -- proving that is part of the point:
# the refusal does not depend on reaching a server at all.
#
#   scripts/e2e/postgres-requires-tls.sh
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
PREFIX="${E2E_PREFIX:-birdcage-e2e-tls-refusal}"
IMAGE="$PREFIX-birdcage-image"
NAME="$PREFIX-birdcage"

STEP=0
step() { STEP=$((STEP + 1)); echo "step $STEP ($1): starting"; }
ok() { echo "  ok   $*"; }
fail() { echo "step $STEP FAILED: $*" >&2; exit 1; }

echo "== postgres-requires-tls =="
cleanup() {
  docker rm --force "$NAME" >/dev/null 2>&1 || true
  docker image rm --force "$IMAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

step "build the shipped image"
docker build --quiet --file "$REPO_ROOT/build/birdcage/Dockerfile" --tag "$IMAGE" "$REPO_ROOT" >/dev/null \
  || fail "building $IMAGE failed"
ok "built $IMAGE"

step "start birdcage with a plaintext-permitting DATABASE_URL"
# sslmode=disable named explicitly rather than left unset: pgx's own
# default for an absent sslmode is "prefer" (also refused, but by a
# different branch of the same check), so naming disable checks the
# plainest case without leaning on a default that could quietly change
# under us. nowhere.invalid never needs to resolve or answer -- the
# check runs before db.Open ever dials it.
#
# BIRDCAGE_HTTP_ADDR is loopback and BIRDCAGE_INGEST_ADDR is unset, so
# this needs no CA directory (internal/ca.Load, gated on exactly those
# two things in cmd/birdcage/main.go) -- the point here is the Postgres
# refusal alone, not the CA machinery a full `stack.sh up` exercises.
# --read-only/--tmpfs/--cap-drop match test:image:birdcage's hardening:
# a journey that only passes with these relaxed would be a finding
# about the shipped image, not about this check.
set +e
output="$(docker run --rm --name "$NAME" \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 64 --memory 256m \
  --env DATABASE_URL="postgres://postgres:refused@nowhere.invalid:5432/birdcage?sslmode=disable" \
  --env BIRDCAGE_HTTP_ADDR=127.0.0.1:8080 \
  --env BIRDCAGE_DB_PATH=/tmp/birdcage.db \
  "$IMAGE" 2>&1)"
status=$?
set -e
[ "$status" -ne 0 ] || fail "birdcage exited 0 with a plaintext-permitting DATABASE_URL: $output"
ok "exited $status rather than starting"

step "the refusal names sslmode=verify-full as the fix"
case "$output" in
  *"DATABASE_URL must set sslmode=verify-full"*) ok "logged startcheck's refusal message" ;;
  *) fail "birdcage's output did not name sslmode=verify-full: $output" ;;
esac

step "no listener ever bound"
# Every listener birdcage can open logs "serving ... on <addr>"
# immediately before binding (cmd/birdcage/main.go) -- its absence is
# the positive proof that nothing after the refusal ever ran.
case "$output" in
  *"serving dashboard"*) fail "output mentions the dashboard listener; it may have bound before refusing: $output" ;;
  *) ok "nothing in the output suggests a listener bound" ;;
esac

echo "RESULT: PASS (postgres-requires-tls, $STEP steps)"
