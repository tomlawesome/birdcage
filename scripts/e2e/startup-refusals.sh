#!/usr/bin/env bash
# startup-refusals.sh -- issue #78 journey C: birdcage refuses to start,
# loudly and for the right reason, against a handful of bad
# configurations. Runs the birdcage image alone, before scripts/e2e/
# stack.sh up brings up the rest of the stack -- nothing here needs a
# network, a database volume or a second container.
#
# This file cannot source journey.sh: that file's very first line
# refuses to run at all unless E2E_STACK is already set (`eval
# "$(stack.sh up)"` has run), which is exactly the thing this journey
# runs before. What follows instead is the same shape by hand -- step/ok/
# fail, a failure that names the step and dumps the container's log --
# copied from journey.sh rather than sourced from it.
#
#   E2E_BIRDCAGE_IMAGE=birdcage-e2e-image scripts/e2e/startup-refusals.sh
set -eu

: "${E2E_BIRDCAGE_IMAGE:?set E2E_BIRDCAGE_IMAGE to the birdcage image to test (see scripts/e2e/stack.sh)}"

JOURNEY_NAME="$(basename "$0" .sh)"
STEP_NUMBER=0
STEP_NAME="(no step started)"
echo "== $JOURNEY_NAME =="

step() {
  STEP_NUMBER=$((STEP_NUMBER + 1))
  STEP_NAME="$1"
  echo "step $STEP_NUMBER ($STEP_NAME): starting"
}
ok() { echo "  ok   $*"; }
fail() {
  local message="$1" name="$2" log="$3"
  echo "step $STEP_NUMBER ($STEP_NAME) FAILED: $message" >&2
  echo "--- container output ($name) ---" >&2
  printf '%s\n' "$log" >&2
  exit 1
}

# run_refused runs the birdcage image with the given extra `docker run`
# arguments (an env override or two), expecting it to exit non-zero
# within refuseTimeout and to print want_substring somewhere in its
# combined output -- startcheck's and tlsconfig's own messages all go to
# stderr via internal/logging, but this greps stdout+stderr together so
# a message landing on either still counts.
refuseTimeout=15
refusal_count=0
run_refused() {
  local name="$1" want_substring="$2"
  shift 2
  # Named from E2E_PREFIX (the job id in CI), never from $$: a fresh CI
  # container starts its shell at the same pid every time, so two jobs
  # on one Docker host collided on "-63" (pipeline 1521). The counter
  # keeps consecutive refusals in one run apart too.
  refusal_count=$((refusal_count + 1))
  local container="${E2E_PREFIX:-birdcage-e2e}-startup-refusal-$refusal_count"
  local out status
  # A refusal exiting non-zero is the success case this function is
  # testing for, so the capture below must not trip `set -e` itself --
  # disabled around just this one command, restored immediately after.
  set +e
  out="$(timeout "$refuseTimeout" docker run --rm --name "$container" \
    --cap-drop ALL --security-opt no-new-privileges \
    "$@" "$E2E_BIRDCAGE_IMAGE" 2>&1)"
  status=$?
  set -e
  docker rm --force "$container" >/dev/null 2>&1 || true
  if [ "$status" -eq 0 ]; then
    fail "$name: birdcage exited 0 -- it started instead of refusing" "$container" "$out"
  fi
  if [ "$status" -eq 124 ]; then
    fail "$name: birdcage did not exit within ${refuseTimeout}s (timeout killed it)" "$container" "$out"
  fi
  case "$out" in
    *"$want_substring"*) ok "$name: exited $status, message names the cause: $(printf '%s' "$out" | grep -F "$want_substring" | head -1)" ;;
    *) fail "$name: exited $status but the output never named the cause (\"$want_substring\"): $out" "$container" "$out" ;;
  esac
}

step "a missing data directory is refused"
# internal/startcheck.WritableDir proves the data directory before the
# database ever opens (issue #70) -- BIRDCAGE_DB_PATH pointed at a
# directory the image never created and no volume supplies one.
run_refused "missing data directory" \
  "is not usable by this process" \
  --env BIRDCAGE_DB_PATH=/no-such-directory/birdcage.db

step "a missing certificate where one is required is refused"
# BIRDCAGE_HTTP_TLS_CERT/_KEY both point at paths nothing mounted --
# tlsconfig.Select accepts the pair (both set, so ModeCert), and
# startcheck.ReadableFile then proves the cert file itself is actually
# there before the listener ever binds to it.
run_refused "missing certificate" \
  "is not usable by this process" \
  --env BIRDCAGE_HTTP_TLS_CERT=/tls/does-not-exist.pem \
  --env BIRDCAGE_HTTP_TLS_KEY=/tls/does-not-exist-key.pem

# Issue #70/#63's third named case -- a non-loopback BIRDCAGE_HTTP_ADDR
# with no certificate configured -- is a named gap, not skipped
# silently: internal/tlsconfig.Select (see its own doc comment, and
# build/birdcage/Dockerfile's now-stale comment claiming the opposite)
# no longer refuses that combination. Owner decision 2026-09-20
# (issue #63) changed it to ModeMintedCert -- birdcage mints its own
# leaf from its own CA and starts anyway -- specifically so a bare
# `docker run` with no TLS configuration would no longer need one. There
# is currently no configuration under which a non-loopback address with
# no certificate makes birdcage refuse to start; grep internal/tlsconfig
# and cmd/birdcage/main.go to confirm this is still true before ever
# reviving this case.

echo "RESULT: PASS ($JOURNEY_NAME, $STEP_NUMBER steps; 1 named gap -- see the journey's own comment above)"
