#!/usr/bin/env bash
# Tests for publish-image.sh. No docker daemon and no registry are available
# here, so these tests never touch either: they source the script (its
# sourcing guard keeps main() from running on import), override the four
# daemon-touching functions -- run_docker_push, resolve_pushed_digest,
# pull_digest, image_config_id -- with fixture stand-ins, and then drive
# main() for real over everything else: argument validation, reference
# parsing, and the round-trip comparison logic this script exists to get
# right.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/publish-image.sh"
pass=0; fail=0

ok() { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; shift; [ $# -gt 0 ] && printf '%s\n' "$*" | sed 's/^/       /'; fail=$((fail + 1)); }

# shellcheck source=/dev/null
source "$script"

repo="registry.gitlab.tomlawson.io/ai/birdcage/birdcage"
ref="${repo}:sha-$(printf 'b%.0s' $(seq 40))"
tested_id="sha256:$(printf 'a%.0s' $(seq 64))"
good_digest="sha256:$(printf 'c%.0s' $(seq 64))"

# Fixture controls read by the overridden daemon functions below.
PUSH_SHOULD_FAIL=0
RESOLVED_REPO_DIGEST=""
PULL_SHOULD_FAIL=0
PULLED_CONFIG_ID=""

run_docker_push() {
  [ "$PUSH_SHOULD_FAIL" = 1 ] && return 1
  return 0
}

resolve_pushed_digest() {
  [ -n "$RESOLVED_REPO_DIGEST" ] || return 1
  printf '%s' "$RESOLVED_REPO_DIGEST"
}

pull_digest() {
  [ "$PULL_SHOULD_FAIL" = 1 ] && return 1
  return 0
}

image_config_id() {
  printf '%s' "$PULLED_CONFIG_ID"
}

# reset_fixtures -- back to a happy-path baseline before each scenario that
# needs to change just one thing away from success.
reset_fixtures() {
  PUSH_SHOULD_FAIL=0
  RESOLVED_REPO_DIGEST="${repo}@${good_digest}"
  PULL_SHOULD_FAIL=0
  PULLED_CONFIG_ID="$tested_id"
}

# run <args...> -- invokes main() with stdout and stderr combined, in a
# subshell (command substitution) so main()'s `exit` (via fail()/refuse(),
# on every failure path) never kills the test runner.
run() {
  local got=0 out
  out="$(main "$@" 2>&1)" || got=$?
  printf '%s\x1f%s' "$got" "$out"
}

# run_stdout_only <args...> -- same, but keeps stdout and stderr apart, so
# the "stdout carries nothing but the digest" contract can actually be
# checked instead of assumed.
run_stdout_only() {
  local got=0 out
  out="$(main "$@" 2>/dev/null)" || got=$?
  printf '%s\x1f%s' "$got" "$out"
}

split() { GOT="${1%%$'\x1f'*}"; OUT="${1#*$'\x1f'}"; }

# --- happy path: exactly the digest on stdout, exit 0 --------------------
reset_fixtures
split "$(run_stdout_only "$ref" "$tested_id")"
if [ "$GOT" = 0 ] && [ "$OUT" = "$good_digest" ]; then
  ok "happy path prints exactly the pushed digest on stdout and nothing else, exit 0"
else
  bad "happy path prints exactly the pushed digest on stdout and nothing else, exit 0" "exit $GOT: $OUT"
fi

# --- argument handling ----------------------------------------------------
reset_fixtures
split "$(run)"
[ "$GOT" = 1 ] && ok "no arguments is a usage error (exit 1)" \
  || bad "no arguments is a usage error (exit 1)" "exit $GOT: $OUT"

split "$(run "$ref")"
[ "$GOT" = 1 ] && ok "a missing tested-image-id argument is a usage error (exit 1)" \
  || bad "a missing tested-image-id argument is a usage error (exit 1)" "exit $GOT: $OUT"

split "$(run "$ref" "$tested_id" "extra")"
[ "$GOT" = 1 ] && ok "too many arguments is a usage error (exit 1)" \
  || bad "too many arguments is a usage error (exit 1)" "exit $GOT: $OUT"

# --- reference validation --------------------------------------------------
split "$(run "${repo}@${good_digest}" "$tested_id")"
[ "$GOT" = 1 ] && ok "a reference already carrying @sha256: is refused (exit 1)" \
  || bad "a reference already carrying @sha256: is refused (exit 1)" "exit $GOT: $OUT"

split "$(run "${repo}:sha-x@${good_digest}" "$tested_id")"
[ "$GOT" = 1 ] && ok "a tag-plus-digest reference is refused (exit 1)" \
  || bad "a tag-plus-digest reference is refused (exit 1)" "exit $GOT: $OUT"

# --- tested image ID validation --------------------------------------------
split "$(run "$ref" "not-a-config-id")"
[ "$GOT" = 1 ] && ok "a malformed tested image ID is refused (exit 1)" \
  || bad "a malformed tested image ID is refused (exit 1)" "exit $GOT: $OUT"

# --- push failure -----------------------------------------------------------
reset_fixtures
PUSH_SHOULD_FAIL=1
split "$(run "$ref" "$tested_id")"
[ "$GOT" = 2 ] && ok "a failing docker push is refused (exit 2)" \
  || bad "a failing docker push is refused (exit 2)" "exit $GOT: $OUT"

# --- digest resolution failures ---------------------------------------------
reset_fixtures
RESOLVED_REPO_DIGEST=""
split "$(run "$ref" "$tested_id")"
if [ "$GOT" = 2 ] && [[ "$OUT" == *"could not resolve"* ]]; then
  ok "an unresolvable pushed digest is refused (exit 2), naming the cause"
else
  bad "an unresolvable pushed digest is refused (exit 2), naming the cause" "exit $GOT: $OUT"
fi

reset_fixtures
RESOLVED_REPO_DIGEST="${repo}@not-a-digest"
split "$(run "$ref" "$tested_id")"
if [ "$GOT" = 2 ] && [[ "$OUT" == *"malformed"* ]]; then
  ok "a malformed pushed digest is refused (exit 2), naming the cause"
else
  bad "a malformed pushed digest is refused (exit 2), naming the cause" "exit $GOT: $OUT"
fi

reset_fixtures
RESOLVED_REPO_DIGEST="registry.gitlab.tomlawson.io/ai/someone-else/other@${good_digest}"
split "$(run "$ref" "$tested_id")"
if [ "$GOT" = 2 ] && [[ "$OUT" == *"no RepoDigests entry for ${repo}"* ]]; then
  ok "a resolved digest belonging only to a different repository is refused (exit 2), naming the cause"
else
  bad "a resolved digest belonging only to a different repository is refused (exit 2), naming the cause" "exit $GOT: $OUT"
fi

# The containerd image store lists a RepoDigests entry for every name the
# image carries, local build tag included, so the published repository's
# entry is not necessarily first (pipeline #1476, #112).
reset_fixtures
RESOLVED_REPO_DIGEST="$(printf 'birdcage-build@%s\n%s@%s\n' "$good_digest" "$repo" "$good_digest")"
split "$(run "$ref" "$tested_id")"
if [ "$GOT" = 0 ] && [ "$OUT" = "$good_digest" ]; then
  ok "the published repository's entry is picked when a local tag's entry comes first"
else
  bad "the published repository's entry is picked when a local tag's entry comes first" "exit $GOT: $OUT"
fi

# --- pull-back failure -------------------------------------------------------
reset_fixtures
PULL_SHOULD_FAIL=1
split "$(run "$ref" "$tested_id")"
[ "$GOT" = 2 ] && ok "a failing pull-back is refused (exit 2)" \
  || bad "a failing pull-back is refused (exit 2)" "exit $GOT: $OUT"

# --- pulled config ID checks -------------------------------------------------
reset_fixtures
PULLED_CONFIG_ID="not-a-config-id"
split "$(run "$ref" "$tested_id")"
[ "$GOT" = 2 ] && ok "a malformed pulled-back config ID is refused (exit 2)" \
  || bad "a malformed pulled-back config ID is refused (exit 2)" "exit $GOT: $OUT"

# The important one: the registry round-trip catches a substituted image.
reset_fixtures
PULLED_CONFIG_ID="sha256:$(printf 'd%.0s' $(seq 64))"
split "$(run "$ref" "$tested_id")"
if [ "$GOT" = 2 ] && [[ "$OUT" == *"different image than was tested"* ]]; then
  ok "a pulled-back config ID differing from the tested image ID is refused (exit 2), naming the substitution"
else
  bad "a pulled-back config ID differing from the tested image ID is refused (exit 2), naming the substitution" "exit $GOT: $OUT"
fi

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
