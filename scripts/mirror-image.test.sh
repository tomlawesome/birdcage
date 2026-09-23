#!/usr/bin/env bash
# Tests for mirror-image.sh. No Docker daemon and no registry are available
# in this environment, so these tests never call docker: they source the
# script (its sourcing guard keeps main() from running on import), override
# resolve_source_digest/run_mirror/resolve_dest_digest -- the only three
# functions that touch anything external -- with recording stubs, and drive
# main() for real over everything else: argument validation and the
# copy-then-reresolve round trip.
#
# The behaviour worth naming here is that a mismatch after the copy is
# refused exactly like publish-image.sh refuses a mismatched push-back --
# this script exists for the same reason, one registry hop further along.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/mirror-image.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

ok() { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; shift; [ $# -gt 0 ] && printf '%s\n' "$*" | sed 's/^/       /'; fail=$((fail + 1)); }

# shellcheck source=/dev/null
source "$script"

source_repo="registry.gitlab.tomlawson.io/ai/birdcage/birdcage"
dest_repo="ghcr.io/tomlawesome/birdcage"
digest="sha256:$(printf 'a%.0s' $(seq 64))"
other_digest="sha256:$(printf 'e%.0s' $(seq 64))"
tag="preview"

# Stub configuration, read by the stubs below each time main() calls them.
STUB_SOURCE_RC=0
STUB_SOURCE_DIGEST="$digest"
STUB_MIRROR_RC=0
STUB_DEST_RC=0
STUB_DEST_DIGEST="$digest"

resolve_source_digest() {
  : > "$work/resolve_source_digest.called"
  printf '%s\x1f%s' "$1" "$2" > "$work/resolve_source_digest.args"
  [ "$STUB_SOURCE_RC" = 0 ] || return "$STUB_SOURCE_RC"
  printf '%s' "$STUB_SOURCE_DIGEST"
}
run_mirror() {
  : > "$work/run_mirror.called"
  printf '%s\x1f%s' "$1" "$2" > "$work/run_mirror.args"
  return "$STUB_MIRROR_RC"
}
resolve_dest_digest() {
  : > "$work/resolve_dest_digest.called"
  printf '%s\x1f%s' "$1" "$2" > "$work/resolve_dest_digest.args"
  [ "$STUB_DEST_RC" = 0 ] || return "$STUB_DEST_RC"
  printf '%s' "$STUB_DEST_DIGEST"
}

reset_stubs() {
  STUB_SOURCE_RC=0
  STUB_SOURCE_DIGEST="$digest"
  STUB_MIRROR_RC=0
  STUB_DEST_RC=0
  STUB_DEST_DIGEST="$digest"
  rm -f "$work"/*.called "$work"/*.args
}

# run <args...> -- invokes main() with stdout and stderr combined, in a
# subshell (command substitution) so its `exit`, taken on every path, never
# kills the test runner.
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

result() { result_got="${1%%$'\x1f'*}"; result_out="${1#*$'\x1f'}"; }

# --- happy path: exactly the digest on stdout, exit 0 -----------------------
reset_stubs
result "$(run_stdout_only "$source_repo" "$tag" "$dest_repo")"
if [ "$result_got" = 0 ] && [ "$result_out" = "$digest" ] && [ -f "$work/run_mirror.called" ]; then
  ok "a valid mirror with a matching post-copy digest prints exactly the digest on stdout, exit 0"
else
  bad "a valid mirror with a matching post-copy digest prints exactly the digest on stdout, exit 0" "exit $result_got: $result_out"
fi

# --- run_mirror is called with the source digest reference and dest tag ----
reset_stubs
result "$(run "$source_repo" "$tag" "$dest_repo")"
if [ "$(cat "$work/run_mirror.args")" = "${source_repo}@${digest}"$'\x1f'"${dest_repo}:${tag}" ]; then
  ok "the copy is made from the resolved source digest to the destination tag"
else
  bad "the copy is made from the resolved source digest to the destination tag" "$(cat "$work/run_mirror.args" 2>/dev/null)"
fi

# --- argument count -----------------------------------------------------------
reset_stubs
result "$(run "$source_repo" "$tag")"
[ "$result_got" = 1 ] && ok "too few arguments is a usage error" || bad "too few arguments is a usage error" "exit $result_got: $result_out"

reset_stubs
result "$(run "$source_repo" "$tag" "$dest_repo" "extra")"
[ "$result_got" = 1 ] && ok "too many arguments is a usage error" || bad "too many arguments is a usage error" "exit $result_got: $result_out"

# --- repository shape ---------------------------------------------------------
reset_stubs
result "$(run "${source_repo}:othertag" "$tag" "$dest_repo")"
[ "$result_got" = 1 ] && ok "a source repository carrying a tag is a usage error" || bad "a source repository carrying a tag is a usage error" "exit $result_got: $result_out"

reset_stubs
result "$(run "${source_repo}@${digest}" "$tag" "$dest_repo")"
[ "$result_got" = 1 ] && ok "a source repository carrying a digest is a usage error" || bad "a source repository carrying a digest is a usage error" "exit $result_got: $result_out"

reset_stubs
result "$(run "$source_repo" "$tag" "${dest_repo}:othertag")"
[ "$result_got" = 1 ] && ok "a destination repository carrying a tag is a usage error" || bad "a destination repository carrying a tag is a usage error" "exit $result_got: $result_out"

reset_stubs
result "$(run "$source_repo" "$tag" "${dest_repo}@${digest}")"
[ "$result_got" = 1 ] && ok "a destination repository carrying a digest is a usage error" || bad "a destination repository carrying a digest is a usage error" "exit $result_got: $result_out"

# --- tag shape ------------------------------------------------------------
reset_stubs
result "$(run "$source_repo" ".starts-with-dot" "$dest_repo")"
[ "$result_got" = 1 ] && ok "a tag starting with '.' is a usage error" || bad "a tag starting with '.' is a usage error" "exit $result_got: $result_out"

# --- source does not resolve -----------------------------------------------
reset_stubs
STUB_SOURCE_RC=1
result "$(run "$source_repo" "$tag" "$dest_repo")"
if [ "$result_got" = 2 ] && [ ! -f "$work/run_mirror.called" ]; then
  ok "an unresolvable source tag is refused before anything is copied"
else
  bad "an unresolvable source tag is refused before anything is copied" "exit $result_got: $result_out"
fi

# --- source digest malformed ------------------------------------------------
reset_stubs
STUB_SOURCE_DIGEST="not-a-digest"
result "$(run "$source_repo" "$tag" "$dest_repo")"
if [ "$result_got" = 2 ] && [ ! -f "$work/run_mirror.called" ]; then
  ok "a malformed source digest is refused before anything is copied"
else
  bad "a malformed source digest is refused before anything is copied" "exit $result_got: $result_out"
fi

# --- the copy itself fails ---------------------------------------------------
reset_stubs
STUB_MIRROR_RC=1
result "$(run "$source_repo" "$tag" "$dest_repo")"
[ "$result_got" = 2 ] && ok "a failing copy is refused" || bad "a failing copy is refused" "exit $result_got: $result_out"

# --- destination does not resolve after the copy -----------------------------
reset_stubs
STUB_DEST_RC=1
result "$(run "$source_repo" "$tag" "$dest_repo")"
[ "$result_got" = 2 ] && ok "a destination tag that fails to resolve after copying is refused" || bad "a destination tag that fails to resolve after copying is refused" "exit $result_got: $result_out"

# --- destination digest malformed after the copy -----------------------------
reset_stubs
STUB_DEST_DIGEST="not-a-digest"
result "$(run "$source_repo" "$tag" "$dest_repo")"
[ "$result_got" = 2 ] && ok "a malformed destination digest after copying is refused" || bad "a malformed destination digest after copying is refused" "exit $result_got: $result_out"

# --- destination resolves to a different digest -------------------------------
reset_stubs
STUB_DEST_DIGEST="$other_digest"
result "$(run "$source_repo" "$tag" "$dest_repo")"
if [ "$result_got" = 2 ]; then
  ok "a destination tag resolving to a different digest than mirrored is refused"
else
  bad "a destination tag resolving to a different digest than mirrored is refused" "exit $result_got: $result_out"
fi

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
