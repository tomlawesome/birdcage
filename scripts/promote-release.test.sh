#!/usr/bin/env bash
# Tests for promote-release.sh. No docker daemon and no registry are
# available in this environment, so these tests never call docker for real:
# they source the script (its sourcing guard keeps main() from running on
# import) and replace resolve_tag_digest, run_verifier, image_reported_version
# and create_version_tag with fixtures, then drive main() for real over
# everything else -- argument validation, the version-tag-already-exists
# refusal, verifier exit-code propagation, and the post-creation re-resolve
# check.
#
# scripts/release-version.sh itself is NOT stubbed: it only reads the
# repository's tracked VERSION file, touches no registry and no daemon, so
# these tests read the real version/tag/stamp through it and use those
# values as ground truth, rather than guessing what VERSION currently holds.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/promote-release.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

ok() { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; shift; [ $# -gt 0 ] && printf '%s\n' "$*" | sed 's/^/       /'; fail=$((fail + 1)); }

# shellcheck source=/dev/null
source "$script"

repo="ghcr.io/tomlawesome/birdcage"
commit="$(printf 'b%.0s' $(seq 40))"
digest_ok="sha256:$(printf 'a%.0s' $(seq 64))"
other_digest="sha256:$(printf 'e%.0s' $(seq 64))"

# The real, unstubbed script is the ground truth for what a happy path must
# produce -- never a second guess at what VERSION currently holds.
version="$("$here/release-version.sh")"
tag="$("$here/release-version.sh" --tag)"
stamp="$("$here/release-version.sh" --stamp "$commit")"

# default_stubs -- the happy-path fixture wiring shared by most cases:
#   - the anchor tag (repo:sha-<commit>) always resolves to digest_ok
#   - the version tag (repo:<tag>) resolves only once create_version_tag has
#     "run" (marked by $work/tag_created), proving the not-yet-created and
#     just-created cases are told apart correctly
#   - create_version_tag and run_verifier record what they were called with,
#     so wiring can be checked, not just exit codes
default_stubs() {
  resolve_tag_digest() {
    local ref="$1"
    case "$ref" in
      "${repo}:sha-${commit}")
        printf '%s\n' "$digest_ok"; return 0 ;;
      "${repo}:${tag}")
        if [ -f "$work/tag_created" ]; then
          printf '%s\n' "$digest_ok"; return 0
        fi
        return 1 ;;
      *) return 1 ;;
    esac
  }
  create_version_tag() {
    printf '%s %s %s' "$1" "$2" "$3" > "$work/create_args"
    : > "$work/tag_created"
    return 0
  }
  run_verifier() {
    printf '%s %s %s' "$1" "$2" "$3" > "$work/verifier_args"
    return 0
  }
  image_reported_version() { printf '%s\n' "$stamp"; }
}

reset() {
  rm -f "$work/tag_created" "$work/create_args" "$work/verifier_args"
  default_stubs
}

# assert_exit <want-exit> <name> <args...> -- runs main() with the current
# function overrides, in a subshell (command substitution) so main()'s exit
# calls never kill the test runner. Sets last_stdout/last_stderr for callers
# that need to check them too.
assert_exit() {
  local want="$1" name="$2" err_file got out
  shift 2
  err_file="$(mktemp)"
  out="$(main "$@" 2>"$err_file")" && got=0 || got=$?
  last_stdout="$out"
  last_stderr="$(cat "$err_file")"
  rm -f "$err_file"
  if [ "$got" = "$want" ]; then
    ok "$name"
  else
    bad "$name" "exit $got, want $want; stdout=[$last_stdout] stderr=[$last_stderr]"
  fi
}

assert_not_called() { # assert_not_called <marker-file> <name>
  if [ ! -f "$1" ]; then
    ok "$2"
  else
    bad "$2" "marker file $1 exists: the stub it belongs to was called"
  fi
}

# --- happy path, without --expect-stamp ---------------------------------
reset
assert_exit 0 "happy path without --expect-stamp promotes and prints the digest" "$repo" "$commit"
if [ "$last_stdout" = "$digest_ok" ]; then
  ok "the promoted digest, and only it, is printed on stdout"
else
  bad "the promoted digest, and only it, is printed on stdout" "got: [$last_stdout]"
fi
if [ -f "$work/create_args" ] && [ "$(cat "$work/create_args")" = "$repo $tag $digest_ok" ]; then
  ok "create_version_tag is called with the repo, the tag and the anchor digest"
else
  bad "create_version_tag is called with the repo, the tag and the anchor digest" "$(cat "$work/create_args" 2>/dev/null)"
fi
if [ -f "$work/verifier_args" ] && [ "$(cat "$work/verifier_args")" = "$repo $digest_ok $commit" ]; then
  ok "run_verifier is called with the repo, the anchor digest and the commit"
else
  bad "run_verifier is called with the repo, the anchor digest and the commit" "$(cat "$work/verifier_args" 2>/dev/null)"
fi
case "$last_stderr" in
  *"$version"*) ok "the commentary on stderr names the version being released" ;;
  *) bad "the commentary on stderr names the version being released" "stderr=[$last_stderr]" ;;
esac

# --- happy path, with --expect-stamp ------------------------------------
reset
assert_exit 0 "happy path with --expect-stamp promotes and prints the digest" --expect-stamp "$repo" "$commit"
if [ "$last_stdout" = "$digest_ok" ]; then
  ok "--expect-stamp still prints only the digest on a matching stamp"
else
  bad "--expect-stamp still prints only the digest on a matching stamp" "got: [$last_stdout]"
fi

# --- the version tag already exists: never overwritten ------------------
reset
resolve_tag_digest() {
  case "$1" in
    "${repo}:sha-${commit}") printf '%s\n' "$digest_ok"; return 0 ;;
    "${repo}:${tag}") printf '%s\n' "$other_digest"; return 0 ;;
    *) return 1 ;;
  esac
}
assert_exit 3 "a version tag that already exists is refused, not overwritten" "$repo" "$commit"
assert_not_called "$work/create_args" "the tag-creation stub is never called when the version tag already exists"

# --- the anchor tag does not resolve -------------------------------------
reset
resolve_tag_digest() { return 1; }
assert_exit 11 "an anchor tag that does not resolve is refused: never published through the validated path" "$repo" "$commit"
assert_not_called "$work/create_args" "the tag-creation stub is never called when the anchor tag does not resolve"

# --- verifier exit codes are propagated unchanged ------------------------
for code in 10 11 12 13; do
  reset
  eval "run_verifier() { return $code; }"
  assert_exit "$code" "verifier exit $code is propagated unchanged" "$repo" "$commit"
  assert_not_called "$work/create_args" "the tag-creation stub is never called when the verifier refuses (exit $code)"
done

# --- --expect-stamp mismatch ----------------------------------------------
reset
image_reported_version() { printf '%s\n' "not-the-expected-stamp"; }
assert_exit 4 "an embedded stamp that does not match the version being released is refused" --expect-stamp "$repo" "$commit"
assert_not_called "$work/create_args" "the tag-creation stub is never called on a stamp mismatch"

# --- tag creation fails ----------------------------------------------------
reset
create_version_tag() { return 1; }
assert_exit 2 "a failing tag creation is refused" "$repo" "$commit"

# --- tag resolves back to a different digest ------------------------------
reset
resolve_tag_digest() {
  case "$1" in
    "${repo}:sha-${commit}") printf '%s\n' "$digest_ok"; return 0 ;;
    "${repo}:${tag}")
      if [ -f "$work/tag_created" ]; then
        printf '%s\n' "$other_digest"; return 0
      fi
      return 1 ;;
    *) return 1 ;;
  esac
}
assert_exit 2 "a tag that resolves back to a different digest than promoted is refused" "$repo" "$commit"

# --- usage errors ----------------------------------------------------------
reset
assert_exit 1 "no arguments at all is a usage error"
assert_exit 1 "a commit argument missing is a usage error" "$repo"
assert_exit 1 "an extra positional argument is a usage error" "$repo" "$commit" "extra"
assert_exit 1 "an unknown flag is a usage error" --not-a-real-flag "$repo" "$commit"
assert_exit 1 "a repository carrying a tag is a usage error" "${repo}:preview" "$commit"
assert_exit 1 "a repository carrying a digest is a usage error" "${repo}@${digest_ok}" "$commit"
assert_exit 1 "a commit that is too short is a usage error" "$repo" "abc123"
assert_exit 1 "a commit with uppercase hex is a usage error" "$repo" "$(printf 'B%.0s' $(seq 40))"
assert_exit 1 "a commit with non-hex characters is a usage error" "$repo" "$(printf 'z%.0s' $(seq 40))"

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
