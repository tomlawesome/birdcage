#!/usr/bin/env bash
# Tests for release-version.sh -- the one place the released version string
# and the build-stamp format are decided. Every fixture here uses --file
# against a throwaway file under a temp directory; the real tracked VERSION
# is never read or touched.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/release-version.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

ok() { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; shift; [ $# -gt 0 ] && printf '%s\n' "$*" | sed 's/^/       /'; fail=$((fail + 1)); }

# fixture <name> <content> -- writes content verbatim to $work/<name> and
# prints its path. Callers pass real newlines via $'...' quoting.
fixture() {
  local f="$work/$1"
  printf '%s' "$2" > "$f"
  printf '%s' "$f"
}

# run <args...> -- invokes the real script as a subprocess (it has no
# sourcing guard, so it is a program under test, not a library) and sets
# got/out.
run() { out="$("$script" "$@" 2>&1)" && got=0 || got=$?; }

assert_output() { # assert_output <want> <name> <args...>
  local want="$1" name="$2"
  shift 2
  run "$@"
  if [ "$got" = 0 ] && [ "$out" = "$want" ]; then
    ok "$name"
  else
    bad "$name" "exit $got, output=[$out], want output=[$want]"
  fi
}

assert_fails() { # assert_fails <name> <args...>
  local name="$1"
  shift
  run "$@"
  if [ "$got" = 1 ]; then
    ok "$name"
  else
    bad "$name" "exit $got, want 1; output=[$out]"
  fi
}

sha="$(printf 'd%.0s' $(seq 40))"

# --- a valid version prints as-is ----------------------------------------
f="$(fixture plain '1.2.3')"
assert_output '1.2.3' "a plain MAJOR.MINOR.PATCH version prints as-is" --file "$f"


f="$(fixture trailing-newline $'1.2.3\n')"
assert_output '1.2.3' "a trailing newline in the file is not part of the version" --file "$f"

f="$(fixture padded '  1.2.3  ')"
assert_output '1.2.3' "surrounding whitespace on the version line is trimmed" --file "$f"

# --- --tag prefixes v ------------------------------------------------------
f="$(fixture for-tag '1.2.3')"
assert_output 'v1.2.3' "--tag prefixes the version with v" --file "$f" --tag

# --- --stamp <sha> prints <version>+<first 8 of sha> -----------------------
f="$(fixture for-stamp '1.2.3')"
assert_output "1.2.3+${sha:0:8}" "--stamp prints the version plus the first 8 hex characters of the commit" --file "$f" --stamp "$sha"

# --- missing, empty, whitespace-only, malformed files: each exits 1 -------
assert_fails "a file that does not exist fails" --file "$work/does-not-exist"

f="$(fixture empty '')"
assert_fails "an empty file fails" --file "$f"

f="$(fixture whitespace-only $'   \n\t\n  \n')"
assert_fails "a whitespace-only file fails" --file "$f"

f="$(fixture two-versions $'1.2.3\n4.5.6\n')"
assert_fails "a file holding two versions fails" --file "$f"

f="$(fixture not-a-version 'not-a-version')"
assert_fails "a file holding something that is not a version fails" --file "$f"

f="$(fixture incomplete-version '1.2')"
assert_fails "a file holding an incomplete version (missing PATCH) fails" --file "$f"

# --- pre-release suffixes and a leading v are refused (owner, 2026-09-25) --
f="$(fixture prerelease '1.2.3-beta.4')"
assert_fails "a version with a -beta pre-release suffix fails" --file "$f"
run --file "$f"
case "$out" in
  *"preview"*) ok "the pre-release refusal says preview is the pre-release stage" ;;
  *) bad "the pre-release refusal says preview is the pre-release stage" "output=[$out]" ;;
esac

f="$(fixture rc '1.2.3-rc.1')"
assert_fails "a version with an -rc.1 pre-release suffix fails" --file "$f"
assert_fails "--tag on a pre-release version fails rather than printing a tag" --file "$f" --tag

f="$(fixture leading-v 'v1.2.3')"
assert_fails "a leading v in the file fails (the file holds 1.2.3; --tag adds the v)" --file "$f"

f="$(fixture build-metadata '1.2.3+abc')"
assert_fails "build metadata in the file fails (--stamp adds it)" --file "$f"

# --- --stamp with a malformed sha fails, even over a valid version file ---
f="$(fixture valid-for-bad-stamp '1.2.3')"
assert_fails "--stamp with a too-short sha fails" --file "$f" --stamp "abc123"
assert_fails "--stamp with uppercase hex fails" --file "$f" --stamp "$(printf 'D%.0s' $(seq 40))"
assert_fails "--stamp with non-hex characters fails" --file "$f" --stamp "$(printf 'z%.0s' $(seq 40))"

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
