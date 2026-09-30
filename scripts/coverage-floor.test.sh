#!/usr/bin/env bash
# Tests for coverage-floor.py. A ratchet that cannot fail ratchets nothing,
# so every rule it enforces has a case here that proves it fires.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
checker="$here/coverage-floor.py"
repo_root="$(cd "$here/.." && pwd)"
module="$(awk '/^module /{print $2; exit}' "$repo_root/go.mod")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0; skip=0

# expect <want-exit> <name> <profile-content-or-PATH:x> <floors-content-or-PATH:x>
# The checker resolves the module path from go.mod above the current
# directory, so it is always run with repo_root as the working directory --
# same assumption ci-e2e-guard.py makes about .gitlab-ci.yml.
expect() {
  local want="$1" name="$2" profile="$3" floors="$4" got=0 out
  local prof_arg="$work/cover.out" floors_arg="$work/floors.yml"

  if [[ "$profile" == PATH:* ]]; then
    prof_arg="${profile#PATH:}"
  else
    printf '%s\n' "$profile" > "$prof_arg"
  fi
  if [[ "$floors" == PATH:* ]]; then
    floors_arg="${floors#PATH:}"
  else
    printf '%s\n' "$floors" > "$floors_arg"
  fi

  out="$(cd "$repo_root" && python3 "$checker" "$prof_arg" "$floors_arg" 2>&1)" || got=$?
  if [ "$got" = "$want" ]; then
    echo "ok   $name"; pass=$((pass + 1))
  else
    echo "FAIL $name: exit $got, want $want"; echo "$out" | sed 's/^/       /'
    fail=$((fail + 1))
  fi
}

# A Go coverage profile line is "file:pos numstmt count" -- count is a hit
# count for the whole block, not "how many of numstmt were covered": if
# count > 0 every statement in that block counts as covered, otherwise none
# do. So a fractional package percentage in a fixture needs two blocks, one
# hit and one not, not one line with a fractional-looking count.
#
# block <pkg-dir> <covered-stmts> <uncovered-stmts> -- one profile line for
# the covered statements (count 1) and, if any, one more for the uncovered
# ones (count 0), both attributed to <pkg-dir> via its synthetic file path.
block() {
  local pkg="$1" covered="$2" uncovered="$3" f
  f="$module/$pkg/x.go"
  printf '%s:1.1,2.1 %d 1\n' "$f" "$covered"
  if [ "$uncovered" -gt 0 ]; then
    printf '%s:3.1,4.1 %d 0\n' "$f" "$uncovered"
  fi
}

# A package well within its floor (80% against a floor of 79), used as
# filler in fixtures that need one clean package alongside the package
# under test, so the fixture's only problem is the one being tested for.
clean_block="$(block pkg/clean 8 2)"
clean_floor="  pkg/clean: 79"

expect 1 "a package under its floor is caught" \
"mode: set
$clean_block
$(block pkg/low 5 5)" \
"floors:
$clean_floor
  pkg/low: 90"

expect 1 "a package in the profile but missing from the floors file is caught" \
"mode: set
$clean_block
$(block pkg/unlisted 9 1)" \
"floors:
$clean_floor"

# The stale-ratchet boundary. These two cases sit either side of
# coverage-floor.py's RATCHET_SLACK, which is 5: 85% against a floor of 80
# is exactly at it and passes, 86% is one point past it and is caught. The
# number is written out here on purpose rather than read from the script --
# a test that follows the constant pins nothing. Moving RATCHET_SLACK means
# deliberately moving both of these, not discovering they still pass.
#
# The pair used to be 100%-against-90 and 82%-against-80, which proved only
# that something above the floor fires and something a little above it does
# not: every value from 3 to 5 would have passed both, so the boundary was
# never actually pinned, and two comments elsewhere in the repository said
# the slack was 2.
expect 0 "a package exactly at the ratchet slack (5 points) still passes" \
"mode: set
$clean_block
$(block pkg/edge 85 15)" \
"floors:
$clean_floor
  pkg/edge: 80"

expect 1 "a package one point past the ratchet slack is caught" \
"mode: set
$clean_block
$(block pkg/high 86 14)" \
"floors:
$clean_floor
  pkg/high: 80"

expect 2 "an unreadable profile fails red, not green" \
"PATH:$work/does-not-exist.out" \
"floors:
$clean_floor"

expect 2 "an unreadable floors file fails red, not green" \
"mode: set
$clean_block" \
"PATH:$work/does-not-exist.yml"

expect 0 "a clean pass across multiple packages" \
"mode: set
$clean_block
$(block pkg/ok 79 21)" \
"floors:
$clean_floor
  pkg/ok: 79"

# The real thing must pass: a fresh coverage run against this checkout,
# checked against the real, committed floors file.
#
# It only means anything where a Postgres is reachable. Without
# BIRDCAGE_TEST_DATABASE_URL, internal/db's Postgres tests skip themselves,
# the package reads about 44% against a floor of 67, and this check goes red
# on every clean workstation -- for the exact reason coverage-floors.yml's
# own header warns about, and with nothing wrong in the repository. A suite
# that cannot tell a broken repository from an unconfigured machine trains
# its reader to skim past the red, which is how a real one gets missed
# (issue 100).
#
# So: state the precondition, skip loudly when it is absent, and let CI's
# test:go job -- which does have a Postgres, and does set the variable --
# be where this runs for real.
if [ -z "${BIRDCAGE_TEST_DATABASE_URL:-}" ]; then
  echo "skip this repository's own coverage profile against its own floors:"
  echo "       BIRDCAGE_TEST_DATABASE_URL is not set, so internal/db's Postgres"
  echo "       tests would skip and the profile would read far under its floor"
  echo "       for that reason alone. CI's test:go job runs this for real."
  skip=$((skip + 1))
elif ! command -v go >/dev/null 2>&1; then
  echo "skip this repository's own coverage profile against its own floors: no go toolchain"
  skip=$((skip + 1))
else
  echo "generating a real coverage profile (go test ./..., can take a minute)..."
  real_profile="$work/real-cover.out"
  if ! (cd "$repo_root" && go test ./... -coverprofile="$real_profile" >/dev/null 2>&1); then
    echo "FAIL go test ./... did not run cleanly; cannot check the real profile"
    fail=$((fail + 1))
  elif (cd "$repo_root" && python3 "$checker" "$real_profile" "supply-chain/coverage-floors.yml"); then
    echo "ok   this repository's own coverage profile passes its own floors"
    pass=$((pass + 1))
  else
    echo "FAIL this repository's own coverage profile does not pass its own floors"
    fail=$((fail + 1))
  fi
fi

echo "$pass passed, $fail failed, $skip skipped"
[ "$fail" = 0 ]
