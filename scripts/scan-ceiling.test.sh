#!/usr/bin/env bash
# Tests for scan-ceiling.py (#199 slice 1), written from the specification
# before the script exists. A ratchet that cannot fail ratchets nothing, so
# every rule has a case here that proves it fires.
#
# Interface under test:
#   scan-ceiling.py check   --key KEY --count N [--ceilings FILE]
#   scan-ceiling.py compare --ceilings FILE (--base FILE | --base-ref REF)
# The ceilings file is a flat `ceilings:` mapping of `key: integer  # note`,
# the coverage-floors.yml shape turned round. Exit codes as coverage-floor.py:
# 0 clean, 1 a rule fired, 2 an input could not be read or parsed.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
tool="$here/scan-ceiling.py"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

ceil="$work/ceilings.yml"
cat > "$ceil" <<'Y'
# ceilings, count measured date, issue number
ceilings:
  shellcheck: 41      # 41 measured 2026-11-18 (#199)
  ruff-S: 10          # 10 measured 2026-11-18 (#199)
  actionlint: 0       # 0 measured 2026-11-18 (#199)
Y

expect() { # want-exit name args...
  local want="$1" name="$2" got=0 out
  shift 2
  out="$(python3 "$tool" "$@" 2>&1)" || got=$?
  if [ "$got" = "$want" ]; then
    echo "ok   $name"; pass=$((pass + 1))
  else
    echo "FAIL $name: exit $got, want $want"; echo "$out" | sed 's/^/       /'
    fail=$((fail + 1))
  fi
}

# --- check: over, at, within slack, stale
expect 0 "count equal to the ceiling passes" check --key shellcheck --count 41 --ceilings "$ceil"
expect 1 "count above the ceiling fails (a new finding)" check --key shellcheck --count 42 --ceilings "$ceil"
expect 0 "count 5 below the ceiling passes (the slack)" check --key shellcheck --count 36 --ceilings "$ceil"
expect 1 "count 6 below the ceiling fails (stale ratchet)" check --key shellcheck --count 35 --ceilings "$ceil"
expect 0 "ceiling 0 with count 0 passes" check --key actionlint --count 0 --ceilings "$ceil"
expect 1 "ceiling 0 with any finding fails" check --key actionlint --count 1 --ceilings "$ceil"
expect 0 "a small ceiling with count 0 is within the slack" check --key ruff-S --count 5 --ceilings "$ceil"
expect 1 "a key missing from the file fails" check --key no-such-tool --count 0 --ceilings "$ceil"

# The failure message names the key and the numbers, so a reviewer can act.
out="$(python3 "$tool" check --key shellcheck --count 42 --ceilings "$ceil" 2>&1 || true)"
if grep -q "shellcheck" <<<"$out" && grep -q "42" <<<"$out" && grep -q "41" <<<"$out"; then
  echo "ok   the over-ceiling message names the key, the count and the ceiling"; pass=$((pass + 1))
else
  echo "FAIL the over-ceiling message names the key, the count and the ceiling"; echo "$out" | sed 's/^/       /'
  fail=$((fail + 1))
fi

# --- unreadable input fails red, never quietly green
expect 2 "a missing ceilings file is exit 2" check --key shellcheck --count 1 --ceilings "$work/absent.yml"
printf 'not: [a mapping of ceilings\n' > "$work/garbled.yml"
expect 2 "an unparsable ceilings file is exit 2" check --key shellcheck --count 1 --ceilings "$work/garbled.yml"
printf 'ceilings:\n  shellcheck: many\n' > "$work/nonint.yml"
expect 2 "a non-integer ceiling is exit 2" check --key shellcheck --count 1 --ceilings "$work/nonint.yml"
expect 2 "a non-integer count is exit 2" check --key shellcheck --count lots --ceilings "$ceil"

# --- compare: a ceiling may only go down
lowered="$work/lowered.yml"; sed 's/shellcheck: 41 /shellcheck: 30 /' "$ceil" > "$lowered"
raised="$work/raised.yml";   sed 's/shellcheck: 41 /shellcheck: 42 /' "$ceil" > "$raised"
expect 0 "compare: an unchanged file passes" compare --ceilings "$ceil" --base "$ceil"
expect 0 "compare: a lowered ceiling passes" compare --ceilings "$lowered" --base "$ceil"
expect 1 "compare: a raised ceiling is refused" compare --ceilings "$raised" --base "$ceil"
newkey="$work/newkey.yml"; { cat "$ceil"; echo "  zizmor-high: 3      # 3 measured 2026-11-18 (#199)"; } > "$newkey"
expect 0 "compare: a new tool key may be added" compare --ceilings "$newkey" --base "$ceil"
expect 2 "compare: an unreadable base is exit 2" compare --ceilings "$ceil" --base "$work/absent.yml"

# --- compare against a git ref: the target branch in a merge request, the
# previous commit on a branch push with no target.
repo="$work/repo"
mkdir -p "$repo/supply-chain"
git -C "$repo" init -q -b main
git -C "$repo" config user.email t@example.invalid
git -C "$repo" config user.name tester
git -C "$repo" config commit.gpgsign false
cp "$ceil" "$repo/supply-chain/scan-ceilings.yml"
git -C "$repo" add -A && git -C "$repo" commit -q -m base
cp "$raised" "$repo/supply-chain/scan-ceilings.yml"
git -C "$repo" commit -q -am raise
ref_expect() { # want name ref
  local got=0 out
  out="$(cd "$repo" && python3 "$tool" compare --ceilings supply-chain/scan-ceilings.yml --base-ref "$3" 2>&1)" || got=$?
  if [ "$got" = "$1" ]; then echo "ok   $2"; pass=$((pass + 1))
  else echo "FAIL $2: exit $got, want $1"; echo "$out" | sed 's/^/       /'; fail=$((fail + 1)); fi
}
ref_expect 1 "compare --base-ref: a ceiling raised since the previous commit is refused" HEAD~1
ref_expect 0 "compare --base-ref: the file against itself passes" HEAD
ref_expect 2 "compare --base-ref: an unknown ref is exit 2" refs/heads/no-such-branch

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
