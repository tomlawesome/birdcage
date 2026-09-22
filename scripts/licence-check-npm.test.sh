#!/usr/bin/env bash
# Tests for licence-check-npm.sh / licence-check-npm.py. A guard that
# cannot fail guards nothing, so every rule it enforces has a case here
# that proves it fires.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
checker="$here/licence-check-npm.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0; skip=0

# mkpkg <node_modules_dir> <name> <version-dir> <package.json-body>
# name may be "scope/pkg" for a scoped package.
mkpkg() {
  local nm="$1" name="$2" body="$3"
  mkdir -p "$nm/$name"
  printf '%s\n' "$body" > "$nm/$name/package.json"
}

# expect <want-exit> <name> <node_modules_dir> <policy_file>
expect() {
  local want="$1" name="$2" nm="$3" pol="$4" got=0 out
  out="$(NODE_MODULES_DIR="$nm" POLICY_FILE="$pol" "$checker" 2>&1)" || got=$?
  if [ "$got" = "$want" ]; then
    echo "ok   $name"; pass=$((pass + 1))
  else
    echo "FAIL $name: exit $got, want $want"; echo "$out" | sed 's/^/       /'
    fail=$((fail + 1))
  fi
}

good_policy="$work/good-policy.yml"
printf '%s\n' 'allow-npm-licenses:
  - MIT
  - Apache-2.0' > "$good_policy"

nm="$work/clean/node_modules"
mkpkg "$nm" foo '{"name":"foo","version":"1.0.0","license":"MIT"}'
mkpkg "$nm" bar '{"name":"bar","version":"2.0.0","license":"Apache-2.0"}'
expect 0 "a clean tree with allowed licences passes" "$nm" "$good_policy"

nm="$work/disallowed/node_modules"
mkpkg "$nm" foo '{"name":"foo","version":"1.0.0","license":"MIT"}'
mkpkg "$nm" evil '{"name":"evil","version":"3.1.4","license":"GPL-3.0"}'
expect 1 "a disallowed licence is caught" "$nm" "$good_policy"

nm="$work/missing/node_modules"
mkpkg "$nm" foo '{"name":"foo","version":"1.0.0","license":"MIT"}'
mkpkg "$nm" mystery '{"name":"mystery","version":"0.1.0"}'
expect 1 "a package with no licence field at all is caught" "$nm" "$good_policy"

nm="$work/empty-licenses/node_modules"
mkpkg "$nm" mystery '{"name":"mystery","version":"0.1.0","licenses":[]}'
expect 1 "an empty legacy licenses array counts as no licence field" "$nm" "$good_policy"

expect 2 "an absent node_modules fails red, not green" "$work/does-not-exist" "$good_policy"

empty_policy="$work/empty-policy.yml"
printf '%s\n' 'allow-npm-licenses: []' > "$empty_policy"
nm="$work/anyclean/node_modules"
mkpkg "$nm" foo '{"name":"foo","version":"1.0.0","license":"MIT"}'
expect 1 "an empty allow-list refuses to run" "$nm" "$empty_policy"

no_key_policy="$work/no-key-policy.yml"
printf '%s\n' 'something-else: []' > "$no_key_policy"
expect 1 "a policy file missing the allow-npm-licenses key refuses to run" "$nm" "$no_key_policy"

nm="$work/legacy-array/node_modules"
mkpkg "$nm" foo '{"name":"foo","version":"1.0.0","licenses":[{"type":"MIT"}]}'
expect 0 "the legacy licenses array form (object entries) is read" "$nm" "$good_policy"

nm="$work/legacy-array-strings/node_modules"
mkpkg "$nm" foo '{"name":"foo","version":"1.0.0","licenses":["MIT"]}'
expect 0 "the legacy licenses array form (string entries) is read" "$nm" "$good_policy"

nm="$work/legacy-array-bad/node_modules"
mkpkg "$nm" foo '{"name":"foo","version":"1.0.0","licenses":[{"type":"GPL-3.0"}]}'
expect 1 "a disallowed licence in the legacy array form is caught" "$nm" "$good_policy"

nm="$work/object-form/node_modules"
mkpkg "$nm" foo '{"name":"foo","version":"1.0.0","license":{"type":"Apache-2.0"}}'
expect 0 "the {type: ...} object form is read" "$nm" "$good_policy"

nm="$work/object-form-bad/node_modules"
mkpkg "$nm" foo '{"name":"foo","version":"1.0.0","license":{"type":"GPL-3.0"}}'
expect 1 "a disallowed licence in the {type: ...} object form is caught" "$nm" "$good_policy"

# Scoped packages (@scope/name) are a real, common shape in this tree
# (e.g. @sveltejs/*) and live one directory deeper than a plain package.
nm="$work/scoped/node_modules"
mkpkg "$nm" "@scope/pkg" '{"name":"@scope/pkg","version":"1.0.0","license":"MIT"}'
expect 0 "a scoped package is found and checked" "$nm" "$good_policy"

# A nested node_modules (npm's way of resolving a version conflict) is a
# real installed package too, and must not be skipped just because it is
# not a direct child of the top-level node_modules.
nm="$work/nested/node_modules"
mkpkg "$nm" foo '{"name":"foo","version":"1.0.0","license":"MIT"}'
mkpkg "$nm/foo/node_modules" evil '{"name":"evil","version":"9.9.9","license":"GPL-3.0"}'
expect 1 "a disallowed licence in a nested node_modules is caught" "$nm" "$good_policy"

# The real thing must pass -- where there is a real thing to check. A fresh
# checkout and every worktree have no frontend/node_modules, so without this
# guard the suite fails there with nothing installed to examine, which says
# nothing about the checker or the repository. CI's frontend job runs the
# real checker after its own `npm ci`, and that is where this is covered.
repo_root="$(cd "$here/.." && pwd)"
if [ ! -d "$repo_root/frontend/node_modules" ]; then
  echo "skip this repository's own frontend/node_modules: not installed here."
  echo "       Run npm ci in frontend/ to check it locally; CI's frontend job"
  echo "       runs the real checker against its own install."
  skip=$((skip + 1))
elif (cd "$repo_root" && "$checker" >/dev/null 2>&1); then
  echo "ok   this repository's own frontend/node_modules passes"; pass=$((pass + 1))
else
  echo "FAIL this repository's own frontend/node_modules does not pass"; fail=$((fail + 1))
fi

echo "$pass passed, $fail failed, $skip skipped"
[ "$fail" = 0 ]
