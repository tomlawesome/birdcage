#!/usr/bin/env bash
# Tests for release-record-policy.py (#215), the rule behind the
# `policy:release-record` job: the one release/vX.Y.Z MR per release goes
# straight into dev (owner answer 41b, exception recorded centrally) and may
# change only CHANGELOG.md and docs/releases/v<VERSION>.md.
#
# Written from the #215 final specification (section 3.3) before the script
# existed. Interface assumed by these tests: run in the MR's checkout with
# HEAD = the source tip; reads CI_MERGE_REQUEST_SOURCE_BRANCH_NAME and
# CI_MERGE_REQUEST_TARGET_BRANCH_NAME; `--remote NAME` (default origin);
# VERSION is read from <remote>/<target>; changed paths are
# `git diff --name-only <remote>/<target>...HEAD`. Exit 0 allowed, 1 refused.
#
# Real scratch git repositories, a local bare origin, no network.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/release-record-policy.py"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

export HOME="$work/home"; mkdir -p "$HOME"
export GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
unset CI CI_MERGE_REQUEST_SOURCE_BRANCH_NAME CI_MERGE_REQUEST_TARGET_BRANCH_NAME 2>/dev/null || true
git config --global user.name "Fixture Bot"
git config --global user.email "fixture-bot@example.invalid"
git config --global init.defaultBranch main

[ -f "$script" ] || echo "FAIL $script does not exist (tests written before the script, #215)"

# Base: origin with dev at VERSION 0.2.0, a change log and an older record.
b="$work/base"; mkdir -p "$b"
git init -q --bare "$b/origin.git"
git clone -q "$b/origin.git" "$b/wt" 2>/dev/null
mkdir -p "$b/wt/docs/releases"
echo "0.2.0" > "$b/wt/VERSION"
printf '# Changelog\n\n## [Unreleased]\n\n### Added\n\n- Thing.\n' > "$b/wt/CHANGELOG.md"
printf 'version: v0.1.0\n' > "$b/wt/docs/releases/v0.1.0.md"
printf 'template\n' > "$b/wt/docs/releases/TEMPLATE.md"
echo "readme" > "$b/wt/README.md"
git -C "$b/wt" add . && git -C "$b/wt" commit -q -m base
git -C "$b/wt" branch dev && git -C "$b/wt" push -q origin main dev 2>/dev/null
git -C "$b/wt" fetch -q origin

n=0
# case_run <name> <want> <source-branch> <target> <files...>
# Each file arg is a path the release branch changes (created or edited).
case_run() {
  local name="$1" want="$2" src="$3" tgt="$4" c out code=0 f
  shift 4
  n=$((n + 1)); c="$work/c$n"; cp -a "$b" "$c"
  git -C "$c/wt" remote set-url origin "$c/origin.git"
  git -C "$c/wt" checkout -q -b "$src" origin/dev
  for f in "$@"; do
    mkdir -p "$(dirname "$c/wt/$f")"; echo "edit $n" >> "$c/wt/$f"
  done
  git -C "$c/wt" add -A && git -C "$c/wt" commit -q -m "release edits" --allow-empty
  out="$(cd "$c/wt" && CI_MERGE_REQUEST_SOURCE_BRANCH_NAME="$src" \
    CI_MERGE_REQUEST_TARGET_BRANCH_NAME="$tgt" timeout 60 python3 "$script" 2>&1)" || code=$?
  if [ "$code" = "$want" ]; then echo "ok   $name"; pass=$((pass + 1))
  else echo "FAIL $name: exit $code (want $want)"; printf '%s\n' "$out" | sed 's/^/       /'; fail=$((fail + 1)); fi
}

case_run "record and change log into dev: allowed" 0 \
  release/v0.2.0 dev CHANGELOG.md docs/releases/v0.2.0.md
case_run "change log only: allowed" 0 release/v0.2.0 dev CHANGELOG.md
case_run "record only: allowed" 0 release/v0.2.0 dev docs/releases/v0.2.0.md
case_run "target preview: refused" 1 \
  release/v0.2.0 preview CHANGELOG.md docs/releases/v0.2.0.md
case_run "target a batch: refused" 1 release/v0.2.0 batch-b CHANGELOG.md
case_run "branch names another version than dev's VERSION: refused" 1 \
  release/v0.3.0 dev CHANGELOG.md docs/releases/v0.3.0.md
case_run "branch name with a suffix: refused" 1 \
  release/v0.2.0-extra dev CHANGELOG.md
case_run "branch name without the v: refused" 1 release/0.2.0 dev CHANGELOG.md
case_run "another path changed (README.md): refused" 1 \
  release/v0.2.0 dev CHANGELOG.md docs/releases/v0.2.0.md README.md
case_run "VERSION changed: refused (bumps go through a batch)" 1 \
  release/v0.2.0 dev CHANGELOG.md VERSION
case_run "an older record changed: refused" 1 \
  release/v0.2.0 dev docs/releases/v0.2.0.md docs/releases/v0.1.0.md
case_run "TEMPLATE.md changed: refused" 1 \
  release/v0.2.0 dev docs/releases/v0.2.0.md docs/releases/TEMPLATE.md
case_run "a file nested under docs/releases/: refused" 1 \
  release/v0.2.0 dev docs/releases/v0.2.0.md/extra.md

# Origin's own dev moved on: the diff is against the merge base, so dev's
# new commit is not counted as the branch's change.
n=$((n + 1)); c="$work/c$n"; cp -a "$b" "$c"
git -C "$c/wt" remote set-url origin "$c/origin.git"
git -C "$c/wt" checkout -q -b release/v0.2.0 origin/dev
echo x >> "$c/wt/CHANGELOG.md"; git -C "$c/wt" commit -q -am "change log"
git -C "$c/wt" checkout -q -b tmp origin/dev; echo y >> "$c/wt/README.md"
git -C "$c/wt" commit -q -am "dev moves"; git -C "$c/wt" push -q origin tmp:dev 2>/dev/null
git -C "$c/wt" fetch -q origin; git -C "$c/wt" checkout -q release/v0.2.0
code=0; out="$(cd "$c/wt" && CI_MERGE_REQUEST_SOURCE_BRANCH_NAME=release/v0.2.0 \
  CI_MERGE_REQUEST_TARGET_BRANCH_NAME=dev timeout 60 python3 "$script" 2>&1)" || code=$?
if [ "$code" = 0 ]; then echo "ok   dev moving on does not count against the branch"; pass=$((pass + 1))
else echo "FAIL dev moving on does not count against the branch: exit $code"; printf '%s\n' "$out" | sed 's/^/       /'; fail=$((fail + 1)); fi

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
