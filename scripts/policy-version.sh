#!/usr/bin/env bash
set -euo pipefail

# A single digest over every file that decides whether a built artefact is
# fit to publish (the list and why it exists: supply-chain/policy-files.txt).
# A release process can stamp this digest onto an artefact and later prove
# the artefact was validated under the rules live at build time -- not rules
# that have since been loosened -- because changing a byte in any listed
# file, or adding or removing one from the list, changes this digest.
#
# FAILS CLOSED on purpose: a policy version computed over a missing file, or
# over a list that lost its entries, would look trustworthy and would not
# be -- that is worse than refusing to print a digest at all. Every error
# path below exits non-zero rather than hashing whatever happened to exist.
#
# The digest does not depend on the order of lines in the list: each file is
# hashed into a "<file-sha256>  <path>" line first, and the set of those
# lines is sorted (LC_ALL=C, so the sort order cannot depend on the
# machine's locale) before the final hash. So re-ordering
# supply-chain/policy-files.txt for readability is not itself a policy
# change -- only adding, removing, or editing what it names is.
#
# Usage: scripts/policy-version.sh [--list PATH]
# Exit codes: 0 digest printed to stdout; 1 the list, or a file it names,
# is missing, unusable, or empty.

# repo_root is derived from this script's own location, not the caller's
# cwd, so the digest is the same whether this runs from the repo root, a
# subdirectory, or CI's working directory -- the same assumption
# scripts/coverage-floor.test.sh documents for coverage-floor.py.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"
list_file="$repo_root/supply-chain/policy-files.txt"

# --list is the only flag this takes, and exists so a test harness can
# point this at a fixture list without touching the real one.
while [ $# -gt 0 ]; do
  case "$1" in
    --list)
      if [ $# -lt 2 ]; then
        echo "policy-version: --list needs a path" >&2
        exit 1
      fi
      list_file="$2"
      shift 2
      ;;
    *)
      echo "policy-version: unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [ ! -f "$list_file" ]; then
  echo "policy-version: policy list not found: $list_file" >&2
  exit 1
fi

# Comments and blank lines are formatting, not policy, so only they are
# skipped here -- every other stray line still becomes a path and is
# checked (and, if unreadable, fails loudly) below rather than being
# silently dropped.
paths=()
while IFS= read -r line || [ -n "$line" ]; do
  trimmed="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  [ -z "$trimmed" ] && continue
  [ "${trimmed:0:1}" = "#" ] && continue
  paths+=("$trimmed")
done < "$list_file"

if [ ${#paths[@]} -eq 0 ]; then
  echo "policy-version: no usable paths in $list_file -- refusing to hash nothing" >&2
  exit 1
fi

# Each path is resolved against repo_root, never against whatever a listed
# path might mean relative to $list_file's own directory -- the list can
# live anywhere (a fixture, under --list) while still describing the one
# real tree.
lines=()
for path in "${paths[@]}"; do
  full="$repo_root/$path"
  if [ ! -f "$full" ]; then
    echo "policy-version: listed path is missing or not a regular file: $path" >&2
    exit 1
  fi
  hash="$(sha256sum "$full" | awk '{print $1}')"
  lines+=("$hash  $path")
done

printf '%s\n' "${lines[@]}" | LC_ALL=C sort | sha256sum | awk '{print $1}'
