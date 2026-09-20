#!/usr/bin/env bash
# The one place the released version string is decided, and the one place
# the build stamp's format is written down (issue #90).
#
# WHY A TRACKED FILE AND NOT THE GIT TAG. The version has to be stamped
# into the binaries at build time, on `preview`, and the whole point of the
# release design is that promotion moves that exact tested digest to the
# version tag rather than rebuilding it. So the tag cannot be the source:
# it does not exist yet when the bytes that carry the version are built.
# A tracked file makes the version an explicit, reviewable commit -- and
# `scripts/promote-release.sh` refuses to overwrite a version tag that
# already exists, so a forgotten bump fails closed rather than silently
# republishing.
#
# THE STAMP. Images are stamped `<version>+<short-commit>`, e.g.
# `0.1.0-beta+1a2b3c4d`. The `+<short-commit>` half is semver build
# metadata: it does not change which release this is, and it means every
# build says exactly which commit it came from, so two preview builds of
# one version are still told apart by what the binary itself reports.
# Nothing else may compute this string -- callers ask for it here.
#
# Usage:
#   scripts/release-version.sh                 print the version, e.g. 0.1.0-beta
#   scripts/release-version.sh --stamp <sha>   print <version>+<first 8 of sha>
#   scripts/release-version.sh --tag           print v<version>, the tag name
#
# Flags for tests only:
#   --file PATH   read the version from PATH instead of the tracked VERSION
#
# Exit codes: 0 printed; 1 the file is missing, empty, unreadable, holds
# more than one version, or holds something that is not a version.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"
version_file="$repo_root/VERSION"

fail() { printf 'release-version: %s\n' "$1" >&2; exit 1; }

mode="version"
commit=""

while [ $# -gt 0 ]; do
  case "$1" in
    --file)
      [ $# -ge 2 ] || fail "--file needs a path"
      version_file="$2"
      shift 2
      ;;
    --stamp)
      [ $# -ge 2 ] || fail "--stamp needs a commit sha"
      mode="stamp"
      commit="$2"
      shift 2
      ;;
    --tag)
      mode="tag"
      shift
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[ -f "$version_file" ] || fail "version file not found: $version_file"

# Read every non-blank line, not just the first: a file that has grown a
# second version is ambiguous, and picking one of them silently is how the
# wrong thing ships.
mapfile -t lines < <(grep -v '^[[:space:]]*$' "$version_file" || true)
[ "${#lines[@]}" -gt 0 ] || fail "version file is empty: $version_file"
[ "${#lines[@]}" -eq 1 ] || fail "version file holds ${#lines[@]} lines; it must hold exactly one version"

version="${lines[0]}"
version="${version#"${version%%[![:space:]]*}"}"
version="${version%"${version##*[![:space:]]}"}"

# MAJOR.MINOR.PATCH with an optional pre-release suffix (0.1.0-beta). No
# build metadata here: that half is this script's to add, from the commit.
if ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$'; then
  fail "not a version: '$version' (expected MAJOR.MINOR.PATCH with an optional -prerelease)"
fi

case "$mode" in
  version) printf '%s\n' "$version" ;;
  tag)     printf 'v%s\n' "$version" ;;
  stamp)
    printf '%s' "$commit" | grep -Eq '^[0-9a-f]{40}$' \
      || fail "not a commit sha: '$commit' (expected 40 lowercase hex characters)"
    printf '%s+%s\n' "$version" "${commit:0:8}"
    ;;
esac
