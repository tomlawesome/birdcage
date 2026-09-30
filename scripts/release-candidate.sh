#!/bin/sh
# Which commit release:promote releases (issue #154). Prints its full sha
# on stdout; refuses, naming what it tried, when there is none or more
# than one.
#
# A validated build exists only for a commit that went through preview,
# published as <repository>:sha-<commit>. `main`'s head is either that
# commit itself (a fast-forward) or a merge of it into `main`. For a
# merge, the first parent is `main`'s previous tip and is never the
# release: an earlier fast-forward release leaves it with a build of its
# own, and picking it would promote the last release again. So the
# candidates are HEAD, then every parent after the first -- more than one
# only for an octopus merge, where two with a build is ambiguous and
# refused rather than guessed.
#
# Usage: scripts/release-candidate.sh <repository>
#   run inside the checkout, with every parent of HEAD reachable.
set -eu

repo="${1:-}"
if [ -z "$repo" ]; then
  echo "usage: $0 <repository>" >&2
  exit 2
fi

has_build() {
  docker buildx imagetools inspect "${repo}:sha-$1" >/dev/null 2>&1
}

# shellcheck disable=SC2046 # word-splitting the sha list is the point
set -- $(git rev-list --parents -n1 HEAD)
head="$1"
shift
if has_build "$head"; then
  echo "$head"
  exit 0
fi

tried="$head"
found=""
count=0
if [ $# -gt 0 ]; then
  shift # the first parent: main's previous tip, never the release
fi
for parent in "$@"; do
  tried="$tried $parent"
  if has_build "$parent"; then
    found="$parent"
    count=$((count + 1))
  fi
done

if [ "$count" -eq 1 ]; then
  echo "$found"
  exit 0
fi
if [ "$count" -gt 1 ]; then
  echo "more than one merged-in parent has a validated build; refusing to guess which to release: $tried" >&2
  exit 1
fi
echo "no validated build was published for any of: $tried" >&2
echo "A release can only promote a digest that went through preview." >&2
exit 1
