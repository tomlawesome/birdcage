#!/bin/sh
# Render the GitLab release note from release:promote's dotenv report (#230).
#
#   scripts/release-note.sh PROMOTION_ENV
#
# PROMOTION_ENV carries RELEASE_TAG and RELEASE_<NAME>_REPO for the six images
# (the repository promoted, without the tag). The note goes to stdout. Any
# missing or empty value prints nothing on stdout, a reason on stderr, and
# exits 1, so release:gitlab fails before a release is made.
#
# The file is read as plain KEY=VALUE text, never sourced, so a value cannot
# run as shell.
set -eu

if [ $# -ne 1 ]; then
  echo "usage: release-note.sh PROMOTION_ENV" >&2
  exit 2
fi
file="$1"
if [ ! -r "$file" ] || [ -d "$file" ]; then
  echo "release-note: cannot read $file" >&2
  exit 1
fi

# get KEY: the value of the last KEY=... line, empty if absent.
get() {
  sed -n "s/^$1=//p" "$file" | tail -n 1 | tr -d '\r'
}

tag="$(get RELEASE_TAG)"
if [ -z "$tag" ]; then
  echo "release-note: RELEASE_TAG is empty or missing in $file" >&2
  exit 1
fi

lines=""
for name in BIRDCAGE MOCKINGBIRD NIGHTJAR SMB_LURE HOLDER OPENCANARY; do
  repo="$(get "RELEASE_${name}_REPO")"
  if [ -z "$repo" ]; then
    echo "release-note: RELEASE_${name}_REPO is empty or missing in $file" >&2
    exit 1
  fi
  lines="$lines- \`$repo:$tag\`
"
done

cat <<NOTE
Images published by digest, promoted from the build \`preview\` tested:

${lines}
Verify before you run any of them -- docs/releasing.md has the
commands. All six carry a key-based validation attestation; the keyless
countersignature is added by hand on GitHub after the cut.
NOTE
