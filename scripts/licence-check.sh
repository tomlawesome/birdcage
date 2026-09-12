#!/usr/bin/env bash
set -euo pipefail

# Gates the licences of the Go modules linked into the Birdcage binary --
# what `go build ./...` actually ships, not build- or test-only tooling.
# Host independent on purpose: both the `licence` GitHub Actions workflow
# (.github/workflows/licence.yml) and a future GitLab job call this same
# script.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POLICY_FILE="${POLICY_FILE:-$SCRIPT_DIR/../supply-chain/licence-policy.yml}"
GO_LICENSES_VERSION="${GO_LICENSES_VERSION:-v2.0.1}"

if [ ! -f "$POLICY_FILE" ]; then
  echo "licence-check: policy file not found: $POLICY_FILE" >&2
  exit 1
fi

# Extract the allow-licenses list entries (lines "  - X" under that key,
# up to the next top-level key) straight out of the policy file. No yq:
# the file's shape is simple and fixed enough for awk/sed.
ALLOWED_LICENSES="$(awk '
  /^allow-licenses:/ { in_list=1; next }
  /^[^[:space:]]/ { in_list=0 }
  in_list && /^[[:space:]]*-[[:space:]]*/ {
    sub(/^[[:space:]]*-[[:space:]]*/, "")
    print
  }
' "$POLICY_FILE" | sed 's/[[:space:]]*$//' | paste -sd, -)"

# An empty list must fail loudly rather than silently allowing every
# licence: go-licenses treats a blank --allowed_licenses as "no
# restriction", so a policy file that lost its entries (or whose key name
# drifted from what this script parses) must not pass quietly.
if [ -z "$ALLOWED_LICENSES" ]; then
  echo "licence-check: no allow-licenses entries found in $POLICY_FILE -- refusing to run with an empty allow-list" >&2
  exit 1
fi

echo "licence-check: allowed licences: $ALLOWED_LICENSES"

go install "github.com/google/go-licenses/v2@${GO_LICENSES_VERSION}"

# --ignore excludes only Birdcage's own module path from the check it
# runs against dependencies; it does not add Birdcage's own licence to the
# allow-list above, and Birdcage's own licence is not thereby "allowed"
# for any dependency that happens to share it. (There is no LICENSE file
# at the repository root at the time of writing -- check it if one is
# added later.)
go-licenses check ./... \
  --ignore github.com/tomlawesome/birdcage \
  --allowed_licenses="$ALLOWED_LICENSES"
