#!/usr/bin/env bash
# Tests for agent-deps-check.sh: the ADR-0008/ADR-0009 image-boundary
# fence, generalised in #108 to run once per agent kind. Run from
# anywhere -- it cd's to the repository root, since `go list -deps` and
# the script's own default ./cmd/mockingbird are both relative to that.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"
script="$here/agent-deps-check.sh"
pass=0; fail=0

ok() { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; shift; [ $# -gt 0 ] && printf '%s\n' "$*" | sed 's/^/       /'; fail=$((fail + 1)); }

cd "$repo_root"

# Both real agent binaries must pass their own fence -- this is the
# actual gate lint:agent-deps runs in CI, exercised here the same way.
for cmd in ./cmd/mockingbird ./cmd/nightjar; do
  if out="$(bash "$script" "$cmd" 2>&1)"; then
    ok "$cmd holds its fence"
  else
    bad "$cmd holds its fence" "$out"
  fi
done

# An unrecognised command path must fail loudly rather than silently
# defaulting to one kind's allowed set (which would let a third binary
# ship unchecked).
if out="$(bash "$script" ./cmd/birdcage 2>&1)"; then
  bad "unrecognised command is refused" "expected non-zero exit, got success: $out"
else
  ok "unrecognised command is refused"
fi

# Cross-kind isolation: each binary's dependency closure must not carry
# the other kind's own package (ADR-0009 decision 6, "internal/opencanary
# must NOT be in the scanner's allowed set").
module="$(awk '/^module /{print $2; exit}' go.mod)"
if go list -deps ./cmd/mockingbird | grep -qxF "$module/internal/scan"; then
  bad "mockingbird does not import internal/scan" "it does"
else
  ok "mockingbird does not import internal/scan"
fi
if go list -deps ./cmd/nightjar | grep -qxF "$module/internal/opencanary"; then
  bad "nightjar does not import internal/opencanary" "it does"
else
  ok "nightjar does not import internal/opencanary"
fi

echo "agent-deps-check.test.sh: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
