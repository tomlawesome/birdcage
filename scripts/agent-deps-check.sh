#!/bin/sh
# The agent ships in the Mockingbird container, which runs on the one machine
# the product expects to be attacked. Nothing of the birdcage server belongs
# in it. This check is that image boundary expressed in code -- ADR-0008
# decision 4.
#
# internal/selftest is deliberately allowed: it is the wire contract both
# ends share, a data-only package, not server logic. internal/logging and
# internal/term (#71) are allowed for the same reason: leveled-log line
# formatting and terminal-output escaping, not server logic or CA/key
# handling -- Mockingbird uses the same log handler birdcage does, just
# without its banner or configuration inventory.
set -eu

MODULE=github.com/tomlawesome/birdcage
CMD=${1:-./cmd/mockingbird}

ALLOWED="
$MODULE/cmd/mockingbird
$MODULE/internal/opencanary
$MODULE/internal/selftest
$MODULE/internal/logging
$MODULE/internal/term
"

unexpected=$(go list -deps "$CMD" | grep "^$MODULE/" | while read -r pkg; do
  case "$pkg" in
    "$MODULE"/internal/agent/*) continue ;;
  esac
  echo "$ALLOWED" | grep -qxF "$pkg" || echo "$pkg"
done)

if [ -n "$unexpected" ]; then
  echo "The agent has pulled in birdcage packages that must not ship in the"
  echo "Mockingbird container (ADR-0008 decision 4):"
  echo "$unexpected" | sed 's/^/  /'
  echo
  echo "Allowed: internal/agent/*, internal/opencanary, internal/selftest,"
  echo "internal/logging, internal/term, and the command itself."
  exit 1
fi

echo "Agent dependency fence holds."
