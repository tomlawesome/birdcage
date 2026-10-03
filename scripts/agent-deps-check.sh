#!/bin/sh
# Every agent ships on a box outside birdcage's own trust boundary --
# Mockingbird runs on the machine the product expects to be attacked,
# Nightjar runs privileged with read access to the whole host. Nothing
# of the birdcage server belongs in either. This check is that image
# boundary expressed in code, once per agent kind -- ADR-0008 decision
# 4, generalised per ADR-0009 decision 6 ("the CI job runs it once per
# agent binary").
#
# internal/agent/* is always allowed (the shared enrolment/client
# plumbing #108 factored out of cmd/mockingbird so a second kind could
# reuse it). internal/selftest, internal/logging, internal/term and
# internal/hostmask are common to every kind: wire contracts and
# leveled-log/terminal formatting, not server logic; internal/hostmask
# is the mask-list constant the enrol renderer (cmd/birdcage, unfenced)
# and Nightjar's own startup check must never disagree about (issue
# #108), and it imports nothing else of birdcage's, so allowing it here
# costs nothing. Beyond that, each kind gets exactly the package that is
# actually its own: internal/opencanary for the honeypot,
# internal/scan for the scanner -- and explicitly NOT each other's, so a
# stray import cannot quietly link one kind's logic into the other
# kind's image.
set -eu

MODULE=github.com/tomlawesome/birdcage
CMD=${1:-./cmd/mockingbird}

COMMON="
$MODULE/internal/selftest
$MODULE/internal/logging
$MODULE/internal/term
$MODULE/internal/hostmask
"

case "$CMD" in
  */cmd/mockingbird)
    CMD_PKG="$MODULE/cmd/mockingbird"
    KIND_ALLOWED="$MODULE/internal/opencanary"
    ;;
  */cmd/nightjar)
    CMD_PKG="$MODULE/cmd/nightjar"
    KIND_ALLOWED="$MODULE/internal/scan"
    ;;
  *)
    echo "agent-deps-check.sh: unrecognised agent command $CMD (add a case for it)" >&2
    exit 1
    ;;
esac

ALLOWED="$COMMON
$CMD_PKG
$KIND_ALLOWED
"

unexpected=$(go list -deps "$CMD" | grep "^$MODULE/" | while read -r pkg; do
  case "$pkg" in
    "$MODULE"/internal/agent/*) continue ;;
  esac
  echo "$ALLOWED" | grep -qxF "$pkg" || echo "$pkg"
done)

if [ -n "$unexpected" ]; then
  echo "$CMD has pulled in birdcage packages that must not ship in its image"
  echo "(ADR-0009 decision 6, generalising ADR-0008 decision 4):"
  echo "$unexpected" | sed 's/^/  /'
  echo
  echo "Allowed for $CMD: internal/agent/*, internal/selftest,"
  echo "internal/logging, internal/term, internal/hostmask, $KIND_ALLOWED,"
  echo "and the command itself."
  exit 1
fi

echo "Agent dependency fence holds for $CMD."
