#!/usr/bin/env bash
# journey.sh -- the few helpers every scripts/e2e/*.sh journey shares:
# numbered steps, an assertion that names the step it failed in, and a
# bounded poll.
#
# Source this from a per-journey script rather than editing it. The
# point is that #79 (port scan), #80 (mail) and #81 (dashboard) each add
# a short file next to this one, not that this grows into a second test
# framework -- the same rule mikroview's live-browser.mjs states for its
# scenarios.
#
#   . "$(dirname "$0")/journey.sh"
#   step "the canary answers FTP"
#   poll 30 helper "nc -w 5 $E2E_CANARY 21 < /dev/null" \
#     || fail "nothing answered on port 21" "$E2E_CANARY"
#   finish
#
# A failure prints the step it happened in, what was expected, and the
# log of every container named on the `fail` line, then exits 1. It
# never exits 0 on the way past: `set -eu` is on in every journey, and
# nothing here swallows a non-zero status.

[ -n "${E2E_STACK:-}" ] || {
  echo "E2E_STACK unset -- run: eval \"\$(scripts/e2e/stack.sh up)\"" >&2
  exit 2
}

JOURNEY_NAME="$(basename "$0" .sh)"
STEP_NUMBER=0
STEP_NAME="(no step started)"

echo "== $JOURNEY_NAME =="

# step announces what is about to be attempted. Every step says what it
# is doing before it does it, so a run that hangs still shows where.
step() {
  STEP_NUMBER=$((STEP_NUMBER + 1))
  STEP_NAME="$1"
  echo "step $STEP_NUMBER ($STEP_NAME): starting"
}

ok() { echo "  ok   $*"; }

# fail names the step, says what went wrong, and dumps the log of each
# container named after the message (birdcage when none is named) --
# "Step 4 (FTP hit) failed: /api/alerts never contained the event",
# never a bare exit 1.
fail() {
  local message="$1"
  shift
  echo "step $STEP_NUMBER ($STEP_NAME) FAILED: $message" >&2
  local container
  for container in "${@:-$E2E_BIRDCAGE}"; do
    echo "--- docker logs $container ---" >&2
    docker logs "$container" >&2 || echo "(no log: $container does not exist)" >&2
  done
  exit 1
}

# helper runs a shell command inside the harness's helper container: on
# the stack's network, with curl, openssl, jq and sqlite, and with
# /tls, /work, /data and /state mounted (see stack.sh).
helper() { "$E2E_STACK" helper "$@"; }

# poll retries a command until it succeeds, bounded. The bound is part
# of the failure message the caller writes, so a journey never waits
# forever and never reports "it failed" without saying how long it
# waited. The command is run as given, never through eval: a journey's
# assertions are full of quotes and backslashes, and an eval layer is
# where one of them silently becomes a command that always succeeds.
#
#   poll 30 helper 'curl ... | grep -q ftp' || fail "... after 30 attempts"
poll() {
  local attempts="$1" attempt
  shift
  for attempt in $(seq 1 "$attempts"); do
    if "$@" >/dev/null 2>&1; then
      ok "succeeded on attempt $attempt of $attempts"
      return 0
    fi
    sleep 1
  done
  return 1
}

finish() {
  echo "RESULT: PASS ($JOURNEY_NAME, $STEP_NUMBER steps)"
}
