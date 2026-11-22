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
    # Setup and unlock codes (#8) blanked, as stack.sh's birdcage_log
    # does: either one hands whoever reads the log an admin account.
    { docker logs "$container" 2>&1 || echo "(no log: $container does not exist)"; } \
      | sed -E 's/with (setup|unlock) code [A-Za-z0-9-]+/with \1 code <redacted>/g' >&2
  done
  fail_diagnostics "$@"
  exit 1
}

# fail_diagnostics is what fail() adds after the per-container dump, so a
# red pipeline shows enough to diagnose (pipeline 5115's failures did not):
# which container holds which address, the tail of every other stack
# container's log, and the alerts and canaries birdcage stores. Every
# section is bounded and ends in `|| true`: a dump must never fail the dump.
# Sign-in tokens never reach the log: DASHBOARD_AUTH is curl's `-H @file`,
# so the token is read inside the helper container; nothing here prints it
# or the auth file.
fail_diagnostics() {
  local prefix="${E2E_PREFIX:-}" c
  if [ -z "$prefix" ]; then
    echo "--- diagnostics skipped: E2E_PREFIX unset ---" >&2
    return 0
  fi
  echo "--- containers and addresses ($prefix*) ---" >&2
  local names dumped=" $* "
  [ "$#" -gt 0 ] || dumped=" ${E2E_BIRDCAGE:-} "
  names="$(timeout 30 docker ps -a --filter "name=^${prefix}" --format '{{.Names}}' 2>&1 | sort)" || true
  for c in $names; do
    # shellcheck disable=SC2016  # Go template, not shell
    timeout 10 docker inspect --format '{{.Name}}{{range $k, $v := .NetworkSettings.Networks}} {{$k}}={{$v.IPAddress}}{{end}}' "$c" >&2 2>&1 || true
  done
  for c in $names; do
    case "$dumped" in *" $c "*) continue ;; esac
    echo "--- docker logs --tail 200 $c ---" >&2
    { timeout 30 docker logs --tail 200 "$c" 2>&1 || echo "(no log: $c)"; } \
      | sed -E 's/with (setup|unlock) code [A-Za-z0-9-]+/with \1 code <redacted>/g' >&2 || true
  done
  echo "--- birdcage alerts: id received_at source_ip service dest_port logtype synthetic ---" >&2
  if [ -z "${DASHBOARD_AUTH:-}" ] || [ -z "${BIRDCAGE_URL:-}" ] \
    || ! helper 'test -s /work/dashboard-auth' >/dev/null 2>&1; then
    echo "(skipped: dashboard sign-in not set up at this step)" >&2
    return 0
  fi
  # logtype lives inside the stored raw OpenCanary line, not as an alert field.
  helper "curl -sS --max-time 10 --cacert /tls/dashboard-ca.pem $DASHBOARD_AUTH '$BIRDCAGE_URL/api/alerts?limit=200' | jq -r '.alerts[] | [.id, .received_at, .source_ip, .service, .dest_port, (try (.raw | fromjson | .logtype) catch null), .synthetic] | @tsv'" 2>&1 | head -n 300 >&2 || true
  echo "--- birdcage canaries: id name hits status ---" >&2
  helper "curl -sS --max-time 10 --cacert /tls/dashboard-ca.pem $DASHBOARD_AUTH '$BIRDCAGE_URL/api/canaries' | jq -r '.canaries[] | [.id, .name, .hits, .status] | @tsv'" 2>&1 | head -n 100 >&2 || true
}

# helper runs a shell command inside the harness's helper container: on
# the stack's network, with curl, openssl, jq and sqlite, and with
# /tls, /work, /data and /state mounted (see stack.sh). Bounded
# (E2E_HELPER_TIMEOUT, default 20s): almost nothing run through here
# (a bare curl, nc -w 5) carries a timeout of its own, so a connection
# that is accepted and then never answers used to block whichever
# poll() attempt called it forever, past poll()'s own stated attempts
# bound. `timeout` wraps the external "$E2E_STACK" call, not this
# function, so a caller that stashes the result in a variable (poll()
# callbacks like conflict_visible, outbox_row) still sees it land.
E2E_HELPER_TIMEOUT="${E2E_HELPER_TIMEOUT:-20}"
helper() { timeout "$E2E_HELPER_TIMEOUT" "$E2E_STACK" helper "$@"; }

# DASHBOARD_AUTH signs a dashboard API call (#8): every route under
# /api/ answers 401 without a credential. It is curl's `-H @file`, the
# header line `Authorization: Bearer <read API token>` that stack.sh's
# sign_in left in the work volume, so the token is read inside the
# helper and never appears on a command line or in a log:
#
#   helper "curl -sS --cacert /tls/dashboard-ca.pem $DASHBOARD_AUTH '$BIRDCAGE_URL/api/alerts'"
DASHBOARD_AUTH='-H @/work/dashboard-auth'

# poll retries a command until it succeeds, bounded. The bound is part
# of the failure message the caller writes, so a journey never waits
# forever and never reports "it failed" without saying how long it
# waited. The command is run as given, never through eval: a journey's
# assertions are full of quotes and backslashes, and an eval layer is
# where one of them silently becomes a command that always succeeds.
# Attempts are only actually bounded if whatever they run is too --
# see helper()'s own E2E_HELPER_TIMEOUT above.
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
