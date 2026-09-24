#!/usr/bin/env bash
# smb-lure.sh -- issue #87's own journey, and #123's acceptance: the
# SHIPPED SMB lure image serving a read-only guest share on a canary's own
# address, a real smbclient opening one bait file, and EXACTLY ONE alert
# reaching birdcage naming the share and the path -- then the same again
# across a restart of the canary, which must lose nothing and duplicate
# nothing.
#
# This is not scripts/e2e/smb.sh. That journey drives build/e2e-samba and
# OpenCanary's own smb module, the arrangement #78 proved; this one drives
# the image that ships and the agent's own tailer and parse. See
# scripts/e2e/smb-lure-stack.sh's header.
#
#   eval "$(scripts/e2e/stack.sh up)"
#   eval "$(scripts/e2e/smb-lure-stack.sh up)"
#   scripts/e2e/smb-lure.sh
#   scripts/e2e/smb-lure-stack.sh down
#   scripts/e2e/stack.sh down
set -eu

. "$(dirname "$0")/journey.sh"

[ -n "${SMB_LURE:-}" ] && [ -n "${SMB_LURE_CANARY:-}" ] && [ -n "${SMB_LURE_CANARY_ID:-}" ] \
  && [ -n "${SMB_LURE_CLIENT_IMAGE:-}" ] && [ -n "${SMB_LURE_SHARE:-}" ] \
  && [ -n "${SMB_LURE_BAIT_ONE:-}" ] && [ -n "${SMB_LURE_BAIT_TWO:-}" ] \
  && [ -n "${SMB_LURE_STACK:-}" ] || {
  echo "SMB_LURE* unset -- run: eval \"\$(scripts/e2e/smb-lure-stack.sh up)\"" >&2
  exit 2
}

# BASELINE_ID is the highest smb alert id birdcage already holds, read
# before this journey touches anything. Every count below is of alerts
# *newer* than it.
#
# Both halves of that scoping were put in after watching this journey lie.
# stack.sh's birdcage database outlives this harness's own up/down -- only
# `stack.sh down` drops it -- and the bait file names are fixed in the
# image, so a plain "count the alerts naming this file" counts every
# earlier run's too: run the journey twice and the second run reports two
# alerts for one fetch and blames the collapser, which was doing exactly
# the right thing. An integer id is used rather than a timestamp because
# it needs no clock and no date parsing to compare.
BASELINE_ID=0

# settleSeconds is how long to keep watching after the first alert for a
# path arrives, before asserting there is only one. Without it "exactly
# one" would pass on any run where the duplicate simply had not landed
# yet, which is the failure #123 is about. Comfortably over the
# collapser's own two-second window plus a sender cycle.
SETTLE_SECONDS=10

# smb_get opens one file on the share with a real client, over the
# canary's own address -- which is the point of decision 3, so the journey
# asserts it by using it rather than by reading a configuration file.
smb_get() {
  local path="$1" dir base
  dir="$(dirname "$path")"
  base="$(basename "$path")"
  docker run --rm --network "$E2E_NET" "$SMB_LURE_CLIENT_IMAGE" \
    "//$SMB_LURE_CANARY/$SMB_LURE_SHARE" -N \
    -c "cd \"$dir\"; get \"$base\" /tmp/fetched" 2>&1
}

# alerts_naming counts the stored smb alerts from THIS canary whose
# FILENAME ends with this path.
#
# Scoped to instance_id, not just to the path, and that is not tidiness:
# stack.sh's birdcage database outlives this harness's own up/down (only
# `stack.sh down` drops it), the bait file names are fixed in the image, so
# every run would otherwise count every previous run's alerts for the same
# file. Found by running this journey twice in a row: the second run
# reported two alerts for one fetch and blamed the collapser, which was
# doing exactly the right thing.
#
# /api/alerts keeps OpenCanary's whole event as a raw JSON string
# (internal/store.Alert.Raw), so logdata.FILENAME is a field inside that
# string and not of the alert object -- hence fromjson, the same shape
# scripts/e2e/smb.sh's own poll uses. instance_id is a field of the alert
# itself.
alerts_naming() {
  local path="$1"
  helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/alerts?service=smb' \
    | jq --arg p '$path' --arg c '$SMB_LURE_CANARY_ID' --argjson b '$BASELINE_ID' \
      '[.alerts[] | select(.instance_id == \$c and .id > \$b) | (.raw | fromjson)
        | select((.logdata.FILENAME // \"\") | endswith(\$p))] | length'"
}

# alert_for prints the fields worth reading back for one path: the share,
# the path, the wording, and the service birdcage filed it under.
alert_for() {
  local path="$1"
  helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/alerts?service=smb' \
    | jq -c --arg p '$path' --arg c '$SMB_LURE_CANARY_ID' --argjson b '$BASELINE_ID' \
      '[.alerts[] | select(.instance_id == \$c and .id > \$b)
        | select((.raw | fromjson | .logdata.FILENAME // \"\") | endswith(\$p))
        | {id, service, dest_port, share: (.raw | fromjson | .logdata.SHARENAME),
           path: (.raw | fromjson | .logdata.FILENAME), wording: (.raw | fromjson | .logdata.AUDITEVENT)}][0]'"
}

# expect_exactly_one polls for the first alert naming a path, waits for any
# duplicate to arrive, and then insists there is still only one.
expect_exactly_one() {
  local path="$1" count
  poll 60 test_at_least_one "$path" \
    || fail "no smb alert ever named $path after 60 attempts" "$SMB_LURE_CANARY" "$SMB_LURE" "$E2E_BIRDCAGE"
  sleep "$SETTLE_SECONDS"
  count="$(alerts_naming "$path")" || fail "could not count the alerts naming $path" "$E2E_BIRDCAGE"
  [ "$count" = 1 ] || fail "$count alerts name $path, want exactly 1 -- one visit is one alert (#123)" "$SMB_LURE_CANARY"
  ok "exactly one alert names $path"
}

test_at_least_one() {
  local count
  count="$(alerts_naming "$1" 2>/dev/null)" || return 1
  [ -n "$count" ] && [ "$count" -ge 1 ]
}

step "note which alerts birdcage already holds, so this run counts only its own"
BASELINE_ID="$(helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/alerts?service=smb' \
  | jq '[.alerts[].id] | max // 0'")" || fail "could not read birdcage's existing smb alerts"
case "$BASELINE_ID" in
  ''|*[!0-9]*) fail "the alert-id baseline is not a number: [$BASELINE_ID]" ;;
esac
ok "counting only smb alerts newer than id $BASELINE_ID"

step "the lure canary appears in birdcage's canary list"
list="$("$E2E_STACK" birdcage canary list)" || fail "birdcage canary list did not run"
case "$list" in
  *"canary=$SMB_LURE_CANARY_ID"*) ok "lure canary $SMB_LURE_CANARY_ID holds a token" ;;
  *) fail "lure canary $SMB_LURE_CANARY_ID is not in the list: $list" ;;
esac

step "the shipped lure offers its shares on the canary's own address"
shares="$(docker run --rm --network "$E2E_NET" "$SMB_LURE_CLIENT_IMAGE" -L "//$SMB_LURE_CANARY" -N 2>&1)" \
  || fail "smbclient -L against the canary's address failed: $shares" "$SMB_LURE" "$SMB_LURE_CANARY"
case "$shares" in
  *"$SMB_LURE_SHARE"*) ok "share $SMB_LURE_SHARE is offered on //$SMB_LURE_CANARY" ;;
  *) fail "the share list does not name $SMB_LURE_SHARE: $shares" "$SMB_LURE" ;;
esac
# The lure must never look like what it is. A share list an intruder can
# read is the most visible string the product has.
case "$shares" in
  *[Hh]oneypot*|*[Cc]anary*|*[Bb]irdcage*|*e2e*|*[Ll]ure*)
    fail "the share list gives the game away: $shares" "$SMB_LURE" ;;
  *) ok "nothing in the share list says what this is" ;;
esac

step "a real smbclient opens $SMB_LURE_BAIT_ONE"
out="$(smb_get "$SMB_LURE_BAIT_ONE")" || fail "smbclient could not get $SMB_LURE_BAIT_ONE: $out" "$SMB_LURE"
case "$out" in
  *getting\ file*) ok "fetched $SMB_LURE_BAIT_ONE over a real SMB session" ;;
  *) fail "smbclient did not report fetching the file: $out" "$SMB_LURE" ;;
esac

step "exactly one alert reaches birdcage naming the share and the path"
expect_exactly_one "$SMB_LURE_BAIT_ONE"
alert="$(alert_for "$SMB_LURE_BAIT_ONE")" || fail "could not re-read the alert" "$E2E_BIRDCAGE"
case "$alert" in
  *'"share":"'"$SMB_LURE_SHARE"'"'*) ok "the alert names the share: $alert" ;;
  *) fail "the alert does not name the share $SMB_LURE_SHARE: $alert" "$E2E_BIRDCAGE" ;;
esac
case "$alert" in
  *'"service":"smb"'*) ok "birdcage filed it as an smb alert" ;;
  *) fail "the alert is not filed under service smb: $alert" "$E2E_BIRDCAGE" ;;
esac
case "$alert" in
  *'"wording":"file access"'*) ok "the alert reads as a file access" ;;
  *) fail "the alert's wording is not a file access: $alert" "$E2E_BIRDCAGE" ;;
esac

step "a restart of the canary loses nothing and duplicates nothing"
# The lure goes down with the canary and comes back with it -- see
# restart_canary in smb-lure-stack.sh for why that is the design and not
# an accident of this harness.
"$SMB_LURE_STACK" restart-canary || fail "restarting the canary and the lure failed" "$SMB_LURE_CANARY" "$SMB_LURE"
ok "the canary and the lure are back"

# Nothing new was accessed, so the first alert must still be exactly one:
# the agent re-reads the audit file from its saved position on every start,
# and a re-read line has to mint the id it already had.
sleep "$SETTLE_SECONDS"
count="$(alerts_naming "$SMB_LURE_BAIT_ONE")" || fail "could not recount the alerts naming $SMB_LURE_BAIT_ONE" "$E2E_BIRDCAGE"
[ "$count" = 1 ] || fail "$count alerts name $SMB_LURE_BAIT_ONE after the restart, want 1 -- the re-read minted a second id" "$SMB_LURE_CANARY"
ok "the restart raised no duplicate of the first alert"

step "and the road still reports a fresh access afterwards"
out="$(smb_get "$SMB_LURE_BAIT_TWO")" || fail "smbclient could not get $SMB_LURE_BAIT_TWO after the restart: $out" "$SMB_LURE"
expect_exactly_one "$SMB_LURE_BAIT_TWO"
alert="$(alert_for "$SMB_LURE_BAIT_TWO")" || fail "could not re-read the second alert" "$E2E_BIRDCAGE"
ok "after the restart: $alert"

finish
