#!/usr/bin/env bash
# crowdsec.sh -- ADR-0014's live journey (#4): the real `birdcage
# crowdsec add` against a real CrowdSec Local API, and CrowdSec itself
# asked what it holds afterwards.
#
# Needs the base stack and crowdsec-stack.sh up:
#
#   eval "$(scripts/e2e/stack.sh up)"
#   eval "$(scripts/e2e/crowdsec-stack.sh up)"
#   scripts/e2e/crowdsec.sh
#
# What it proves, in order: the configured connection is logged at
# startup without the password; one add lands as a permanent `ban` on
# the LAPI with the cscli origin and birdcage's scenario, and is
# recorded in audit_log; the same add again posts nothing; a floor
# address is refused before the LAPI is contacted; an address on
# CrowdSec's own allowlist is refused; and a wrong CA, an http:// URL
# and a wrong password each fail closed with nothing added -- every
# refusal with its audit row, and every absence checked after the
# presence that proves the check can see a decision at all.
#
# jq runs on this host (the CI job installs it): cscli's JSON comes out
# of the LAPI container and is read here, so the assertions do not
# depend on what the fixture image happens to ship.
set -eu

. "$(dirname "$0")/journey.sh"

[ -n "${CROWDSEC_STACK:-}" ] && [ -n "${CROWDSEC_SERVER:-}" ] || {
  echo "crowdsec: CROWDSEC_STACK/CROWDSEC_SERVER unset -- run: eval \"\$(scripts/e2e/crowdsec-stack.sh up)\" first" >&2
  exit 2
}
command -v jq >/dev/null 2>&1 || { echo "crowdsec: jq is not on PATH" >&2; exit 2; }

TARGET=203.0.113.9
FLOOR_TARGET=10.0.0.5
ALLOWLISTED_TARGET=203.0.113.50
CA_TARGET=203.0.113.60
HTTP_TARGET=203.0.113.61
PASSWORD_TARGET=203.0.113.62
# 99 years in hours: the bar for "never expires, as far as CrowdSec can
# express it" (ADR-0014, decision 4) -- the LAPI reports what remains
# of the hundred years birdcage asked for.
MIN_REMAINING_HOURS=867240

# decisions_for prints the count of live ban decisions the LAPI holds
# for an address, from cscli's own JSON (alerts with nested decisions;
# `null` when there are none).
decisions_for() {
  "$CROWDSEC_STACK" cscli decisions list -o json 2>/dev/null \
    | jq --arg ip "$1" '(. // []) | [ .[] | .decisions[]? | select(.value == $ip and .type == "ban") ] | length'
}

decision_field() {
  "$CROWDSEC_STACK" cscli decisions list -o json 2>/dev/null \
    | jq -r --arg ip "$1" --arg f "$2" '(. // []) | [ .[] | .decisions[]? | select(.value == $ip and .type == "ban") ] | .[0][$f]'
}

audit_count() {
  "$E2E_STACK" query "select count(*) from audit_log where action = '$1' and target = '$2'"
}

# birdcage_add runs the real command inside the running birdcage
# container, with any extra `docker exec` flags first (the negative
# checks override one variable each, exactly as an operator's typo
# would). Output and exit status are captured, never asserted away.
birdcage_add() {
  local target="$1"
  shift
  docker exec "$@" "$E2E_BIRDCAGE" /birdcage crowdsec add "$target" --reason "e2e: live journey" 2>&1
}

# The password is read once into a shell variable so the log and the
# audit rows can be searched for it; it is never echoed.
password="$(docker run --rm --volume "${E2E_PREFIX}-crowdsec-client:/client:ro" "${E2E_PREFIX}-helper" cat /client/password)"
[ -n "$password" ] || fail "could not read the fixture's machine password"

step "birdcage logged the CrowdSec connection at startup, without the password"
docker logs "$E2E_BIRDCAGE" 2>&1 | grep -q "BIRDCAGE_CROWDSEC_LAPI_URL=https://$CROWDSEC_SERVER:8080" \
  || fail "birdcage did not log the configured LAPI URL at startup"
docker logs "$E2E_BIRDCAGE" 2>&1 | grep -q "BIRDCAGE_CROWDSEC_MACHINE_ID=$CROWDSEC_MACHINE_ID" \
  || fail "birdcage did not log the machine id at startup"
if docker logs "$E2E_BIRDCAGE" 2>&1 | grep -qF "$password"; then
  fail "the machine password appears in birdcage's log"
fi
ok "logged URL and machine id; password absent"

step "one add lands as a permanent ban on the real LAPI"
[ "$(decisions_for "$TARGET")" = 0 ] || fail "the LAPI already held a decision for $TARGET before the journey started" "$CROWDSEC_SERVER"
out="$(birdcage_add "$TARGET")" || fail "birdcage crowdsec add $TARGET failed: $out"
case "$out" in
  *"added: permanent ban on $TARGET"*) ok "birdcage reported the add: $out" ;;
  *) fail "unexpected output from the add: $out" ;;
esac
[ "$(decisions_for "$TARGET")" = 1 ] || fail "the LAPI does not hold exactly one ban for $TARGET" "$CROWDSEC_SERVER"
origin="$(decision_field "$TARGET" origin)"
scenario="$(decision_field "$TARGET" scenario)"
scope="$(decision_field "$TARGET" scope)"
remaining="$(decision_field "$TARGET" duration)"
[ "$origin" = cscli ] || fail "decision origin is $origin, want cscli (ADR-0014: a manual decision, not shared with the central API by default)"
[ "$scenario" = "birdcage: e2e: live journey" ] || fail "decision scenario is $scenario"
case "$scope" in Ip|ip) ;; *) fail "decision scope is $scope, want ip" ;; esac
hours="${remaining%%h*}"
case "$hours" in ''|*[!0-9]*) fail "could not read the remaining hours from duration $remaining" ;; esac
[ "$hours" -ge "$MIN_REMAINING_HOURS" ] || fail "the decision expires in ${hours}h, which is less than 99 years ($MIN_REMAINING_HOURS h)"
ok "ban on $TARGET: origin $origin, scenario \"$scenario\", ${hours}h remaining"

step "the add is in audit_log"
[ "$(audit_count crowdsec.block_added "$TARGET")" = 1 ] || fail "audit_log does not hold exactly one crowdsec.block_added for $TARGET"
reason="$("$E2E_STACK" query "select reason from audit_log where action = 'crowdsec.block_added' and target = '$TARGET'")"
case "$reason" in
  *"e2e: live journey"*"LAPI alert "*"876000h"*) ok "audit reason: $reason" ;;
  *) fail "audit reason lacks the operator's text, the alert id or the duration: $reason" ;;
esac
triggered="$("$E2E_STACK" query "select triggered_by from audit_log where action = 'crowdsec.block_added' and target = '$TARGET'")"
[ "$triggered" = cli ] || fail "triggered_by is $triggered, want cli"

step "the same add again posts nothing"
out="$(birdcage_add "$TARGET")" || fail "the second add of $TARGET failed instead of reporting the existing ban: $out"
case "$out" in
  *"already banned by birdcage: $TARGET"*) ok "birdcage reported the existing ban: $out" ;;
  *) fail "unexpected output from the second add: $out" ;;
esac
[ "$(decisions_for "$TARGET")" = 1 ] || fail "a second decision was created for $TARGET" "$CROWDSEC_SERVER"
[ "$(audit_count crowdsec.block_exists "$TARGET")" = 1 ] || fail "audit_log does not hold exactly one crowdsec.block_exists for $TARGET"

step "a never-block floor address is refused before the LAPI is contacted"
set +e
out="$(birdcage_add "$FLOOR_TARGET")"
status=$?
set -e
[ "$status" -ne 0 ] || fail "adding the floor address $FLOOR_TARGET succeeded: $out"
case "$out" in
  *"never-block floor"*) ok "refused: $out" ;;
  *) fail "the refusal did not name the floor: $out" ;;
esac
[ "$(decisions_for "$FLOOR_TARGET")" = 0 ] || fail "the LAPI holds a decision for the floor address $FLOOR_TARGET" "$CROWDSEC_SERVER"
[ "$(audit_count 'refused: never-block floor' "$FLOOR_TARGET")" = 1 ] || fail "audit_log does not hold the floor refusal for $FLOOR_TARGET"
[ "$(audit_count crowdsec.block_failed "$FLOOR_TARGET")" = 0 ] || fail "a floor refusal was also recorded as a LAPI failure"

step "an address on CrowdSec's own allowlist is refused"
"$CROWDSEC_STACK" cscli allowlists create e2e -d "e2e allowlist" >/dev/null 2>&1 || fail "cscli allowlists create failed" "$CROWDSEC_SERVER"
"$CROWDSEC_STACK" cscli allowlists add e2e "$ALLOWLISTED_TARGET" -d "e2e allowlisted" >/dev/null 2>&1 || fail "cscli allowlists add failed" "$CROWDSEC_SERVER"
set +e
out="$(birdcage_add "$ALLOWLISTED_TARGET")"
status=$?
set -e
[ "$status" -ne 0 ] || fail "adding the allowlisted address $ALLOWLISTED_TARGET succeeded: $out"
case "$out" in
  *"allowlist"*) ok "refused: $out" ;;
  *) fail "the refusal did not name the allowlist: $out" ;;
esac
[ "$(decisions_for "$ALLOWLISTED_TARGET")" = 0 ] || fail "the LAPI holds a decision for the allowlisted address" "$CROWDSEC_SERVER"
[ "$(audit_count crowdsec.block_refused "$ALLOWLISTED_TARGET")" = 1 ] || fail "audit_log does not hold crowdsec.block_refused for $ALLOWLISTED_TARGET"

step "a CA that did not sign the LAPI's certificate fails closed"
set +e
out="$(birdcage_add "$CA_TARGET" --env BIRDCAGE_CROWDSEC_CA_FILE=/crowdsec/untrusted-ca.pem)"
status=$?
set -e
[ "$status" -ne 0 ] || fail "the add succeeded with an unrelated CA: $out"
case "$out" in
  *login*certificate*|*login*x509*|*login*tls*) ok "refused at login for the certificate: $out" ;;
  *) fail "the failure was not a certificate failure at login: $out" ;;
esac
[ "$(decisions_for "$CA_TARGET")" = 0 ] || fail "the LAPI holds a decision for $CA_TARGET after a failed handshake" "$CROWDSEC_SERVER"
[ "$(audit_count crowdsec.block_failed "$CA_TARGET")" = 1 ] || fail "audit_log does not hold crowdsec.block_failed for $CA_TARGET"

step "an http:// LAPI URL is refused before anything is contacted"
set +e
out="$(birdcage_add "$HTTP_TARGET" --env "BIRDCAGE_CROWDSEC_LAPI_URL=http://$CROWDSEC_SERVER:8080")"
status=$?
set -e
[ "$status" -ne 0 ] || fail "the add succeeded over http://: $out"
case "$out" in
  *"must start with https://"*) ok "refused: $out" ;;
  *) fail "the refusal did not name the https rule: $out" ;;
esac
[ "$(decisions_for "$HTTP_TARGET")" = 0 ] || fail "the LAPI holds a decision for $HTTP_TARGET" "$CROWDSEC_SERVER"
[ "$(audit_count crowdsec.block_failed "$HTTP_TARGET")" = 0 ] || fail "a configuration refusal was recorded as a LAPI failure"

step "a wrong machine password is refused by the real LAPI and recorded without the password"
set +e
out="$(birdcage_add "$PASSWORD_TARGET" --env BIRDCAGE_CROWDSEC_PASSWORD_FILE=/crowdsec/wrong-password)"
status=$?
set -e
[ "$status" -ne 0 ] || fail "the add succeeded with the wrong password: $out"
case "$out" in
  *"login"*"401"*) ok "refused: $out" ;;
  *) fail "the failure was not a 401 at login: $out" ;;
esac
[ "$(decisions_for "$PASSWORD_TARGET")" = 0 ] || fail "the LAPI holds a decision for $PASSWORD_TARGET" "$CROWDSEC_SERVER"
[ "$(audit_count crowdsec.block_failed "$PASSWORD_TARGET")" = 1 ] || fail "audit_log does not hold crowdsec.block_failed for $PASSWORD_TARGET"
wrong="$(docker run --rm --volume "${E2E_PREFIX}-crowdsec-client:/client:ro" "${E2E_PREFIX}-helper" cat /client/wrong-password)"
reasons="$("$E2E_STACK" query "select reason from audit_log where action like 'crowdsec.%'")"
if printf '%s' "$reasons" | grep -qF "$wrong"; then
  fail "the wrong password appears in an audit_log reason"
fi
if printf '%s' "$reasons" | grep -qF "$password"; then
  fail "the machine password appears in an audit_log reason"
fi
if docker logs "$E2E_BIRDCAGE" 2>&1 | grep -qF "$password"; then
  fail "the machine password appears in birdcage's log after the journey"
fi
ok "no password in any audit row or log line"

step "the one real ban is still the only one"
[ "$(decisions_for "$TARGET")" = 1 ] || fail "the ban on $TARGET changed during the negative checks" "$CROWDSEC_SERVER"
total="$("$CROWDSEC_STACK" cscli decisions list -o json 2>/dev/null | jq '(. // []) | [ .[] | .decisions[]? ] | length')"
[ "$total" = 1 ] || fail "the LAPI holds $total decisions, want exactly the one from step 2" "$CROWDSEC_SERVER"
ok "exactly one decision on the LAPI"

finish
