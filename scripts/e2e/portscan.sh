#!/usr/bin/env bash
# portscan.sh -- issue #79's live check: a real sweep of closed ports
# against the real Mockingbird image produces a real port-scan alert in
# birdcage, and the negative path -- the image run without a working
# NET_RAW capability -- reports itself absent rather than silently
# matching nothing (the trap #65's own comments record: a filter with
# the wrong offsets passed every unit test and matched no packets at
# all, and only running the real image found it).
#
# scripts/e2e/portscan-stack.sh is the infrastructure this needs and no
# other journey does: two extra canaries carrying the two capability
# shapes (see that file's own comment for why two, and for the
# capability combination that was tried and rejected), plus the
# container this journey sweeps from.
#
#   eval "$(scripts/e2e/stack.sh up)"
#   eval "$(scripts/e2e/portscan-stack.sh up)"
#   scripts/e2e/portscan.sh
#   scripts/e2e/portscan-stack.sh down
#   scripts/e2e/stack.sh down
set -eu

. "$(dirname "$0")/journey.sh"

[ -n "${PORTSCAN_POS_CANARY:-}" ] && [ -n "${PORTSCAN_POS_CANARY_ID:-}" ] \
  && [ -n "${PORTSCAN_NEG_CANARY:-}" ] && [ -n "${PORTSCAN_NEG_CANARY_ID:-}" ] \
  && [ -n "${PORTSCAN_SWEEPER:-}" ] || {
  echo "portscan: PORTSCAN_POS_CANARY/_ID, PORTSCAN_NEG_CANARY/_ID or PORTSCAN_SWEEPER unset -- run: eval \"\$(scripts/e2e/portscan-stack.sh up)\"" >&2
  exit 2
}

# Ports nothing in build/mockingbird/opencanary.conf enables (the
# highest listed there is 9418) and nothing else on this stack's
# network answers on either -- birdcage's own three listeners are
# 8080/8443/8444. sweep_low..sweep_low+4 is exactly
# internal/agent/portscan.DefaultThreshold (5) distinct ports, enough on
# its own to cross the threshold; the rest extend one continuing scan
# to prove the rate cap, not to cross it a second time.
SWEEP_LOW=20000
SWEEP_FIRST_COUNT=5
SWEEP_TOTAL_COUNT=25

sweep() { # sweep <target> <first-port> <count>
  local target="$1" first="$2" count="$3" last
  last=$((first + count - 1))
  docker exec "$PORTSCAN_SWEEPER" sh -c "
    for p in \$(seq $first $last); do
      nc -z -w1 '$target' \"\$p\" 2>/dev/null || true
    done
  " || fail "could not run nc from $PORTSCAN_SWEEPER against $target:$first-$last" "$PORTSCAN_SWEEPER"
}

# portscan_alert_count reads the number of portscan-service alerts
# birdcage holds for one canary's instance id. instance= is
# store.AlertFilter.InstanceID, set from the bearer token at ingest
# time (internal/ingest/batch.go) -- never from the event body -- so
# this is real proof the alert was attributed to the canary that sent
# it, not just that *a* portscan event landed somewhere.
portscan_alert_count() { # portscan_alert_count <canary-id>
  helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/alerts?service=portscan&instance=$1' | jq '.alerts | length'"
}

# portscan_seen is poll's predicate: exit 0 once at least one alert has
# reached birdcage for this canary. A function and its own argument,
# not a string handed to poll -- see journey.sh's own poll doc comment
# for why: a journey's assertions are full of quotes, and an eval layer
# in between is where one of them silently becomes a command that
# always succeeds.
portscan_seen() {
  local n
  n="$(portscan_alert_count "$1")" || return 1
  [ "${n:-0}" -ge 1 ] 2>/dev/null
}

step "both portscan canaries hold tokens"
list="$("$E2E_STACK" birdcage canary list)" || fail "birdcage canary list did not run"
case "$list" in
  *"canary=$PORTSCAN_POS_CANARY_ID"*) ok "positive canary $PORTSCAN_POS_CANARY_ID holds a token" ;;
  *) fail "positive canary $PORTSCAN_POS_CANARY_ID is not in the list: $list" ;;
esac
case "$list" in
  *"canary=$PORTSCAN_NEG_CANARY_ID"*) ok "negative canary $PORTSCAN_NEG_CANARY_ID holds a token" ;;
  *) fail "negative canary $PORTSCAN_NEG_CANARY_ID is not in the list: $list" "$PORTSCAN_NEG_CANARY" ;;
esac

step "a sweep of $SWEEP_FIRST_COUNT closed ports produces exactly one port-scan event"
sweep "$PORTSCAN_POS_CANARY" "$SWEEP_LOW" "$SWEEP_FIRST_COUNT"
poll 30 portscan_seen "$PORTSCAN_POS_CANARY_ID" \
  || fail "no port-scan alert reached birdcage for $PORTSCAN_POS_CANARY_ID after 30 attempts" "$PORTSCAN_POS_CANARY"
count="$(portscan_alert_count "$PORTSCAN_POS_CANARY_ID")"
[ "$count" = 1 ] || fail "expected exactly one port-scan alert after a $SWEEP_FIRST_COUNT-port sweep, got $count" "$PORTSCAN_POS_CANARY"
ok "exactly one port-scan alert"

alert="$(helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/alerts?service=portscan&instance=$PORTSCAN_POS_CANARY_ID' \
  | jq -c '.alerts[0] | {id, service, dest_port, count: (.raw | fromjson | .logdata.COUNT), proto: (.raw | fromjson | .logdata.PROTO)}'")"
case "$alert" in
  *'"proto":"TCP"'*) ok "alert names TCP: $alert" ;;
  *) fail "the port-scan alert does not name TCP: $alert" "$PORTSCAN_POS_CANARY" ;;
esac
case "$alert" in
  *"\"count\":\"$SWEEP_FIRST_COUNT\""*) ok "alert reports $SWEEP_FIRST_COUNT ports: $alert" ;;
  *) fail "the port-scan alert does not report $SWEEP_FIRST_COUNT ports: $alert" "$PORTSCAN_POS_CANARY" ;;
esac

step "the rate cap holds on a longer sweep of the same source"
remaining=$((SWEEP_TOTAL_COUNT - SWEEP_FIRST_COUNT))
sweep "$PORTSCAN_POS_CANARY" "$((SWEEP_LOW + SWEEP_FIRST_COUNT))" "$remaining"
# internal/agent/portscan.DefaultCooldown is 60s; this only has to prove
# the count does not climb while the scan continues, so a much shorter
# watch is enough -- if the cap were broken, a second event would
# appear within seconds of the extra ports landing, not after a wait
# tuned to the cooldown itself.
attempt=0
while [ "$attempt" -lt 12 ]; do
  count="$(portscan_alert_count "$PORTSCAN_POS_CANARY_ID")"
  [ "$count" = 1 ] || fail "port-scan alert count for $PORTSCAN_POS_CANARY_ID climbed to $count after sweeping $SWEEP_TOTAL_COUNT ports total -- the rate cap did not hold" "$PORTSCAN_POS_CANARY"
  attempt=$((attempt + 1))
  sleep 1
done
ok "still exactly one port-scan alert after sweeping $SWEEP_TOTAL_COUNT ports total"

step "the no-capability canary reports detection absent rather than matching nothing silently"
# Already asserted once at portscan-stack.sh's own readiness check
# (its own startup line); re-read it here so this journey's own PASS
# does not depend on another script's earlier assertion still holding.
logs="$(docker logs "$PORTSCAN_NEG_CANARY" 2>&1)" || fail "could not read $PORTSCAN_NEG_CANARY's log" "$PORTSCAN_NEG_CANARY"
case "$logs" in
  *"port-scan detection is OFF"*) ok "the agent logged detection off at startup" ;;
  *) fail "the no-capability canary never logged that detection is off: $logs" "$PORTSCAN_NEG_CANARY" ;;
esac

step "the same sweep against the no-capability canary produces no port-scan alert"
# The sweep mechanism itself was just proven to produce a real alert
# (the step above) -- so a zero count here is evidence about this
# canary's missing capability, not evidence that nothing on this path
# could ever produce an event (the trap testing-and-ci's own rules warn
# against: an absence test that could not have failed proves nothing).
sweep "$PORTSCAN_NEG_CANARY" "$SWEEP_LOW" "$SWEEP_TOTAL_COUNT"
attempt=0
while [ "$attempt" -lt 15 ]; do
  count="$(portscan_alert_count "$PORTSCAN_NEG_CANARY_ID")"
  [ "$count" = 0 ] || fail "the no-capability canary produced $count port-scan alert(s) -- detection should have been off" "$PORTSCAN_NEG_CANARY"
  attempt=$((attempt + 1))
  sleep 1
done
ok "no port-scan alert after sweeping $SWEEP_TOTAL_COUNT ports with no capability"

step "the no-capability canary kept running"
running="$(docker inspect --format '{{.State.Running}}' "$PORTSCAN_NEG_CANARY")" \
  || fail "could not inspect $PORTSCAN_NEG_CANARY" "$PORTSCAN_NEG_CANARY"
[ "$running" = true ] || fail "the no-capability canary is not running: state=$running" "$PORTSCAN_NEG_CANARY"
ok "still running after being swept with no capability"

finish
