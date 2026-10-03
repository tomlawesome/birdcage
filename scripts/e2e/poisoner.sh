#!/usr/bin/env bash
# poisoner.sh -- issue #86 slice C's live check: the real the fixture,
# answering a real canary's real bait lookups, produces a real poisoner
# alert in birdcage naming what answered -- and the canary never connects
# to the address it was offered.
#
# The second half is the one that needs a real poisoner rather than a
# hand-made reply. the fixture does not just answer: it stands up the SMB
# and HTTP servers that collect a victim's credentials, and it logs every
# client that reaches them. So "the canary never connected" is not
# asserted by reading our own code back -- it is asserted from the
# attacker's own side of the wire, which is the only place that could
# disagree with us.
#
# scripts/e2e/poisoner-stack.sh is the infrastructure this needs and no
# other journey does: a canary paced to burst every few seconds, enrolled
# with bait names through `birdcage canary enrol --bait-names`, and the
# the fixture container itself.
#
#   eval "$(scripts/e2e/stack.sh up)"
#   eval "$(scripts/e2e/poisoner-stack.sh up)"
#   scripts/e2e/poisoner.sh
#   scripts/e2e/poisoner-stack.sh down
#   scripts/e2e/stack.sh down
set -eu

. "$(dirname "$0")/journey.sh"

[ -n "${POISONER_CANARY:-}" ] && [ -n "${POISONER_CANARY_ID:-}" ] \
  && [ -n "${POISONER_FIXTURE:-}" ] || {
  echo "poisoner: POISONER_CANARY/_ID or POISONER_FIXTURE unset -- run: eval \"\$(scripts/e2e/poisoner-stack.sh up)\"" >&2
  exit 2
}

# poisoner_alert_count reads how many poisoner-service alerts birdcage
# holds for this canary's instance id. instance= is
# store.AlertFilter.InstanceID, set from the bearer token at ingest time
# (internal/ingest/batch.go) -- never from the event body -- so this is
# proof the alert was attributed to the canary that sent it, not just that
# a poisoner event landed somewhere.
poisoner_alert_count() { # poisoner_alert_count <canary-id>
  helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/alerts?service=poisoner&instance=$1' | jq '.alerts | length'"
}

poisoner_seen() { # poisoner_seen <canary-id>
  local n
  n="$(poisoner_alert_count "$1")" || return 1
  [ "${n:-0}" -ge 1 ] 2>/dev/null
}

fixture_poisoned() { # fixture_poisoned -- exit 0 once the fixture says it answered
  docker logs "$POISONER_FIXTURE" 2>&1 | grep -q "Poisoned answer sent to"
}

step "the poisoner canary holds a token"
list="$("$E2E_STACK" birdcage canary list)" || fail "birdcage canary list did not run"
case "$list" in
  *"canary=$POISONER_CANARY_ID"*) ok "canary $POISONER_CANARY_ID holds a token" ;;
  *) fail "canary $POISONER_CANARY_ID is not in the list: $list" "$POISONER_CANARY" ;;
esac

step "the canary asks for a name nobody should answer, and the fixture answers it"
# poisoner-stack.sh already waited for "poisoner detection active", and
# the pacing it enrolled makes a burst land within seconds. 60 attempts is
# far more headroom than the few seconds this needs; it is generous
# because a loaded runner schedules the container late, not because the
# rate is uncertain.
poll 60 fixture_poisoned \
  || fail "the fixture never logged a poisoned answer -- the canary's bait lookups never reached it, or did not look like a real client's" "$POISONER_CANARY" "$POISONER_FIXTURE"
answered="$(docker logs "$POISONER_FIXTURE" 2>&1 | grep "Poisoned answer sent to" | head -3)"
ok "the fixture answered: $(printf '%s' "$answered" | tr '\n' ';')"

step "the answer reaches birdcage as a poisoner alert for this canary"
poll 60 poisoner_seen "$POISONER_CANARY_ID" \
  || fail "no poisoner alert reached birdcage for $POISONER_CANARY_ID after 60 attempts" "$POISONER_CANARY"

alert="$(helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/alerts?service=poisoner&instance=$POISONER_CANARY_ID' \
  | jq -c '.alerts[0] | {service, source_ip, name: (.raw | fromjson | .logdata.NAME), protocol: (.raw | fromjson | .logdata.PROTOCOL), mac: (.raw | fromjson | .logdata.MAC)}'")"
ok "alert: $alert"

case "$alert" in
  *'"service":"poisoner"'*) ok "the alert's service is poisoner" ;;
  *) fail "the alert is not a poisoner alert: $alert" "$POISONER_CANARY" ;;
esac

# The answering address, taken from the fixture's own container rather than
# from the alert, so this compares two independent sources.
fixture_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$POISONER_FIXTURE")" \
  || fail "could not read $POISONER_FIXTURE's address"
[ -n "$fixture_ip" ] || fail "$POISONER_FIXTURE has no address on $E2E_NET"
case "$alert" in
  *"\"source_ip\":\"$fixture_ip\""*) ok "the alert names the fixture's own address $fixture_ip" ;;
  *) fail "the alert does not name the fixture's address $fixture_ip: $alert" "$POISONER_CANARY" "$POISONER_FIXTURE" ;;
esac

# One of the three protocols, whichever burst landed first. Asserting the
# field is one of the real values rather than a particular one, because
# which protocol gets answered first is a race between three sockets and
# not something this journey should pin.
case "$alert" in
  *'"protocol":"llmnr"'* | *'"protocol":"nbt-ns"'* | *'"protocol":"mdns"'*) ok "the alert names the protocol that carried the answer" ;;
  *) fail "the alert does not name one of llmnr, nbt-ns or mdns: $alert" "$POISONER_CANARY" ;;
esac

# The name must be present and non-empty. It is not compared against the
# enrolled bait names on purpose: this journey prints its own output into
# a CI log, and the whole point of taking bait names from the operator's
# own network is that they are not written down anywhere an attacker
# reads. Proving the field carries a name is what matters.
case "$alert" in
  *'"name":""'* | *'"name":null'*) fail "the alert carries no bait name: $alert" "$POISONER_CANARY" ;;
  *'"name":"'*) ok "the alert names the bait name that was answered for" ;;
  *) fail "the alert has no name field: $alert" "$POISONER_CANARY" ;;
esac

# The MAC is best-effort by design (internal/agent/poisoner/arp.go: an
# answer from off-segment or over IPv6 has no neighbour entry to read), so
# the field must be present but is not required to be filled.
case "$alert" in
  *'"mac":'*) ok "the alert carries the MAC field" ;;
  *) fail "the alert has no MAC field: $alert" "$POISONER_CANARY" ;;
esac

step "the canary never connected to the address it was offered"
# the fixture's own side of the wire. It answered with its own address, and
# a victim that believed it would have connected straight to the SMB or
# HTTP server the fixture stands up for exactly that -- which is what would
# hand over an NTLM exchange. the fixture logs every client that reaches
# those servers, and writes a file per captured hash.
#
# Checked from the fixture rather than from the canary because a bug in the
# canary is precisely what this is looking for: reading our own code's
# claim that it did not connect would prove nothing.
captured="$(docker exec "$POISONER_FIXTURE" sh -c 'ls /opt/responder/logs/ 2>/dev/null | grep -i ntlm || true')"
[ -z "$captured" ] || fail "the fixture captured credentials from the canary -- it must never connect to the offered address: $captured" "$POISONER_CANARY" "$POISONER_FIXTURE"
ok "the fixture captured no credentials"

# The session log's own client lines. Neither substring appears anywhere
# in the fixture's startup banner (checked while building this journey), so
# a match here is a real client, not a banner line.
clients="$(docker logs "$POISONER_FIXTURE" 2>&1 | grep -E 'NTLMv1|NTLMv2|Client +:' || true)"
[ -z "$clients" ] || fail "the fixture logged a client connection from the canary: $clients" "$POISONER_CANARY" "$POISONER_FIXTURE"
ok "the fixture logged no client connection"

step "the canary is still asking, and still not connecting"
# One more round of bursts, to prove the first result was not a one-off
# and that repeated poisoning still never draws a connection. The canary's
# ceiling is a couple of seconds, so several more bursts land in this
# window.
sleep 15
after="$(poisoner_alert_count "$POISONER_CANARY_ID")"
[ "${after:-0}" -ge 1 ] || fail "the poisoner alert count fell to $after" "$POISONER_CANARY"
ok "$after poisoner alert(s) for this canary"

captured="$(docker exec "$POISONER_FIXTURE" sh -c 'ls /opt/responder/logs/ 2>/dev/null | grep -i ntlm || true')"
[ -z "$captured" ] || fail "the fixture captured credentials after further poisoning: $captured" "$POISONER_CANARY" "$POISONER_FIXTURE"
clients="$(docker logs "$POISONER_FIXTURE" 2>&1 | grep -E 'NTLMv1|NTLMv2|Client +:' || true)"
[ -z "$clients" ] || fail "the fixture logged a client connection after further poisoning: $clients" "$POISONER_CANARY" "$POISONER_FIXTURE"
ok "still no connection and no captured credentials"

finish
