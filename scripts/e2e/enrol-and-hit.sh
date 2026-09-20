#!/usr/bin/env bash
# enrol-and-hit.sh -- issue #78 journey 1: a canary enrolled by the
# command birdcage printed, then a real hit on it arriving on the
# dashboard's own API.
#
# scripts/e2e/stack.sh up has already done the deploying half: it ran
# `birdcage canary enrol` and then executed the `docker run` command
# that printed (see run_printed_command there for the three things the
# test environment forces it to change). What is left, and what this
# file checks, is that the command actually worked and that the canary
# it started behaves like a canary.
#
#   eval "$(scripts/e2e/stack.sh up)"
#   scripts/e2e/enrol-and-hit.sh
set -eu

. "$(dirname "$0")/journey.sh"

step "the deploy token was burned"
# --status never prints a token or a hash, only whether the session was
# contacted -- so "contacted=<timestamp>" is the product's own evidence
# that the canary spent the token exactly once.
status="$("$E2E_STACK" birdcage canary enrol --status)" \
  || fail "birdcage canary enrol --status did not run"
case "$status" in
  *"name=$E2E_CANARY_NAME"*) ;;
  *) fail "no enrolment session named $E2E_CANARY_NAME: $status" ;;
esac
case "$status" in
  *"contacted=not contacted"*) fail "the session was never contacted, so the deploy token is still live: $status" ;;
esac
case "$status" in
  *state=provisioned*) ok "session contacted and provisioned" ;;
  *) fail "the session is not provisioned: $status" ;;
esac

step "the canary appears in birdcage canary list"
list="$("$E2E_STACK" birdcage canary list)" || fail "birdcage canary list did not run"
case "$list" in
  *"canary=$E2E_CANARY_ID"*) ok "canary $E2E_CANARY_ID holds a token" ;;
  *) fail "canary $E2E_CANARY_ID is not in the list: $list" ;;
esac

step "a client certificate was issued to this canary"
# Three separate things, because any one of them alone would pass
# against a file that is not a usable credential: the agent has a
# certificate at all, birdcage's own CA signed it, and its subject
# names this canary (the CN is what internal/ingest's requireBearerToken
# matches the bearer token against).
subject="$(helper '
set -eu
test -s /state/client.pem || { echo "no /state/client.pem"; exit 1; }
openssl verify -CAfile /data/ca/ca.pem /state/client.pem >/dev/null || { echo "not issued by birdcage CA"; exit 1; }
openssl x509 -in /state/client.pem -noout -subject
')" || fail "the canary has no usable client certificate: $subject" "$E2E_CANARY"
case "$subject" in
  *"CN=$E2E_CANARY_ID"*) ok "client certificate verified against birdcage's CA, ${subject#subject=}" ;;
  *) fail "the client certificate names someone else: $subject" "$E2E_CANARY" ;;
esac

step "the canary is serving FTP"
# Wait for the 220 greeting before counting on the hit below, not just
# for the port to accept: a bare connect passes against a socket with
# nothing behind it. The `sleep 2` is load-bearing and deliberate --
# see the long comment in .gitlab-ci.yml's test:image:mockingbird: busybox
# nc can exit without draining the reply, so holding stdin open is what
# makes this a readiness check rather than a timing measurement.
poll 30 helper "{ printf 'USER probe\\r\\nQUIT\\r\\n'; sleep 2; } | nc -w 5 $E2E_CANARY 21 | grep -q '^220 '" \
  || fail "no 220 FTP greeting from $E2E_CANARY:21 after 30 attempts" "$E2E_CANARY"

step "an FTP login is a real hit"
helper "{ printf 'USER x\\r\\nPASS y\\r\\nQUIT\\r\\n'; sleep 2; } | nc -w 5 $E2E_CANARY 21" >/dev/null \
  || fail "the FTP login attempt could not be sent to $E2E_CANARY:21" "$E2E_CANARY"
ok "FTP login attempt sent"

step "the hit reaches GET /api/alerts"
# Over TLS against the dashboard's real certificate -- --cacert, never
# -k: a journey that waves certificate verification through would pass
# against the one configuration issue #63 exists to prevent.
#
# service=ftp is the mapping internal/opencanary makes from OpenCanary's
# own logtype, so matching on it proves the whole path ran: OpenCanary
# logged it, the agent read it, posted it over mutual TLS, and birdcage
# stored it.
poll 30 helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/alerts?service=ftp' | jq -e '.alerts | length > 0'" \
  || fail "/api/alerts never contained an ftp event after 30 attempts" "$E2E_CANARY" "$E2E_BIRDCAGE"

alert="$(helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/alerts?service=ftp' | jq -c '.alerts[0]'")"
case "$alert" in
  *'"dest_port":21'*) ok "alert on port 21: $alert" ;;
  *) fail "the ftp alert does not name port 21: $alert" "$E2E_BIRDCAGE" ;;
esac

finish
