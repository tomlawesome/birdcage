#!/usr/bin/env bash
# agent-conflict.sh -- issue #130 live journey (ADR-0012 Part B4): the
# same live certificate presented from two source addresses inside one
# heartbeat interval is a credential_conflict, and `birdcage canary
# revoke` ends it for both holders at once.
#
# Runs after agent-renewal.sh in the same job, against $E2E_CANARY_ID's
# current credential (whatever agent-renewal.sh left it as -- this
# journey does not care whether it has been renewed). The helper
# container stands in for a second holder: it is on the stack's network
# but is its own container, so its source address is never
# $E2E_CANARY's.
#
#   E2E_CLIENT_CERT_TTL=4m eval "$(scripts/e2e/stack.sh up)"
#   scripts/e2e/agent-provisioning.sh
#   scripts/e2e/agent-renewal.sh
#   scripts/e2e/agent-conflict.sh
set -eu

. "$(dirname "$0")/journey.sh"

step "the real agent's current credential is copied for a second holder"
helper "cp /state/client.pem /work/conflict-cert.pem && cp /state/client-key.pem /work/conflict-key.pem && cp /state/token /work/conflict-token.txt" \
  || fail "could not copy $E2E_CANARY_ID's current credential"
ok "copied $E2E_CANARY_ID's live certificate, key and token"

step "the copied credential is presented from a second address"
# $E2E_CANARY has been heartbeating continuously since stack.sh up, so
# birdcage already has its address on file for this certificate; one
# request from this container -- a different address by construction
# -- is what makes the pair.
second_holder="$(helper "curl -sS -w '\nhttp=%{http_code}' --cacert /work/birdcage-ca.pem \
  --cert /work/conflict-cert.pem --key /work/conflict-key.pem \
  -H \"Authorization: Bearer \$(cat /work/conflict-token.txt)\" \
  -X POST '$BIRDCAGE_INGEST_URL/ingest/events' -d '{\"events\":[]}'")" \
  || fail "the second holder's request could not be sent"
case "$second_holder" in
  *http=400*'at least one event'*|*'at least one event'*http=400*) ok "the copied credential authenticates from its own address: $second_holder" ;;
  *) fail "the copied credential did not authenticate on its own (so any conflict below would prove nothing): $second_holder" "$E2E_BIRDCAGE" ;;
esac

# conflict_visible is a poll() command: succeeds once GET /api/canaries
# reports credential_conflict for $E2E_CANARY_ID, carrying two addresses.
conflict_json=""
conflict_visible() {
  conflict_json="$(helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/canaries' \
    | jq -c --arg id '$E2E_CANARY_ID' '.canaries[] | select(.id == \$id) | .credential_conflict'" 2>/dev/null)" || return 1
  [ "$conflict_json" != "null" ] && [ -n "$conflict_json" ]
}

step "credential_conflict appears on the canary status API within 60 seconds, naming both addresses"
poll 60 conflict_visible \
  || fail "credential_conflict never appeared for $E2E_CANARY_ID within 60s of the second holder's request" "$E2E_BIRDCAGE"
printf '%s\n' "$conflict_json" | "$E2E_STACK" write-work conflict-status.json \
  || fail "could not stash the credential_conflict body for inspection"
addr_count="$(helper "jq -er '.addresses | length' /work/conflict-status.json")" \
  || fail "credential_conflict carries no addresses array: $conflict_json"
[ "$addr_count" = "2" ] || fail "credential_conflict names $addr_count address(es), want 2: $conflict_json"
ok "credential_conflict is active, naming both addresses: $conflict_json"

step "birdcage canary revoke ends the credential for both holders"
revoke_output="$("$E2E_STACK" birdcage canary revoke "$E2E_CANARY_ID")" \
  || fail "birdcage canary revoke $E2E_CANARY_ID did not run"
case "$revoke_output" in
  *"revoked agent $E2E_CANARY_ID: "*" token(s), "*" certificate(s)"*) ok "$revoke_output" ;;
  *) fail "revoke did not confirm the expected canary/counts: $revoke_output" ;;
esac

step "both holders are refused (401) on their next request"
holder_a="$(helper "curl -sS -w '\nhttp=%{http_code}' --cacert /work/birdcage-ca.pem \
  --cert /state/client.pem --key /state/client-key.pem \
  -H \"Authorization: Bearer \$(cat /state/token)\" \
  -X POST '$BIRDCAGE_INGEST_URL/ingest/events' -d '{\"events\":[]}'")" \
  || fail "holder A's post-revoke request could not be sent"
case "$holder_a" in
  *http=401*) ok "holder A (the real agent's own credential, presented directly): $holder_a" ;;
  *) fail "holder A was not refused with 401 after revoke: $holder_a" "$E2E_BIRDCAGE" ;;
esac

holder_b="$(helper "curl -sS -w '\nhttp=%{http_code}' --cacert /work/birdcage-ca.pem \
  --cert /work/conflict-cert.pem --key /work/conflict-key.pem \
  -H \"Authorization: Bearer \$(cat /work/conflict-token.txt)\" \
  -X POST '$BIRDCAGE_INGEST_URL/ingest/events' -d '{\"events\":[]}'")" \
  || fail "holder B's post-revoke request could not be sent"
case "$holder_b" in
  *http=401*) ok "holder B (the copied credential): $holder_b" ;;
  *) fail "holder B was not refused with 401 after revoke: $holder_b" "$E2E_BIRDCAGE" ;;
esac

finish
