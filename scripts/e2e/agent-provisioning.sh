#!/usr/bin/env bash
# agent-provisioning.sh -- issue #130 live journey (ADR-0012 Part B1):
# the agent makes its own key and birdcage never sees it.
#
# Two things are proved, both against the real stack:
#
#   1. POST /enrol/provision's response body -- captured from a real
#      exchange, not read from source -- carries no private key: no
#      `client_key_pem` field, and no "PRIVATE KEY" PEM block anywhere
#      in the raw body.
#   2. The agent's private key exists only inside the agent's own state
#      volume, mode 0600, and the exact key material never appears
#      anywhere in birdcage's own data volume.
#
# Runs against the credentials stack (BIRDCAGE_TEST_CLIENT_CERT_TTL set
# -- see stack.sh's E2E_CLIENT_CERT_TTL) after stack.sh up has already
# enrolled and provisioned $E2E_CANARY_ID; this file enrols one more
# throwaway canary of its own for the response-shape check, the same
# way scripts/e2e/refusals.sh's "other" canary is provisioned.
#
#   E2E_CLIENT_CERT_TTL=4m eval "$(scripts/e2e/stack.sh up)"
#   scripts/e2e/agent-provisioning.sh
set -eu

. "$(dirname "$0")/journey.sh"

step "a second canary is provisioned through the real endpoints, and its raw response captured"
"$E2E_STACK" birdcage canary enrol --name "$E2E_CANARY_NAME-provision" --lane "$E2E_CANARY_LANE" \
  | "$E2E_STACK" write-work provision-enrol.txt \
  || fail "minting a throwaway enrolment session failed"

provision_canary_id="$(helper '
set -eu
cd /tmp
token=$(sed -n "s/^.*MOCKINGBIRD_DEPLOY_TOKEN=\([0-9a-f]*\).*$/\1/p" /work/provision-enrol.txt)
test -n "$token" || { echo "no deploy token for the throwaway canary"; exit 1; }
secret=$(curl -sS --cacert /work/birdcage-ca.pem -X POST "'"$BIRDCAGE_ENROL_URL"'/enrol/hello" \
  -d "{\"token\":\"$token\"}" | jq -er .enrolment_secret)
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -subj "/CN=e2e-provisioning-throwaway" -keyout /tmp/provision-key.pem -out /tmp/provision-csr.pem 2>/dev/null
body=$(jq -n --arg secret "$secret" --rawfile csr /tmp/provision-csr.pem \
  "{enrolment_secret:\$secret, csr_pem:\$csr}")
curl -sS --cacert /work/birdcage-ca.pem -X POST "'"$BIRDCAGE_ENROL_URL"'/enrol/provision" -d "$body" \
  > /work/provision-raw.json
jq -er .canary_id /work/provision-raw.json
')" || fail "the throwaway canary could not be provisioned: $provision_canary_id"
[ -n "$provision_canary_id" ] || fail "provisioning ran but printed no canary id"
ok "throwaway canary $provision_canary_id provisioned; raw response saved"

step "the raw provision response carries no client_key_pem field"
helper 'jq -e "has(\"client_key_pem\") | not" /work/provision-raw.json >/dev/null' \
  || fail "the provision response carries a client_key_pem field: $(helper 'cat /work/provision-raw.json')"
ok "no client_key_pem field in the response"

step "the raw provision response carries no PRIVATE KEY PEM block anywhere"
if helper 'grep -q "PRIVATE KEY" /work/provision-raw.json'; then
  fail "the provision response body contains a PRIVATE KEY PEM block"
fi
ok "no PRIVATE KEY block anywhere in the response body"

step "the expected fields are still there (the response is not simply empty)"
fields_ok="$(helper 'jq -e "has(\"canary_id\") and has(\"canary_token\") and has(\"client_cert_pem\") and has(\"heartbeat_interval_s\")" /work/provision-raw.json')" \
  || fail "the provision response is missing one of its documented fields: $(helper 'cat /work/provision-raw.json')"
ok "canary_id, canary_token, client_cert_pem and heartbeat_interval_s are all present"

step "the real agent's private key file is mode 0600, inside its own state volume"
mode="$(helper 'stat -c %a /state/client-key.pem')" \
  || fail "could not stat $E2E_CANARY_ID's private key file at /state/client-key.pem"
[ "$mode" = "600" ] || fail "the agent's private key file is mode $mode, want 600"
ok "/state/client-key.pem is mode 600"

step "the exact key material never reaches birdcage's own data volume"
# The middle line of the PEM body is real key bytes, not boilerplate --
# a search string specific to this one key, unlikely to collide with
# anything else stored (the CA's own key material, unrelated). grep -a
# because /data holds the SQLite database file, which is binary.
key_line="$(helper "sed -n '2p' /state/client-key.pem")" \
  || fail "could not read the agent's private key file to build a search string"
[ -n "$key_line" ] || fail "the agent's private key file has no second line to search for"
if helper "grep -qaR -- '$key_line' /data"; then
  fail "the agent's own private key material was found inside birdcage's data volume"
fi
ok "the agent's private key material appears nowhere in birdcage's data volume"

step "no file named client-key.pem exists anywhere under birdcage's data volume"
if helper "find /data -name client-key.pem 2>/dev/null | grep -q ."; then
  fail "a file named client-key.pem exists inside birdcage's own data volume"
fi
ok "birdcage's data volume holds no client-key.pem"

finish
