#!/usr/bin/env bash
# agent-expiry.sh -- issue #130 live journey (ADR-0012 Part B2): a
# certificate that is never renewed goes through renewal_stalled and
# then not_delivering with reason certificate_expired.
#
# Requires a short-lived certificate (E2E_CLIENT_CERT_TTL), the same as
# agent-renewal.sh. Runs after agent-conflict.sh in the same job --
# agent-conflict.sh ends with $E2E_CANARY_ID revoked, so this journey
# provisions its own throwaway canary rather than reusing it.
#
# "Prevent renewal from succeeding" here means: no agent process is
# ever run for this canary, so POST /ingest/renew is never called for
# it -- store.certificateSignal (internal/store/credhealth.go) derives
# renewal_stalled and certificate expiry from the certificate's own
# NotBefore/NotAfter against the current time, never from whether an
# agent is actually trying, so the state progression is proved either
# way.
#
#   E2E_CLIENT_CERT_TTL=4m eval "$(scripts/e2e/stack.sh up)"
#   scripts/e2e/agent-provisioning.sh
#   scripts/e2e/agent-renewal.sh
#   scripts/e2e/agent-conflict.sh
#   scripts/e2e/agent-expiry.sh
set -eu

. "$(dirname "$0")/journey.sh"

[ -n "${E2E_CLIENT_CERT_TTL:-}" ] || fail "E2E_CLIENT_CERT_TTL is unset -- this journey needs a short-lived certificate to see renewal_stalled and expiry inside a CI job; run stack.sh up with E2E_CLIENT_CERT_TTL set (e.g. 4m)"

step "a throwaway canary is provisioned, and never given an agent to renew it"
"$E2E_STACK" birdcage canary enrol --name "$E2E_CANARY_NAME-expiry" --lane "$E2E_CANARY_LANE" \
  | "$E2E_STACK" write-work expiry-enrol.txt \
  || fail "minting a throwaway enrolment session failed"

expiry_canary_id="$(helper '
set -eu
cd /tmp
token=$(sed -n "s/^.*MOCKINGBIRD_DEPLOY_TOKEN=\([0-9a-f]*\).*$/\1/p" /work/expiry-enrol.txt)
test -n "$token" || { echo "no deploy token for the throwaway canary"; exit 1; }
secret=$(curl -sS --cacert /work/birdcage-ca.pem -X POST "'"$BIRDCAGE_ENROL_URL"'/enrol/hello" \
  -d "{\"token\":\"$token\"}" | jq -er .enrolment_secret)
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -subj "/CN=e2e-expiry-throwaway" -keyout /tmp/expiry-key.pem -out /tmp/expiry-csr.pem 2>/dev/null
body=$(jq -n --arg secret "$secret" --rawfile csr /tmp/expiry-csr.pem \
  "{enrolment_secret:\$secret, csr_pem:\$csr}")
provision=$(curl -sS --cacert /work/birdcage-ca.pem -X POST "'"$BIRDCAGE_ENROL_URL"'/enrol/provision" -d "$body")
printf "%s" "$provision" | jq -er .canary_id
')" || fail "the throwaway expiry canary could not be provisioned: $expiry_canary_id"
[ -n "$expiry_canary_id" ] || fail "provisioning ran but printed no canary id"
ok "throwaway canary $expiry_canary_id provisioned at $(date -u +%FT%TZ); no agent will ever run for it"

# canary_field <field> reads one field of this canary's object from
# GET /api/canaries.
canary_field() {
  helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/canaries' \
    | jq -r --arg id '$expiry_canary_id' --arg f '$1' '.canaries[] | select(.id == \$id) | .[\$f]'" 2>/dev/null
}

renewal_stalled_true() {
  [ "$(canary_field renewal_stalled)" = "true" ]
}

step "the canary reaches renewal_stalled once nothing has renewed it past half-life"
# E2E_CLIENT_CERT_TTL's half-life plus its margin (internal/store's
# renewalStalledMargin -- a tenth of the lifetime for a fixture this
# short) is well under E2E_CLIENT_CERT_TTL itself; bounded generously
# above the full TTL so a slow runner does not turn this into a flake.
poll 300 renewal_stalled_true \
  || fail "renewal_stalled never became true for $expiry_canary_id within 300s (E2E_CLIENT_CERT_TTL=$E2E_CLIENT_CERT_TTL)" "$E2E_BIRDCAGE"
ok "$expiry_canary_id: renewal_stalled"

not_delivering_expired() {
  [ "$(canary_field status)" = "not_delivering" ] && [ "$(canary_field certificate_expired)" = "true" ]
}

step "the canary reaches not_delivering with reason certificate_expired once the certificate actually expires"
poll 300 not_delivering_expired \
  || fail "status never became not_delivering with certificate_expired for $expiry_canary_id within 300s (E2E_CLIENT_CERT_TTL=$E2E_CLIENT_CERT_TTL)" "$E2E_BIRDCAGE"
ok "$expiry_canary_id: status=not_delivering, certificate_expired=true"

finish
