#!/usr/bin/env bash
# agent-renewal.sh -- issue #130 live journey (ADR-0012 Part B2): the
# real agent renews its own client certificate from half-life, over its
# own heartbeat logic -- nothing here calls POST /ingest/renew itself.
#
# Requires a short-lived certificate (BIRDCAGE_TEST_CLIENT_CERT_TTL --
# see stack.sh's E2E_CLIENT_CERT_TTL), or half-life is three and a half
# days away and this journey would never see it. Runs after
# agent-provisioning.sh in the same job, against $E2E_CANARY_ID -- the
# real, already-running agent stack.sh up enrolled.
#
# Proves two things:
#
#   1. A new certificate serial is in use (on the agent's own disk)
#      after renewal.
#   2. The certificate and token captured BEFORE renewal are refused
#      with 401 once the new certificate has had its first successful
#      use (docs/enrolment.md: the old certificate is only revoked at
#      that point, never at the moment the new one is minted).
#
#   E2E_CLIENT_CERT_TTL=4m eval "$(scripts/e2e/stack.sh up)"
#   scripts/e2e/agent-provisioning.sh
#   scripts/e2e/agent-renewal.sh
set -eu

. "$(dirname "$0")/journey.sh"

[ -n "${E2E_CLIENT_CERT_TTL:-}" ] || fail "E2E_CLIENT_CERT_TTL is unset -- this journey needs a short-lived certificate to see a real half-life inside a CI job; run stack.sh up with E2E_CLIENT_CERT_TTL set (e.g. 4m)"

step "the pre-renewal certificate, key and token are captured"
helper "cp /state/client.pem /work/pre-renew-cert.pem && cp /state/client-key.pem /work/pre-renew-key.pem && cp /state/token /work/pre-renew-token.txt" \
  || fail "could not capture the pre-renewal credential"
old_serial="$(helper "openssl x509 -in /state/client.pem -noout -serial")" \
  || fail "could not read the pre-renewal certificate's serial"
ok "captured $E2E_CANARY_ID's pre-renewal certificate, serial $old_serial"

# new_serial_differs is a poll() command: succeeds once the agent has
# overwritten /state/client.pem with a certificate whose serial is not
# old_serial -- renewal.Manager's on-disk swap (cmd/mockingbird/renewal.go).
new_serial_differs() {
  local current
  current="$(helper "openssl x509 -in /state/client.pem -noout -serial" 2>/dev/null)" || return 1
  [ -n "$current" ] && [ "$current" != "$old_serial" ]
}

step "the agent renews its own certificate past half-life, unprompted"
# Bound generously above whatever E2E_CLIENT_CERT_TTL's half-life plus
# one heartbeat tick (60s, store.DefaultHeartbeatIntervalS) could take:
# 280 one-second attempts.
poll 280 new_serial_differs \
  || fail "no new certificate serial appeared on /state/client.pem within 280s of waiting past half-life" "$E2E_CANARY"
new_serial="$(helper "openssl x509 -in /state/client.pem -noout -serial")" \
  || fail "could not read the renewed certificate's serial"
[ "$new_serial" != "$old_serial" ] || fail "the certificate serial did not actually change ($new_serial)"
ok "certificate renewed: serial $old_serial -> $new_serial"

step "the renewed certificate authenticates (control)"
control="$(helper "curl -sS -w '\nhttp=%{http_code}' --cacert /work/birdcage-ca.pem \
  --cert /state/client.pem --key /state/client-key.pem \
  -H \"Authorization: Bearer \$(cat /state/token)\" \
  -X POST '$BIRDCAGE_INGEST_URL/ingest/events' -d '{\"events\":[]}'")" \
  || fail "the renewed-certificate control request could not be sent"
case "$control" in
  *http=400*'at least one event'*|*'at least one event'*http=400*) ok "the renewed certificate authenticates (400 from the batch handler)" ;;
  *) fail "the renewed certificate did not authenticate: $control" "$E2E_BIRDCAGE" ;;
esac

# old_cert_refused is a poll() command: the old certificate stays valid
# until the new one's first successful use (docs/enrolment.md), which
# the control request above just caused -- but that use has to be
# recorded before the old one is actually revoked, so this polls rather
# than asserting once.
old_cert_refused() {
  local attempt
  attempt="$(helper "curl -sS -w '\nhttp=%{http_code}' --cacert /work/birdcage-ca.pem \
    --cert /work/pre-renew-cert.pem --key /work/pre-renew-key.pem \
    -H \"Authorization: Bearer \$(cat /work/pre-renew-token.txt)\" \
    -X POST '$BIRDCAGE_INGEST_URL/ingest/events' -d '{\"events\":[]}'" 2>/dev/null)" || return 1
  case "$attempt" in
    *http=401*) return 0 ;;
    *) return 1 ;;
  esac
}

step "the pre-renewal certificate and token are refused (401) after the new certificate's first use"
poll 60 old_cert_refused \
  || fail "the old certificate+token was not refused with 401 within 60s of the new certificate's first successful use" "$E2E_BIRDCAGE"
last_attempt="$(helper "curl -sS -w '\nhttp=%{http_code}' --cacert /work/birdcage-ca.pem \
  --cert /work/pre-renew-cert.pem --key /work/pre-renew-key.pem \
  -H \"Authorization: Bearer \$(cat /work/pre-renew-token.txt)\" \
  -X POST '$BIRDCAGE_INGEST_URL/ingest/events' -d '{\"events\":[]}'")" \
  || fail "the final confirming request with the old credential could not be sent"
case "$last_attempt" in
  *http=401*'"error":"unauthorized"'*|*'"error":"unauthorized"'*http=401*) ok "old certificate+token refused: $last_attempt" ;;
  *) fail "the old certificate+token request did not read as a clean 401 unauthorized: $last_attempt" "$E2E_BIRDCAGE" ;;
esac

finish
