#!/usr/bin/env bash
# refusals.sh -- issue #78 journey 2: the three things that must be
# refused, each checked for the stated reason rather than for having
# failed somehow.
#
# That distinction is the whole journey. A request that fails because
# the harness sent it to the wrong port also "fails"; so does one
# refused for running out of rate limit. So every step here reads back
# the reason the product itself recorded -- the log line, the TLS
# alert, the audit entry -- and one step proves the contrast: the same
# request with the right certificate gets past authentication.
#
#   eval "$(scripts/e2e/stack.sh up)"
#   scripts/e2e/refusals.sh
set -eu

. "$(dirname "$0")/journey.sh"

step "a burned deploy token is refused"
# The token is read inside the container, out of the work volume, and
# never passes through this script: a live deploy token in a CI log is
# a credential in a CI log, even a throwaway one.
reuse="$(helper '
set -eu
token=$(sed -n "s/^.*MOCKINGBIRD_DEPLOY_TOKEN=\([0-9a-f]*\).*$/\1/p" /work/enrol-output.txt)
test -n "$token" || { echo "no deploy token in the stored enrolment output"; exit 1; }
curl -sS -w "\nhttp=%{http_code}" --cacert /work/birdcage-ca.pem \
  -X POST "'"$BIRDCAGE_ENROL_URL"'/enrol/hello" -d "{\"token\":\"$token\"}"
')" || fail "POST /enrol/hello could not be reached at all: $reuse"
case "$reuse" in
  *http=401*) ;;
  *) fail "re-using the deploy token was not refused with 401: $reuse" ;;
esac
case "$reuse" in
  *'{"error":"refused"}'*) ok "401 and the uniform refusal body" ;;
  *) fail "the refusal body was not the uniform one: $reuse" ;;
esac
# The reason, not just the refusal: birdcage logs a reuse loudly on
# purpose (#47 -- "a lost race *is* the attack signature"), so a 401
# that is not accompanied by this line means the token was refused for
# some other reason and this step proved nothing.
docker logs "$E2E_BIRDCAGE" 2>&1 | grep -q 'deploy token reused after it was burned' \
  || fail "birdcage did not log the reuse, so the 401 was refused for some other reason"
ok "birdcage logged the reuse as hostile"

step "POST /ingest/events with no client certificate is refused at the handshake"
# Expected to fail, so the exit status is captured rather than asserted
# away -- and what is asserted is that it failed *in the TLS
# handshake*: the ingest listener is ClientAuth: RequireAndVerifyClientCert,
# so the connection must never get as far as an HTTP status code at
# all. A 401 here would be a finding, not a pass.
set +e
nocert="$(helper "curl -sS -o /dev/null -w 'http=%{http_code}' --cacert /work/birdcage-ca.pem -X POST '$BIRDCAGE_INGEST_URL/ingest/events' -d '{\"events\":[]}'" 2>&1)"
nocert_status=$?
set -e
[ "$nocert_status" -ne 0 ] || fail "a request with no client certificate succeeded: $nocert"
case "$nocert" in
  *"certificate required"*) ok "refused by TLS alert: certificate required" ;;
  *) fail "the request failed, but not with a certificate-required TLS alert: $nocert" ;;
esac
case "$nocert" in
  *http=000*) ok "no HTTP status was ever reached" ;;
  *) fail "the connection reached an HTTP status, so the listener is not requiring a client certificate: $nocert" ;;
esac

step "a client certificate naming a different canary is refused"
# A second canary, enrolled through the real endpoints rather than by
# forging a certificate: POST /enrol/hello then POST /enrol/provision
# is exactly what the agent does, and it is the only way to get a
# certificate this CA signed whose CN names somebody else.
#
# Its printed output carries a live deploy token, so it goes straight
# into the work volume without passing through a terminal.
"$E2E_STACK" birdcage canary enrol --name "$E2E_CANARY_NAME-other" --lane "$E2E_CANARY_LANE" \
  | "$E2E_STACK" write-work other-enrol.txt \
  || fail "minting a second enrolment session failed"

other="$(helper '
set -eu
cd /tmp
token=$(sed -n "s/^.*MOCKINGBIRD_DEPLOY_TOKEN=\([0-9a-f]*\).*$/\1/p" /work/other-enrol.txt)
test -n "$token" || { echo "no deploy token for the second canary"; exit 1; }
secret=$(curl -sS --cacert /work/birdcage-ca.pem -X POST "'"$BIRDCAGE_ENROL_URL"'/enrol/hello" \
  -d "{\"token\":\"$token\"}" | jq -er .enrolment_secret)
provision=$(curl -sS --cacert /work/birdcage-ca.pem -X POST "'"$BIRDCAGE_ENROL_URL"'/enrol/provision" \
  -d "{\"enrolment_secret\":\"$secret\"}")
printf "%s" "$provision" | jq -er .client_cert_pem > /work/other-cert.pem
printf "%s" "$provision" | jq -er .client_key_pem > /work/other-key.pem
printf "%s" "$provision" | jq -er .canary_id
')" || fail "the second canary could not be provisioned: $other"
[ -n "$other" ] || fail "the second canary was provisioned without a canary id"
ok "second canary $other holds its own client certificate"

mismatch="$(helper "curl -sS -w '\nhttp=%{http_code}' --cacert /work/birdcage-ca.pem \
  --cert /work/other-cert.pem --key /work/other-key.pem \
  -H \"Authorization: Bearer \$(cat /state/token)\" \
  -X POST '$BIRDCAGE_INGEST_URL/ingest/events' -d '{\"events\":[]}'")" \
  || fail "the mismatched-certificate request could not be sent: $mismatch"
case "$mismatch" in
  *http=401*) ok "401 for $E2E_CANARY_ID's bearer token presented with $other's certificate" ;;
  *) fail "a bearer token presented with another canary's certificate was not refused: $mismatch" ;;
esac

# The contrast, so the 401 above cannot be explained by anything else
# about the request: the identical call with this canary's *own*
# certificate gets past authentication and is answered by the batch
# handler (400, "batch must contain at least one event").
contrast="$(helper "curl -sS -w '\nhttp=%{http_code}' --cacert /work/birdcage-ca.pem \
  --cert /state/client.pem --key /state/client-key.pem \
  -H \"Authorization: Bearer \$(cat /state/token)\" \
  -X POST '$BIRDCAGE_INGEST_URL/ingest/events' -d '{\"events\":[]}'")" \
  || fail "the control request could not be sent: $contrast"
case "$contrast" in
  *http=400*'at least one event'*|*'at least one event'*http=400*)
    ok "the same token with its own certificate authenticates (400 from the batch handler)" ;;
  *) fail "the control request did not reach the batch handler, so the 401 above proves nothing: $contrast" ;;
esac

# And the reason birdcage recorded: ingest.client_cert_mismatch names
# both the canary the token resolved to and the CN that was presented.
#
# There is no API for the audit log yet, so this reads the database
# directly -- through
# `stack.sh query`, which speaks to whichever engine is underneath, so
# this step proves itself on Postgres as well as SQLite.
audit="$("$E2E_STACK" query "select reason from audit_log where action = 'ingest.client_cert_mismatch' order by id desc limit 1")" \
  || fail "could not read the audit log: $audit"
case "$audit" in
  *"$E2E_CANARY_ID"*"$other"*) ok "audited: $audit" ;;
  *) fail "no ingest.client_cert_mismatch entry naming $E2E_CANARY_ID and $other; got: ${audit:-<nothing>}" ;;
esac

finish
