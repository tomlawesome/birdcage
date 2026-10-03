#!/usr/bin/env bash
# dashboard-own-ca.sh -- issue #63's new default: with no operator
# certificate configured, birdcage mints the dashboard's HTTPS
# certificate from its own CA rather than refusing to start.
#
# This is deliberately a separate stack run from enrol-and-hit.sh /
# refusals.sh, not a third journey added to the same one: those two
# run the dashboard in the operator-certificate mode on purpose (see
# stack.sh's own comment on generate_tls), because that is the one
# mode a real deployment must not lose coverage of. This file needs
# the stack brought up with E2E_DASHBOARD_MODE=own-ca instead --
#
#   E2E_DASHBOARD_MODE=own-ca eval "$(scripts/e2e/stack.sh up)"
#   scripts/e2e/dashboard-own-ca.sh
#   scripts/e2e/stack.sh down
#
# and refuses to run against a stack brought up any other way, so a
# green run here always means what it says.
set -eu

. "$(dirname "$0")/journey.sh"

[ "${E2E_DASHBOARD_MODE:-}" = own-ca ] || {
  echo "dashboard-own-ca: E2E_DASHBOARD_MODE=$( [ -n "${E2E_DASHBOARD_MODE:-}" ] && echo "${E2E_DASHBOARD_MODE}" || echo "(unset)" ), want own-ca -- bring the stack up with E2E_DASHBOARD_MODE=own-ca first" >&2
  exit 2
}

step "birdcage logged that it minted the dashboard certificate from its own CA"
# The log line is the operator's only way to see, without guessing,
# which names a browser warning is or isn't about (issue #63's own
# "log, at startup, exactly which names the certificate covers"
# requirement) -- so the assertion is on that line, not just on the
# connection working, which a bug in the log message could still pass.
docker logs "$E2E_BIRDCAGE" 2>&1 | grep -q "dashboard TLS mode: certificate minted from birdcage's own CA" \
  || fail "birdcage did not log that it minted the dashboard certificate from its own CA"
docker logs "$E2E_BIRDCAGE" 2>&1 | grep "dashboard TLS mode: certificate minted from birdcage's own CA" | grep -q "$E2E_BIRDCAGE" \
  || fail "the logged certificate coverage did not name $E2E_BIRDCAGE, which BIRDCAGE_DASHBOARD_HOST asked for"
ok "birdcage logged the mode and the names it minted for"

step "the certificate's SANs are exactly what BIRDCAGE_DASHBOARD_HOST asked for"
# Read back the certificate the dashboard is actually serving -- not
# birdcage's own log line a second time, but the wire artifact a
# browser would see -- and check its Subject Alternative Name entry by
# name. This is the check the owner singled out: "a certificate for the
# wrong name still warns in the browser even after the operator has
# installed birdcage's CA, which would defeat the whole change."
sans="$(helper "openssl s_client -connect $E2E_BIRDCAGE:8080 -servername $E2E_BIRDCAGE </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName")" \
  || fail "could not read the dashboard certificate's SANs"
case "$sans" in
  *"DNS:$E2E_BIRDCAGE"*) ok "SANs cover $E2E_BIRDCAGE: $sans" ;;
  *) fail "the certificate's SANs did not cover $E2E_BIRDCAGE (BIRDCAGE_DASHBOARD_HOST): $sans" ;;
esac

step "a client that trusts birdcage's CA completes a request over HTTPS"
trusted="$(helper "curl -sS -w '\nhttp=%{http_code}' --cacert /work/birdcage-ca.pem https://$E2E_BIRDCAGE:8080/api/alerts")" \
  || fail "the request with birdcage's own CA trusted could not be sent: $trusted"
case "$trusted" in
  *http=200*'"alerts"'*|*'"alerts"'*http=200*) ok "200 with an alerts body, trusting birdcage's CA" ;;
  *) fail "a client trusting birdcage's own CA was not answered 200 with an alerts body: $trusted" ;;
esac

step "a client that does not trust birdcage's CA is refused"
# Expected to fail the TLS handshake -- birdcage's CA is self-signed and
# not in any system trust store -- so the exit status is captured
# rather than asserted away, and what is asserted is *why* it failed:
# an untrusted-issuer TLS error, never an HTTP status.
set +e
untrusted="$(helper "curl -sS -o /dev/null -w 'http=%{http_code}' https://$E2E_BIRDCAGE:8080/api/alerts" 2>&1)"
untrusted_status=$?
set -e
[ "$untrusted_status" -ne 0 ] || fail "a request with no trusted CA succeeded: $untrusted"
case "$untrusted" in
  *"unable to get local issuer certificate"*|*"self-signed certificate"*|*"certificate verify failed"*)
    ok "refused for an untrusted issuer: $untrusted" ;;
  *) fail "the request failed, but not for an untrusted-CA reason: $untrusted" ;;
esac
case "$untrusted" in
  *http=200*) fail "an HTTP 200 was reached despite the untrusted certificate: $untrusted" ;;
  *) ok "no successful HTTP response was ever reached" ;;
esac

finish
