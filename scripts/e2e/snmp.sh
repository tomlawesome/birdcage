#!/usr/bin/env bash
# snmp.sh -- issue #88's live check: a real SNMP client's GetRequest
# against the canary's own SNMP listener (internal/agent/snmp, a plain
# UDP reader with no OpenCanary module and no scapy behind it -- see
# that package's doc comment) produces a real alert in birdcage, with
# the community string this journey mints as its marker.
#
# The base stack's canary already runs this listener: it is wired into
# every mockingbird process (cmd/mockingbird/snmp.go), on by default, no
# second canary or extra server needed -- unlike scripts/e2e/smb.sh,
# which needs a real smbd on the other end. The only extra
# infrastructure this journey needs is a client that can speak SNMP;
# build/e2e-snmp is a CI-only image for that, in the same house style as
# build/e2e-samba, built and removed by this file alone.
#
#   eval "$(scripts/e2e/stack.sh up)"
#   scripts/e2e/snmp.sh
#   scripts/e2e/stack.sh down
set -eu

. "$(dirname "$0")/journey.sh"

[ -n "${E2E_PREFIX:-}" ] || {
  echo "snmp: E2E_PREFIX unset -- run: eval \"\$(scripts/e2e/stack.sh up)\" first" >&2
  exit 2
}

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SNMP_IMAGE="${E2E_PREFIX}-snmp-image"

build_snmp_image() {
  if docker image inspect "$SNMP_IMAGE" >/dev/null 2>&1; then
    return 0
  fi
  # --build-arg BASE_IMAGE: CI's dependency-proxy pin (refs #128,
  # .gitlab-ci.yml) when set, the Dockerfile's own default on a workstation.
  docker build --build-arg BASE_IMAGE="${DEBIAN_TRIXIE_SLIM_IMAGE:-debian:trixie-slim}" \
    --file "$REPO_ROOT/build/e2e-snmp/Dockerfile" --tag "$SNMP_IMAGE" "$REPO_ROOT" >/dev/null \
    || { echo "snmp: building $SNMP_IMAGE failed" >&2; exit 1; }
}

# Only ever an image tag this journey named itself (E2E_PREFIX-prefixed,
# the same guard stack.sh's own image cleanup uses), and removed on
# every exit path -- pass or fail -- so a failed run leaves nothing more
# behind than a passing one does.
cleanup_snmp_image() {
  case "$SNMP_IMAGE" in
    "$E2E_PREFIX"*) docker image rm --force "$SNMP_IMAGE" >/dev/null 2>&1 || true ;;
  esac
}
trap cleanup_snmp_image EXIT

build_snmp_image

# The marker is this run's own random hex, riding in the community
# string -- the one field #88's design settled on as what tells a real
# operator's monitoring poll from an attacker's guess (see
# internal/agent/snmp's package doc). Not chosen by the code under test,
# so matching it back out of an alert is evidence about this run and no
# other.
MARKER="e2e-snmp-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"

step "a real snmpget reaches the canary's SNMP listener with $MARKER as the community string"
# -r 0 -t 2: no retries, a 2 second timeout. A timeout is the expected
# outcome, not a failure -- internal/agent/snmp never replies, by
# design (issue #88) -- so snmpget's own nonzero exit status here is
# discarded; the packet having gone out on the wire is all this step
# needs, and the next step proves that from birdcage's side.
docker run --rm --network "$E2E_NET" "$SNMP_IMAGE" \
  snmpget -v2c -c "$MARKER" -r 0 -t 2 "$E2E_CANARY" 1.3.6.1.2.1.1.1.0 >/dev/null 2>&1 || true
ok "snmpget sent (no reply is expected -- this listener never answers)"

step "the request reached OpenCanary's own wire shape and then birdcage"
# fromjson on .raw: /api/alerts stores OpenCanary's whole event as a raw
# JSON string (internal/store.Alert.Raw), so logdata.COMMUNITY_STRING is
# a field inside that string, not of the alert object itself -- the same
# shape smb.sh's own poll uses for logdata.FILENAME.
poll 30 helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/alerts?service=snmp' \
  | jq -e --arg m '$MARKER' '[.alerts[] | (.raw | fromjson | .logdata.COMMUNITY_STRING // \"\") | select(. == \$m)] | length > 0'" \
  || fail "/api/alerts never held an snmp event carrying community string $MARKER after 30 attempts" "$E2E_CANARY" "$E2E_BIRDCAGE"

alert="$(helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/alerts?service=snmp' \
  | jq -c --arg m '$MARKER' '[.alerts[] | select((.raw | fromjson | .logdata.COMMUNITY_STRING // \"\") == \$m)][0] |
      {id, service, dest_port, community: (.raw | fromjson | .logdata.COMMUNITY_STRING), requests: (.raw | fromjson | .logdata.REQUESTS)}'")"
case "$alert" in
  *'"dest_port":161'*) ok "alert on port 161: $alert" ;;
  *) fail "the snmp alert does not name port 161: $alert" "$E2E_CANARY" "$E2E_BIRDCAGE" ;;
esac
case "$alert" in
  *'1.3.6.1.2.1.1.1.0'*) ok "alert names the requested OID: $alert" ;;
  *) fail "the snmp alert does not name the requested OID: $alert" "$E2E_CANARY" ;;
esac

finish
