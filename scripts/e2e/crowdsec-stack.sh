#!/usr/bin/env bash
# crowdsec-stack.sh -- the infrastructure scripts/e2e/crowdsec.sh needs
# (ADR-0014, #4): a real CrowdSec Local API, from the official image
# pinned by digest, LAPI-only, serving TLS from a throwaway CA made for
# this run, with a password machine registered for birdcage -- and
# birdcage restarted with that connection configured the way an
# operator would configure it (docs/configuration.md, "CrowdSec").
#
#   eval "$(scripts/e2e/stack.sh up)"
#   eval "$(scripts/e2e/crowdsec-stack.sh up)"
#   scripts/e2e/crowdsec.sh
#   scripts/e2e/crowdsec-stack.sh down
#   scripts/e2e/stack.sh down
#
# `cscli <args>` runs cscli inside the LAPI container, so a journey can
# ask CrowdSec itself what it holds rather than trusting birdcage's
# account of it.
#
# The machine password is generated inside a volume and never printed:
# it reaches the LAPI through `cscli machines add` run inside that
# container, and reaches birdcage as a mounted file, which is the only
# form birdcage accepts. A second, wrong password file and a second,
# unrelated CA are made at the same time for the journey's negative
# checks.
#
# Everything is named from stack.sh's own E2E_PREFIX, so `down` only
# ever touches what this file created and two parallel pipelines never
# collide.
set -eu

[ -n "${E2E_PREFIX:-}" ] || {
  echo "crowdsec-stack: E2E_PREFIX unset -- run: eval \"\$(scripts/e2e/stack.sh up)\" first" >&2
  exit 2
}

# The one place the fixture's version lives. crowdsecurity/crowdsec
# v1.8.1 (2026-09-03), MIT; the manifest-list digest, so the runner's
# own architecture is pulled. Move this to move the version -- and
# re-read ADR-0014's advisory table when you do, since the pin is what
# keeps the journey off a LAPI with a known flaw (every one listed there
# is fixed by 1.8.0). E2E_REGISTRY_PREFIX is CI's dependency-proxy
# prefix (#128); unset on a workstation, where Docker Hub is pulled
# directly.
CROWDSEC_IMAGE_REF="crowdsecurity/crowdsec@sha256:0f2523fa61ef507f15d953045cface490cc880670c62f2755ced17524107f71a"
CROWDSEC_IMAGE="${E2E_REGISTRY_PREFIX:-docker.io}/$CROWDSEC_IMAGE_REF"

CROWDSEC="${E2E_PREFIX}-crowdsec"
# Three volumes: the LAPI's own certificate and key, its database (the
# image refuses to start without a volume there, by design), and what
# birdcage is handed -- the CA, the password, and the two wrong files.
TLS_VOL="${E2E_PREFIX}-crowdsec-tls"
DATA_VOL="${E2E_PREFIX}-crowdsec-data"
CLIENT_VOL="${E2E_PREFIX}-crowdsec-client"
# stack.sh builds this (build_helper_image) with openssl on board; its
# name is derivable from the prefix, which is how generate_tls below
# gets at it without stack.sh exporting it.
HELPER_IMAGE="${E2E_PREFIX}-helper"
# stack.sh names its birdcage container this way; `down` has to be able
# to find it with nothing but E2E_PREFIX set.
BIRDCAGE_CONTAINER="${E2E_BIRDCAGE:-${E2E_PREFIX}-birdcage}"
MACHINE_ID=birdcage

log() { echo "crowdsec-stack: $*" >&2; }
die() { log "$*"; exit 1; }

create_volumes() {
  local vol
  for vol in "$TLS_VOL" "$DATA_VOL" "$CLIENT_VOL"; do
    docker volume create "$vol" >/dev/null || die "creating volume $vol failed"
  done
}

# generate_tls makes the throwaway CA and the LAPI's leaf (SAN covers
# the container name birdcage connects to, and localhost, which the
# container's own cscli connects to), copies the CA to the client
# volume, and generates the password there. Also made here: a wrong
# password, and a second CA that signed nothing, for the journey's
# negative checks. uid 1000 is what the birdcage image runs as; the
# secrets are readable by it alone.
generate_tls() {
  docker run --rm --volume "$TLS_VOL:/tls" --volume "$CLIENT_VOL:/client" "$HELPER_IMAGE" sh -c "
set -eu
cd /tmp
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout ca-key.pem -out /tls/ca.pem -days 1 \
  -subj /CN=$E2E_PREFIX-crowdsec-throwaway-ca
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout /tls/lapi-key.pem -out lapi.csr -subj /CN=$CROWDSEC
printf 'subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' \
  '$CROWDSEC' > lapi.ext
openssl x509 -req -in lapi.csr -CA /tls/ca.pem -CAkey ca-key.pem \
  -CAcreateserial -days 1 -extfile lapi.ext -out /tls/lapi.pem
rm -f ca-key.pem lapi.csr lapi.ext /tls/ca.srl
chmod 644 /tls/ca.pem /tls/lapi.pem
chmod 600 /tls/lapi-key.pem
cp /tls/ca.pem /client/ca.pem
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout untrusted-key.pem -out /client/untrusted-ca.pem -days 1 \
  -subj /CN=$E2E_PREFIX-unrelated-ca
rm -f untrusted-key.pem
openssl rand -hex 24 > /client/password
openssl rand -hex 24 > /client/wrong-password
chown 1000:1000 /client/ca.pem /client/untrusted-ca.pem /client/password /client/wrong-password
chmod 644 /client/ca.pem /client/untrusted-ca.pem
chmod 400 /client/password /client/wrong-password
[ -s /client/password ] && [ -s /tls/lapi.pem ] && [ -s /tls/lapi-key.pem ]
" || die "generating the throwaway LAPI CA, leaf and password failed"
}

# run_crowdsec starts the LAPI alone: no log processor (DISABLE_AGENT),
# no central-API enrolment (DISABLE_ONLINE_API -- nothing here may
# phone CrowdSec), no hub download at start (NO_HUB_UPGRADE -- nothing
# here may fetch anything). TLS from the files above; the container's
# own cscli trusts the same CA and talks to localhost.
run_crowdsec() {
  docker run --detach --name "$CROWDSEC" --network "$E2E_NET" \
    --pids-limit 256 --memory 512m \
    --volume "$TLS_VOL:/tls-lapi:ro" \
    --volume "$DATA_VOL:/var/lib/crowdsec/data" \
    --volume "$CLIENT_VOL:/client:ro" \
    --env DISABLE_AGENT=true \
    --env DISABLE_ONLINE_API=true \
    --env NO_HUB_UPGRADE=true \
    --env USE_TLS=true \
    --env LAPI_CERT_FILE=/tls-lapi/lapi.pem \
    --env LAPI_KEY_FILE=/tls-lapi/lapi-key.pem \
    --env CACERT_FILE=/tls-lapi/ca.pem \
    --env LOCAL_API_URL=https://localhost:8080 \
    "$CROWDSEC_IMAGE" >/dev/null || die "starting $CROWDSEC failed"
}

# lapi_ready asks the LAPI a real question over its own TLS listener
# from inside the container (cscli logs in as the local machine), not
# merely whether the port is open.
lapi_ready() {
  local attempt
  for attempt in $(seq 1 60); do
    if docker exec "$CROWDSEC" cscli lapi status >/dev/null 2>&1; then
      log "$CROWDSEC answered cscli lapi status (attempt $attempt)"
      return 0
    fi
    sleep 1
  done
  log "$CROWDSEC never answered cscli lapi status; its log follows"
  docker logs "$CROWDSEC" >&2 || true
  die "the LAPI did not come up"
}

# register_machine is the operator's step from docs/configuration.md,
# run where the operator runs it: on the CrowdSec host, with the
# password read from the file birdcage will be given, so the two can
# never be different bytes.
register_machine() {
  docker exec "$CROWDSEC" sh -c "cscli machines add $MACHINE_ID --password \"\$(cat /client/password)\" -f /dev/null --force" >/dev/null 2>&1 \
    || die "registering the $MACHINE_ID machine failed"
  docker exec "$CROWDSEC" cscli machines list -o json | grep -q "\"machineId\": *\"$MACHINE_ID\"" \
    || die "the $MACHINE_ID machine is not in cscli machines list after registration"
}

restart_birdcage_with_crowdsec() {
  "$E2E_STACK" restart-birdcage \
    --volume "$CLIENT_VOL:/crowdsec:ro" \
    --env "BIRDCAGE_CROWDSEC_LAPI_URL=https://$CROWDSEC:8080" \
    --env "BIRDCAGE_CROWDSEC_MACHINE_ID=$MACHINE_ID" \
    --env BIRDCAGE_CROWDSEC_PASSWORD_FILE=/crowdsec/password \
    --env BIRDCAGE_CROWDSEC_CA_FILE=/crowdsec/ca.pem \
    >&2 || die "restarting birdcage with CrowdSec configured failed"
}

up() {
  command -v docker >/dev/null 2>&1 || die "docker is not on PATH"
  [ -n "${E2E_STACK:-}" ] && [ -n "${E2E_NET:-}" ] && [ -n "${E2E_BIRDCAGE:-}" ] \
    || die "E2E_STACK/E2E_NET/E2E_BIRDCAGE unset -- run: eval \"\$(scripts/e2e/stack.sh up)\" first"
  down_crowdsec >/dev/null 2>&1 || true

  docker pull --quiet "$CROWDSEC_IMAGE" >/dev/null || die "pulling $CROWDSEC_IMAGE failed"
  create_volumes
  generate_tls
  run_crowdsec
  lapi_ready
  register_machine
  restart_birdcage_with_crowdsec

  cat <<EOF
export CROWDSEC_SERVER=$CROWDSEC
export CROWDSEC_MACHINE_ID=$MACHINE_ID
export CROWDSEC_STACK=$(cd "$(dirname "$0")" && pwd)/crowdsec-stack.sh
EOF
}

down_crowdsec() {
  docker rm --force "$CROWDSEC" >/dev/null 2>&1 || true
  local vol
  for vol in "$TLS_VOL" "$DATA_VOL" "$CLIENT_VOL"; do
    docker volume rm --force "$vol" >/dev/null 2>&1 || true
  done
  # The image is a shared, digest-pinned pull, not something this file
  # built, so it is left for the next run.
}

# down also removes the birdcage container, which stack.sh owns and
# would remove a moment later anyway: restart_birdcage_with_crowdsec
# started it with this file's client volume mounted, and Docker will
# not delete a volume a container still holds.
down() {
  docker rm --force "$BIRDCAGE_CONTAINER" >/dev/null 2>&1 || true
  down_crowdsec
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  cscli)
    shift
    docker exec "$CROWDSEC" cscli "$@" ;;
  *)
    echo "usage: $0 {up|down|cscli <args>}" >&2
    exit 2 ;;
esac
