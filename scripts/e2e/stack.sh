#!/usr/bin/env bash
# stack.sh -- stand up the real birdcage stack (both shipped images, a
# private network, real TLS, one enrolled canary) and hand back the
# environment every scripts/e2e/*.sh journey runs against.
#
# Shape borrowed from mikroview's scripts/live-container.sh, which
# proved it: `up` prints shell assignments you eval, `down` tears
# everything down, `logs` shows a container's output. Names are fixed
# (E2E_PREFIX), so `down` still cleans up after a run that was killed
# half way.
#
#   eval "$(scripts/e2e/stack.sh up)"
#   scripts/e2e/enrol-and-hit.sh
#   scripts/e2e/refusals.sh
#   scripts/e2e/stack.sh down
#
# Add a journey by adding a file next to this one (see #79 port scan,
# #80 mail, #81 dashboard). Do not add journey logic here: this file
# deploys the stack and nothing else, exactly as live-container.sh
# stays out of the scenarios that import it.
#
# What it deploys, and why each part is the real thing rather than a
# stand-in:
#
#   - Both images, built from this checkout by the same Dockerfiles
#     `docker build` ships, so a journey exercises the distroless
#     runtime, the non-root uid and the hardening flags, not a
#     `go build` on the host.
#   - The dashboard listener runs HTTPS with an operator-supplied
#     certificate (issue #63's ModeCert) minted here from a throwaway
#     CA -- never the loopback-plain-HTTP escape hatch, which is the
#     one mode a real deployment must not be in.
#   - The ingest (8443) and enrolment (8444) listeners serve
#     certificates birdcage's own CA mints, and BIRDCAGE_ADVERTISE_HOST
#     is the container name, so the canary reaches birdcage at the
#     address that certificate actually covers.
#   - The canary is enrolled by running the `docker run` command
#     `birdcage canary enrol` printed, not a hand-written equivalent --
#     see run_printed_command below for the three things the test
#     environment forces us to change and why.
#
# Storage is either engine the product ships. E2E_BACKEND=postgres
# starts a Postgres on the stack's network and points birdcage at it;
# the default is SQLite. E2E_DATABASE_URL overrides both and aims the
# stack at a server somebody else is running.
#
# Journeys never ask which engine is underneath: anything they cannot
# reach through the API goes through `stack.sh query`, which speaks to
# whichever one is there. That is deliberate -- a journey written
# against SQLite proves nothing about Postgres, which is how a project
# ends up saying it supports an engine it only compiles against.
set -eu

E2E_PREFIX="${E2E_PREFIX:-birdcage-e2e}"

NET="$E2E_PREFIX-net"
BIRDCAGE="$E2E_PREFIX-birdcage"
CANARY="$E2E_PREFIX-canary"
HELPER_IMAGE="$E2E_PREFIX-helper"
DATA_VOL="$E2E_PREFIX-data"
TLS_VOL="$E2E_PREFIX-tls"
WORK_VOL="$E2E_PREFIX-work"
PG="$E2E_PREFIX-postgres"
STATE_VOL="$E2E_PREFIX-state"
LOG_VOL="$E2E_PREFIX-log"

# Default tags are prefixed, which is also what makes `down` safe to
# let remove them: it only ever deletes an image tag beginning with
# E2E_PREFIX, so pointing this at an image you built yourself
# (E2E_BIRDCAGE_IMAGE=birdcage:local) never deletes it.
BIRDCAGE_IMAGE="${E2E_BIRDCAGE_IMAGE:-$E2E_PREFIX-birdcage-image}"
MOCKINGBIRD_IMAGE="${E2E_MOCKINGBIRD_IMAGE:-$E2E_PREFIX-mockingbird-image}"

# E2E_BACKEND picks the database: sqlite (the default) or postgres.
# Postgres is not an exotic variant to get to later -- it is one of the
# two engines the product ships, migrations behave differently on it,
# and a journey that only ever ran on SQLite has not tested it. `up`
# starts the server itself, so a caller says E2E_BACKEND=postgres and
# nothing else.
#
# E2E_DATABASE_URL still works and wins: it points the stack at a
# Postgres somebody else is running.
E2E_BACKEND="${E2E_BACKEND:-sqlite}"

# The canary name and lane journey 1 asserts on.
CANARY_NAME="${E2E_CANARY_NAME:-e2e-canary}"
CANARY_LANE="${E2E_CANARY_LANE:-e2e}"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

log() { echo "stack: $*" >&2; }
die() { echo "stack: $*" >&2; exit 1; }

# ---------------------------------------------------------------------
# helper -- one throwaway container with curl, openssl and sqlite, on
# the stack's network, holding every volume a journey needs to look
# into. Built once by `up` so a journey does not pay for `apk add` on
# every assertion.
#
# Mounts: /tls (the throwaway dashboard CA and leaf), /work (this
# harness's own scratch: the enrolment output, birdcage's CA
# certificate), /data (birdcage's data directory, read-only -- the
# SQLite database and the CA live here), /state (the canary's state
# directory, read-only -- its bearer token and client certificate).
# ---------------------------------------------------------------------
helper() {
  docker run --rm --network "$NET" \
    --volume "$TLS_VOL:/tls:ro" \
    --volume "$WORK_VOL:/work" \
    --volume "$DATA_VOL:/data:ro" \
    --volume "$STATE_VOL:/state:ro" \
    "$HELPER_IMAGE" sh -c "$*"
}

# helper_in is helper with stdin attached, for writing a file into the
# work volume without it ever touching the host filesystem (the runner
# job container's filesystem is not the docker host's).
helper_in() {
  docker run --rm --interactive \
    --volume "$WORK_VOL:/work" \
    "$HELPER_IMAGE" sh -c "$*"
}

build_helper_image() {
  # Built from a Dockerfile on stdin: no context to send, and nothing
  # written to the repository.
  printf 'FROM alpine:3.24\nRUN apk add --no-cache curl openssl sqlite jq\n' \
    | docker build --quiet --tag "$HELPER_IMAGE" - >/dev/null
}

build_image() { # build_image <tag> <dockerfile>
  if docker image inspect "$1" >/dev/null 2>&1; then
    log "using existing image $1"
    return 0
  fi
  log "building $1 from $2 (this takes a few minutes the first time)"
  docker build --file "$REPO_ROOT/$2" --tag "$1" "$REPO_ROOT" >/dev/null \
    || die "building $1 from $2 failed"
}

# ---------------------------------------------------------------------
# generate_tls -- a throwaway CA and a leaf for the dashboard listener,
# the same shape test:image:mockingbird already uses for its state
# volume. The leaf's SANs must cover the container name, because that
# is the host a journey's curl asks for; without them every request
# fails certificate verification and the journey reads as a product
# failure rather than a harness one.
#
# The CA key is deleted as soon as the leaf is signed: nothing else is
# ever issued from it, and leaving it in a volume a journey mounts
# would be a private key sitting somewhere it need not be.
# ---------------------------------------------------------------------
generate_tls() {
  # Its own container rather than helper(), which mounts /tls read-only
  # on purpose: a journey has no business rewriting the certificate the
  # thing under test is serving.
  docker run --rm --volume "$TLS_VOL:/tls" "$HELPER_IMAGE" sh -c "
set -eu
cd /tmp
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout ca-key.pem -out /tls/dashboard-ca.pem -days 1 \
  -subj /CN=$E2E_PREFIX-throwaway-ca
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout /tls/server-key.pem -out server.csr -subj /CN=$BIRDCAGE
printf 'subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' \
  '$BIRDCAGE' > server.ext
openssl x509 -req -in server.csr -CA /tls/dashboard-ca.pem -CAkey ca-key.pem \
  -CAcreateserial -days 1 -extfile server.ext -out /tls/server.pem
rm -f ca-key.pem server.csr server.ext /tls/dashboard-ca.srl
# uid 1000 is what the birdcage image runs as; it must be able to read
# both files it was pointed at, and only it should read the key.
chown 1000:1000 /tls/server.pem /tls/server-key.pem /tls/dashboard-ca.pem
chmod 644 /tls/server.pem /tls/dashboard-ca.pem
chmod 600 /tls/server-key.pem
" || die "generating the throwaway dashboard CA and leaf failed"
}

# start_postgres runs the second engine the product supports.
#
# Plain postgres:18-alpine with no TLS, unlike mikroview's equivalent,
# because birdcage does not currently refuse a plaintext connection to
# its database -- see the note in `up`. Nothing here should be read as
# saying that is right.
start_postgres() {
  docker run --detach --name "$PG" --network "$NET" \
    --env POSTGRES_PASSWORD=e2e --env POSTGRES_DB=birdcage \
    --pids-limit 128 --memory 512m \
    postgres:18-alpine >/dev/null || die "starting $PG failed"

  # pg_isready, not a port check: Postgres accepts connections on 5432
  # well before it will answer a query, and a port check hands over a
  # server that then refuses the first migration.
  local attempt
  for attempt in $(seq 1 60); do
    if docker exec "$PG" pg_isready -U postgres -d birdcage >/dev/null 2>&1; then
      log "postgres ready on attempt $attempt"
      return 0
    fi
    sleep 1
  done
  log "postgres never became ready; its log follows"
  docker logs "$PG" >&2 || true
  die "postgres did not become ready"
}

start_birdcage() {
  # Hardening matches test:image:birdcage: read-only root, every
  # capability dropped, no-new-privileges. A journey that only passes
  # with these relaxed is a finding about the shipped image, not a
  # harness problem. (The canary is the opposite case -- see
  # run_printed_command.)
  local db_env=()
  if [ -n "${E2E_DATABASE_URL:-}" ]; then
    db_env=(--env "DATABASE_URL=$E2E_DATABASE_URL")
  fi
  docker run --detach --name "$BIRDCAGE" --network "$NET" \
    --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 128 --memory 512m --cpus 1.0 \
    --volume "$DATA_VOL:/var/lib/birdcage" \
    --volume "$TLS_VOL:/tls:ro" \
    --env BIRDCAGE_HTTP_ADDR=:8080 \
    --env BIRDCAGE_HTTP_TLS_CERT=/tls/server.pem \
    --env BIRDCAGE_HTTP_TLS_KEY=/tls/server-key.pem \
    --env BIRDCAGE_INGEST_ADDR=:8443 \
    --env BIRDCAGE_ENROL_ADDR=:8444 \
    --env BIRDCAGE_ADVERTISE_HOST="$BIRDCAGE" \
    "${db_env[@]}" \
    "$BIRDCAGE_IMAGE" >/dev/null || die "starting $BIRDCAGE failed"

  local attempt
  for attempt in $(seq 1 60); do
    if helper "curl -sS --cacert /tls/dashboard-ca.pem https://$BIRDCAGE:8080/api/alerts" 2>/dev/null | grep -q '"alerts"'; then
      log "dashboard answered over TLS on attempt $attempt"
      return 0
    fi
    sleep 1
  done
  log "the dashboard never answered GET /api/alerts over TLS; birdcage log follows"
  docker logs "$BIRDCAGE" >&2 || true
  die "birdcage did not become ready"
}

# copy_birdcage_ca puts birdcage's *own* CA certificate (the one that
# signs the ingest and enrolment listeners' leaves, not the throwaway
# dashboard CA above) where journeys can hand it to curl.
copy_birdcage_ca() {
  helper "set -eu; cp /data/ca/ca.pem /work/birdcage-ca.pem; chmod 644 /work/birdcage-ca.pem" \
    || die "could not read birdcage's CA certificate from its data volume"
}

# ---------------------------------------------------------------------
# enrol_canary -- mint a deploy token the way an operator does, and
# keep the whole printed output for journey 1 to check and for
# run_printed_command below to execute.
#
# The two addresses are set first because `birdcage canary enrol`
# refuses to mint until they are (docs/enrolment.md). Both are
# .invalid: nothing in this stack sends mail, and a real-looking
# address in a test fixture is an address somebody eventually mails.
# ---------------------------------------------------------------------
enrol_canary() {
  docker exec "$BIRDCAGE" /birdcage settings set admin_approval_address e2e-admin@e2e.invalid >/dev/null \
    || die "setting admin_approval_address failed"
  docker exec "$BIRDCAGE" /birdcage settings set release_address e2e-release@e2e.invalid >/dev/null \
    || die "setting release_address failed"

  local output
  # MOCKINGBIRD_IMAGE is the product's own documented override for the
  # image the printed command names, so using it means the printed
  # command needs no editing on that line at all.
  output="$(docker exec --env "MOCKINGBIRD_IMAGE=$MOCKINGBIRD_IMAGE" "$BIRDCAGE" \
    /birdcage canary enrol --name "$CANARY_NAME" --lane "$CANARY_LANE")" \
    || die "birdcage canary enrol failed"

  # Straight into the work volume. The output carries the deploy token,
  # so it is never echoed to a terminal or a CI log by this harness.
  printf '%s\n' "$output" | helper_in "cat > /work/enrol-output.txt; chmod 600 /work/enrol-output.txt" \
    || die "could not store the enrolment output"
}

# ---------------------------------------------------------------------
# run_printed_command -- take the `docker run` command birdcage printed
# and run it verbatim except for what this test environment forces.
# This is the point of journey 1: if what we print does not work, this
# is what finds out, so the command is edited by rule rather than
# rewritten.
#
# Exactly three edits, all of them collisions with the test
# environment rather than disagreements with the product:
#
#   1. --name mockingbird -> --name $CANARY. A fixed name cannot be
#      used by a harness that must not collide with a second run, or
#      with a canary somebody already has on this machine.
#   2. the two named volumes -> the prefixed ones, for the same reason,
#      and so `down` can delete them without touching a real canary's
#      state.
#   3. --network $NET is added. The printed command has no --network
#      because an operator's canary is on a real network; here both
#      containers have to be on the harness's private one for the
#      canary to resolve $BIRDCAGE at all.
#
# Everything else -- -d, --restart, --init, the sysctl, --cap-add
# NET_RAW, all three -e flags, the image -- runs exactly as printed.
# Note what is *not* added: --security-opt no-new-privileges, which the
# printed command deliberately omits, because it would make the kernel
# ignore the agent's file capability and turn port-scan detection off
# (docs/enrolment.md, and the trap comment in test:image:mockingbird).
# ---------------------------------------------------------------------
run_printed_command() {
  local command
  command="$(helper "
sed -n '/^docker run /,/[^\\\\]\$/p' /work/enrol-output.txt \
  | sed -e 's|^docker run -d |docker run -d --network $NET |' \
        -e 's|--name mockingbird |--name $CANARY |' \
        -e 's|-v mockingbird-state:|-v $STATE_VOL:|' \
        -e 's|-v mockingbird-log:|-v $LOG_VOL:|'
")" || die "could not read the printed docker run command"

  case "$command" in
    docker\ run\ *"$CANARY"*"$MOCKINGBIRD_IMAGE"*) ;;
    *) die "the printed docker run command did not look the way this harness expects; got: $(printf '%s' "$command" | sed 's/MOCKINGBIRD_DEPLOY_TOKEN=[^ ]*/MOCKINGBIRD_DEPLOY_TOKEN=<redacted>/')" ;;
  esac

  log "running the printed command: $(printf '%s' "$command" | tr -d '\\' | tr -s ' \n' ' ' | sed 's/MOCKINGBIRD_DEPLOY_TOKEN=[^ ]*/MOCKINGBIRD_DEPLOY_TOKEN=<redacted>/')"
  eval "$command" >/dev/null || die "the printed docker run command failed to start the canary"
}

# wait_for_enrolment blocks until the session reaches "provisioned" --
# the canary has spent its enrolment secret and holds a bearer token and
# a client certificate. Journeys assert the consequences of that; the
# harness only has to make sure it happened before it hands over.
wait_for_enrolment() {
  local attempt status
  for attempt in $(seq 1 60); do
    status="$(docker exec "$BIRDCAGE" /birdcage canary enrol --status 2>/dev/null || true)"
    case "$status" in
      *state=provisioned*)
        log "the canary enrolled on attempt $attempt"
        CANARY_ID="$(printf '%s\n' "$status" | sed -n 's/.*[[:space:]]canary=\([^[:space:]]*\).*/\1/p' | tail -1)"
        [ -n "$CANARY_ID" ] || die "the session is provisioned but --status printed no canary id"
        return 0
        ;;
    esac
    sleep 1
  done
  log "the canary never contacted birdcage; its log follows"
  docker logs "$CANARY" >&2 || true
  log "birdcage log follows"
  docker logs "$BIRDCAGE" >&2 || true
  die "enrolment never completed"
}

up() {
  command -v docker >/dev/null 2>&1 || die "docker is not on PATH"
  down >/dev/null 2>&1 || true

  build_image "$BIRDCAGE_IMAGE" build/birdcage/Dockerfile
  build_image "$MOCKINGBIRD_IMAGE" build/mockingbird/Dockerfile
  build_helper_image

  docker network create "$NET" >/dev/null || die "creating network $NET failed"
  local vol
  for vol in "$DATA_VOL" "$TLS_VOL" "$WORK_VOL" "$STATE_VOL" "$LOG_VOL"; do
    docker volume create "$vol" >/dev/null || die "creating volume $vol failed"
  done

  generate_tls
  if [ "$E2E_BACKEND" = postgres ] && [ -z "${E2E_DATABASE_URL:-}" ]; then
    start_postgres
    E2E_DATABASE_URL="postgres://postgres:e2e@$PG:5432/birdcage?sslmode=disable"
  fi
  start_birdcage
  copy_birdcage_ca
  enrol_canary
  run_printed_command
  wait_for_enrolment

  # The environment every journey consumes. Nothing secret is printed:
  # the deploy token and the canary's bearer token stay in volumes, and
  # a journey that needs one asks for it (`stack.sh deploy-token`, or
  # reads /state inside `stack.sh helper`).
  cat <<EOF
export E2E_PREFIX=$E2E_PREFIX
export E2E_STACK=$REPO_ROOT/scripts/e2e/stack.sh
export E2E_NET=$NET
export E2E_BIRDCAGE=$BIRDCAGE
export E2E_CANARY=$CANARY
export E2E_BACKEND=$E2E_BACKEND
export E2E_CANARY_ID=$CANARY_ID
export E2E_CANARY_NAME=$CANARY_NAME
export E2E_CANARY_LANE=$CANARY_LANE
export BIRDCAGE_URL=https://$BIRDCAGE:8080
export BIRDCAGE_INGEST_URL=https://$BIRDCAGE:8443
export BIRDCAGE_ENROL_URL=https://$BIRDCAGE:8444
EOF
}

down() {
  docker rm --force "$CANARY" >/dev/null 2>&1 || true
  docker rm --force "$BIRDCAGE" >/dev/null 2>&1 || true
  docker rm --force "$PG" >/dev/null 2>&1 || true
  local vol
  for vol in "$DATA_VOL" "$TLS_VOL" "$WORK_VOL" "$STATE_VOL" "$LOG_VOL"; do
    docker volume rm --force "$vol" >/dev/null 2>&1 || true
  done
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker image rm --force "$HELPER_IMAGE" >/dev/null 2>&1 || true
  # Only ever an image tag this harness named itself -- see
  # BIRDCAGE_IMAGE's comment above.
  local image
  for image in "$BIRDCAGE_IMAGE" "$MOCKINGBIRD_IMAGE"; do
    case "$image" in
      "$E2E_PREFIX"*) docker image rm --force "$image" >/dev/null 2>&1 || true ;;
    esac
  done
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  logs) shift; docker logs "${1:-$BIRDCAGE}" 2>&1 ;;
  helper) shift; helper "$@" ;;
  birdcage) shift; docker exec "$BIRDCAGE" /birdcage "$@" ;;
  # query runs one read-only SQL statement against whichever engine is
  # underneath and prints the rows, so a journey asserting on something
  # with no API -- the audit log, today -- reads the same on both.
  # Without this a journey silently only ever proves itself on SQLite,
  # which is how "we support Postgres" turns out to mean "we compile
  # against it".
  query)
    shift
    [ $# -eq 1 ] || die "usage: $0 query <sql>"
    if [ "$E2E_BACKEND" = postgres ] || [ -n "${E2E_DATABASE_URL:-}" ]; then
      docker exec "$PG" psql -U postgres -d birdcage -At -c "$1" \
        || die "the query failed against postgres"
    else
      # Copied first: the database is open in the birdcage container
      # and sqlite3 would otherwise take a lock on a live file.
      helper "set -eu; cp /data/birdcage.db /tmp/db; sqlite3 /tmp/db \"$1\"" \
        || die "the query failed against sqlite"
    fi ;;
  # write-work reads stdin into the work volume, so a journey can park
  # something a container needs to read without it ever reaching the
  # host filesystem (under a remote docker socket there is no shared
  # one) or a CI log. A second enrolment's printed output -- which
  # carries a live deploy token -- is why this exists.
  write-work)
    shift
    [ $# -eq 1 ] || die "usage: $0 write-work <name>"
    case "$1" in */*|"") die "write-work takes a bare file name, not a path" ;; esac
    helper_in "cat > /work/$1; chmod 600 /work/$1" ;;
  *)
    echo "usage: $0 {up|down|logs [container]|helper <sh command>|birdcage <args>|query <sql>|write-work <name>}" >&2
    exit 2 ;;
esac
