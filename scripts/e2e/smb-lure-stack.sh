#!/usr/bin/env bash
# smb-lure-stack.sh -- the infrastructure scripts/e2e/smb-lure.sh needs:
# the SHIPPED SMB lure image (build/smb-lure), a canary enrolled with the
# audit mount `birdcage canary enrol` itself prints, and an smbclient to
# drive them with.
#
# This is not scripts/e2e/smb-stack.sh. That one stands up
# build/e2e-samba -- a CI-only Debian Samba -- and a canary whose
# OpenCanary smb module reads the audit file, which is the arrangement
# #78 proved and #87 decision 40b replaced. This one runs the image that
# actually ships, and the canary reads the audit file with the agent's own
# tailer and parse (internal/agent/smbaudit). Both exist for now: the
# older journey still guards the OpenCanary path it was written for.
#
#   eval "$(scripts/e2e/stack.sh up)"
#   eval "$(scripts/e2e/smb-lure-stack.sh up)"
#   scripts/e2e/smb-lure.sh
#   scripts/e2e/smb-lure-stack.sh down
#   scripts/e2e/stack.sh down
#
# Everything is named from stack.sh's own E2E_PREFIX, so `down` only ever
# touches what this file created and two parallel pipelines never collide.
set -eu

[ -n "${E2E_PREFIX:-}" ] || {
  echo "smb-lure-stack: E2E_PREFIX unset -- run: eval \"\$(scripts/e2e/stack.sh up)\" first" >&2
  exit 2
}

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# The lure image under test. E2E_SMB_LURE_IMAGE is how CI points this at
# the tag build:images already built, so the journey exercises the bytes
# that would ship rather than a second build of the same source (#98). A
# local run with nothing set builds it here.
LURE_IMAGE="${E2E_SMB_LURE_IMAGE:-${E2E_PREFIX}-lure-image}"
LURE_IMAGE_BUILT=0

CLIENT_IMAGE="${E2E_PREFIX}-smbclient-image"
LURE="${E2E_PREFIX}-lure"
AUDIT_VOL="${E2E_PREFIX}-lure-audit"

LURE_CANARY="${E2E_PREFIX}-lure-canary"
LURE_CANARY_STATE_VOL="${E2E_PREFIX}-lure-canary-state"
LURE_CANARY_LOG_VOL="${E2E_PREFIX}-lure-canary-log"
LURE_CANARY_NAME="${E2E_SMB_LURE_CANARY_NAME:-e2e-lure-canary}"
LURE_CANARY_LANE="${E2E_SMB_LURE_CANARY_LANE:-e2e-lure}"

# The share and the bait files this journey uses, as the image lays them
# out (build/smb-lure/bait). Exported so the journey asserts on the same
# names the harness set up rather than a second copy of them.
LURE_SHARE=public
LURE_BAIT_ONE=IT/vpn-setup.pdf
LURE_BAIT_TWO=HR/salaries-2025.xlsx

log() { echo "smb-lure-stack: $*" >&2; }
die() { echo "smb-lure-stack: $*" >&2; exit 1; }

build_lure_image() {
  if docker image inspect "$LURE_IMAGE" >/dev/null 2>&1; then
    log "using existing image $LURE_IMAGE"
    return 0
  fi
  [ -z "${E2E_SMB_LURE_IMAGE:-}" ] || die "E2E_SMB_LURE_IMAGE=$LURE_IMAGE is not present; ci-ensure-image.sh should have recovered it"
  log "building $LURE_IMAGE from build/smb-lure/Dockerfile"
  docker build --file "$REPO_ROOT/build/smb-lure/Dockerfile" --tag "$LURE_IMAGE" "$REPO_ROOT" >/dev/null \
    || die "building $LURE_IMAGE failed"
  LURE_IMAGE_BUILT=1
}

build_client_image() {
  if docker image inspect "$CLIENT_IMAGE" >/dev/null 2>&1; then
    log "using existing image $CLIENT_IMAGE"
    return 0
  fi
  log "building $CLIENT_IMAGE from build/e2e-smbclient/Dockerfile"
  # --build-arg BASE_IMAGE: CI's dependency-proxy pin (refs #128,
  # .gitlab-ci.yml) when set, the Dockerfile's own default on a workstation.
  docker build --build-arg BASE_IMAGE="${ALPINE_IMAGE:-alpine:3.24}" \
    --file "$REPO_ROOT/build/e2e-smbclient/Dockerfile" --tag "$CLIENT_IMAGE" "$REPO_ROOT" >/dev/null \
    || die "building $CLIENT_IMAGE failed"
}

# create_audit_volume makes the size-capped tmpfs volume the run command
# in docs/enrolment.md tells an operator to make, with the same options.
# Created here rather than left to Docker's on-demand creation for the
# reason that command's own comment gives: a container reaching an
# uncreated named volume first gets a plain on-disk one, silently losing
# the size cap.
create_audit_volume() {
  docker volume create --driver local \
    --opt type=tmpfs --opt device=tmpfs --opt o=size=16m,mode=0755 \
    "$AUDIT_VOL" >/dev/null || die "creating volume $AUDIT_VOL failed"
}

# enrol_lure_canary mints an enrolment session the way smb-stack.sh's own
# enrol_smb_canary does. No extra flags: the SMB lure is on by default, so
# the printed command already carries the read-only audit mount and
# MOCKINGBIRD_SMB_AUDIT_PATH, and this journey exercises exactly what an
# operator would paste.
enrol_lure_canary() {
  local image output
  image="$(docker inspect --format '{{.Config.Image}}' "$E2E_CANARY")" \
    || die "could not read the image $E2E_CANARY is running"

  output="$(docker exec --env "MOCKINGBIRD_IMAGE=$image" "$E2E_BIRDCAGE" \
    /birdcage canary enrol --name "$LURE_CANARY_NAME" --lane "$LURE_CANARY_LANE")" \
    || die "birdcage canary enrol (lure canary) failed"

  printf '%s\n' "$output" | "$E2E_STACK" write-work lure-enrol-output.txt \
    || die "could not store the lure canary's enrolment output"
}

# run_lure_canary takes the printed `docker run` command and applies
# stack.sh's three substitutions (name, both volumes, network) plus one of
# its own: the audit volume's name. The `:ro` and the
# MOCKINGBIRD_SMB_AUDIT_PATH line are NOT added here -- the enrol command
# prints them itself, and this journey is worth much less if the harness
# supplies them. The check below is what notices if it ever stops.
run_lure_canary() {
  local command
  command="$("$E2E_STACK" helper "sed -n '/^docker run /,/[^\\\\]\$/{p;/[^\\\\]\$/q;}' /work/lure-enrol-output.txt")" \
    || die "could not read the lure canary's printed docker run command"

  case "$command" in
    *"-v smb-audit:/audit:ro"*) ;;
    *) die "the enrolment command printed no read-only audit mount -- did --lure default to off, or did the flag change?" ;;
  esac
  case "$command" in
    *"MOCKINGBIRD_SMB_AUDIT_PATH=/audit/smb.log"*) ;;
    *) die "the enrolment command printed no MOCKINGBIRD_SMB_AUDIT_PATH -- the agent's smb road would not run" ;;
  esac

  command="$(printf '%s\n' "$command" | sed \
    -e "s|^docker run -d |docker run -d --network $E2E_NET |" \
    -e "s|--name mockingbird |--name $LURE_CANARY |" \
    -e "s|-v mockingbird-state:|-v $LURE_CANARY_STATE_VOL:|" \
    -e "s|-v mockingbird-log:|-v $LURE_CANARY_LOG_VOL:|" \
    -e "s|-v smb-audit:/audit:ro|-v $AUDIT_VOL:/audit:ro|")"

  case "$command" in
    docker\ run\ *"$LURE_CANARY"*"$AUDIT_VOL"*) ;;
    *) die "the lure canary's printed docker run command did not look the way this harness expects; got: $(printf '%s' "$command" | sed 's/MOCKINGBIRD_DEPLOY_TOKEN=[^ ]*/MOCKINGBIRD_DEPLOY_TOKEN=<redacted>/')" ;;
  esac

  # Second use of the mockingbird build tag in this job -- stack.sh's own
  # enrol_canary already used it once, earlier, to start the base canary
  # this lure canary is modelled on. A concurrent pipeline's prune (#112)
  # can delete the local tag between the two uses even though the job's
  # own before-script recovery already ran once; re-check immediately
  # before this second `docker run`, same as the job's first call. A
  # no-op outside CI, where these variables are unset.
  if [ -n "${MOCKINGBIRD_BUILD_IMAGE:-}" ] && [ -n "${MOCKINGBIRD_BUILD_DIGEST:-}" ]; then
    "$REPO_ROOT/scripts/ci-ensure-image.sh" "$MOCKINGBIRD_BUILD_IMAGE" "$MOCKINGBIRD_BUILD_DIGEST" \
      || die "could not ensure $MOCKINGBIRD_BUILD_IMAGE is present before starting the lure canary"
  fi

  log "running: $(printf '%s' "$command" | tr -d '\\' | tr -s ' \n' ' ' | sed 's/MOCKINGBIRD_DEPLOY_TOKEN=[^ ]*/MOCKINGBIRD_DEPLOY_TOKEN=<redacted>/')"
  eval "$command" >/dev/null || die "the lure canary's docker run command failed to start"
}

# start_lure runs the lure in the canary container's network namespace,
# with the hardening flags docs/enrolment.md prints -- the same flags, so
# this journey also proves the documented command actually works, not just
# that some looser version of it does.
#
# --network container: is the one thing that differs from the printed
# command, and only in naming this harness's canary instead of
# `mockingbird`.
start_lure() {
  docker run --detach --name "$LURE" \
    --network "container:$LURE_CANARY" \
    --read-only \
    --cap-drop ALL \
    --cap-add SETUID --cap-add SETGID --cap-add NET_BIND_SERVICE \
    --security-opt no-new-privileges \
    --pids-limit 128 \
    --memory 192m \
    --ulimit core=0 \
    --tmpfs /run:size=8m \
    --tmpfs /var/lib/samba:size=8m \
    --tmpfs /var/cache/samba:size=8m \
    --tmpfs /var/log:size=8m \
    --volume "$AUDIT_VOL:/audit" \
    --env SMB_WORKGROUP=WORKGROUP \
    --env "SMB_SHARE_PUBLIC=$LURE_SHARE" \
    --env SMB_SHARE_BACKUP=backup \
    --env SMB_SHARE_SCANS=scans \
    "$LURE_IMAGE" >/dev/null || die "starting $LURE failed"
}

# wait_for_lure proves smbd is answering SMB, not merely that a port is
# open -- the same reason smb-stack.sh uses smbclient -L rather than a
# socket check. It asks over the canary's own name, because that is where
# the share has to appear: the whole point of decision 3 is that 445 is on
# the canary's address.
wait_for_lure() {
  local attempt
  for attempt in $(seq 1 30); do
    if smbclient -L "//$LURE_CANARY" -N 2>/dev/null | grep -q "$LURE_SHARE"; then
      log "the lure answered SMB on the canary's address on attempt $attempt"
      return 0
    fi
    sleep 1
  done
  log "the lure never answered; its audit log and the canary's log follow"
  audit_log >&2 || true
  docker logs "$LURE" >&2 || true
  die "the lure did not become ready"
}

# smbclient runs the real client against the stack's network. A function
# rather than a copy of the same docker invocation in four places; the
# journey sources this file's variables but calls docker itself, so this
# is exported through the `up` output as E2E_SMB_CLIENT_IMAGE instead.
smbclient() {
  docker run --rm --network "$E2E_NET" "$CLIENT_IMAGE" "$@"
}

# audit_log prints the lure's audit file, read through a read-only mount --
# the same view the canary agent has. Used only when something failed.
audit_log() {
  echo "--- $AUDIT_VOL /audit/smb.log ---"
  # ${ALPINE_IMAGE:-alpine:3.24}: CI's dependency-proxy pin (refs #128,
  # .gitlab-ci.yml) when set, the plain Docker Hub tag on a workstation.
  docker run --rm --volume "$AUDIT_VOL:/audit:ro" "${ALPINE_IMAGE:-alpine:3.24}" cat /audit/smb.log 2>/dev/null || true
}

wait_for_lure_canary() {
  local attempt status line
  for attempt in $(seq 1 60); do
    status="$(docker exec "$E2E_BIRDCAGE" /birdcage canary enrol --status 2>/dev/null || true)"
    line="$(printf '%s\n' "$status" | grep "name=$LURE_CANARY_NAME[[:space:]]" | tail -1 || true)"
    case "$line" in
      *state=provisioned*)
        log "the lure canary enrolled on attempt $attempt"
        LURE_CANARY_ID="$(printf '%s\n' "$line" | sed -n 's/.*[[:space:]]canary=\([^[:space:]]*\).*/\1/p')"
        [ -n "$LURE_CANARY_ID" ] || die "the lure canary session is provisioned but --status printed no canary id"
        return 0
        ;;
    esac
    sleep 1
  done
  log "the lure canary never contacted birdcage; its log follows"
  docker logs "$LURE_CANARY" >&2 || true
  die "lure canary enrolment never completed"
}

# wait_for_smb_road waits for the agent to say its smb road is running.
# There is no end-of-file race to lose here -- that is the whole point of
# reading the file with the agent's own tailer (#78's finding 3) -- so this
# only keeps the journey's own output honest about when the road came up.
wait_for_smb_road() {
  local attempt
  for attempt in $(seq 1 30); do
    if docker logs "$LURE_CANARY" 2>&1 | grep -q "smb audit road active"; then
      log "the agent's smb road is running (attempt $attempt)"
      return 0
    fi
    sleep 1
  done
  log "the agent never reported its smb road; the canary's log follows"
  docker logs "$LURE_CANARY" >&2 || true
  die "the agent's smb audit road never started in $LURE_CANARY"
}

# restart_canary restarts the canary and puts the lure back beside it.
#
# The lure has to be restarted too, and that is not this harness being
# careless: the lure lives in the canary container's network namespace
# (decision 3), so stopping the canary destroys the namespace the lure's
# smbd is listening in and the lure goes down with it. That is a real
# operational consequence of putting 445 on the canary's own address, and
# docs/enrolment.md says so. Restarting the lure first is impossible for
# the same reason -- there is no namespace to join until the canary is
# back.
restart_canary() {
  docker restart --time 10 "$LURE_CANARY" >/dev/null || die "restarting $LURE_CANARY failed"
  # And then the lure, which is not optional and is not this harness being
  # careless. Restarting the canary destroys the network namespace the
  # lure's smbd is listening in, and Docker does not re-attach a container
  # to a namespace that has been replaced: the lure stays `running` with
  # nothing answering on 445, which is the most misleading state it could
  # be in. `docker restart` on the lure re-resolves the namespace and the
  # share comes back -- verified by running it, after a first pass where
  # `docker start` on an already-running container returned 0 and changed
  # nothing.
  docker restart --time 10 "$LURE" >/dev/null || die "restarting $LURE failed"
  wait_for_lure
  wait_for_smb_road
}

up() {
  command -v docker >/dev/null 2>&1 || die "docker is not on PATH"
  [ -n "${E2E_STACK:-}" ] && [ -n "${E2E_NET:-}" ] && [ -n "${E2E_BIRDCAGE:-}" ] && [ -n "${E2E_CANARY:-}" ] \
    || die "E2E_STACK/E2E_NET/E2E_BIRDCAGE/E2E_CANARY unset -- run: eval \"\$(scripts/e2e/stack.sh up)\" first"
  down >/dev/null 2>&1 || true

  build_lure_image
  build_client_image
  create_audit_volume
  enrol_lure_canary
  run_lure_canary
  wait_for_lure_canary
  start_lure
  wait_for_lure
  wait_for_smb_road

  cat <<EOF
export SMB_LURE=$LURE
export SMB_LURE_IMAGE_REF=$LURE_IMAGE
export SMB_LURE_CLIENT_IMAGE=$CLIENT_IMAGE
export SMB_LURE_CANARY=$LURE_CANARY
export SMB_LURE_CANARY_ID=$LURE_CANARY_ID
export SMB_LURE_CANARY_NAME=$LURE_CANARY_NAME
export SMB_LURE_AUDIT_VOL=$AUDIT_VOL
export SMB_LURE_SHARE=$LURE_SHARE
export SMB_LURE_BAIT_ONE=$LURE_BAIT_ONE
export SMB_LURE_BAIT_TWO=$LURE_BAIT_TWO
export SMB_LURE_STACK=$(cd "$(dirname "$0")" && pwd)/smb-lure-stack.sh
EOF
}

down() {
  docker rm --force "$LURE" >/dev/null 2>&1 || true
  docker rm --force "$LURE_CANARY" >/dev/null 2>&1 || true
  local vol
  for vol in "$AUDIT_VOL" "$LURE_CANARY_STATE_VOL" "$LURE_CANARY_LOG_VOL"; do
    docker volume rm --force "$vol" >/dev/null 2>&1 || true
  done
  # Only images this file built, and only ones carrying the prefix: never
  # the shipped tag CI passed in, which the pipeline's other jobs need.
  local image
  for image in "$LURE_IMAGE" "$CLIENT_IMAGE"; do
    case "$image" in
      "$E2E_PREFIX"*) docker image rm --force "$image" >/dev/null 2>&1 || true ;;
    esac
  done
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  restart-canary) restart_canary ;;
  audit-log) audit_log ;;
  *)
    echo "usage: $0 {up|down|restart-canary|audit-log}" >&2
    exit 2 ;;
esac
