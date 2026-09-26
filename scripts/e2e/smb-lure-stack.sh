#!/usr/bin/env bash
# smb-lure-stack.sh -- the infrastructure scripts/e2e/smb-lure.sh needs:
# the SHIPPED SMB lure image (build/smb-lure), the SHIPPED address holder
# image (build/holder, issue #126), a canary enrolled with the audit
# mount and the holder join `birdcage canary enrol` itself prints, and an
# smbclient to drive them with.
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

# The address holder image under test (issue #126), the same story as
# LURE_IMAGE above: E2E_HOLDER_IMAGE is build:images' own tag in CI, and a
# local run with nothing set builds it here.
HOLDER_IMAGE="${E2E_HOLDER_IMAGE:-${E2E_PREFIX}-holder-image}"
HOLDER_IMAGE_BUILT=0

CLIENT_IMAGE="${E2E_PREFIX}-smbclient-image"
LURE="${E2E_PREFIX}-lure"
HOLDER="${E2E_PREFIX}-holder"
AUDIT_VOL="${E2E_PREFIX}-lure-audit"

LURE_CANARY="${E2E_PREFIX}-lure-canary"
LURE_CANARY_STATE_VOL="${E2E_PREFIX}-lure-canary-state"
LURE_CANARY_LOG_VOL="${E2E_PREFIX}-lure-canary-log"
LURE_CANARY_NAME="${E2E_SMB_LURE_CANARY_NAME:-e2e-lure-canary}"
LURE_CANARY_LANE="${E2E_SMB_LURE_CANARY_LANE:-e2e-lure}"

# OpenCanary's own container for this second canary (issue #132): since
# #132 every honeypot canary, including this one, has OpenCanary as a
# separate container joining the same holder -- reusing the base stack's
# own opencanary image (E2E_OPENCANARY_IMAGE_REF, from
# scripts/e2e/stack.sh's own `up`) rather than building a second copy.
LURE_OPENCANARY="${E2E_PREFIX}-lure-opencanary"

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

# build_holder_image mirrors build_lure_image exactly, for the address
# holder image (#126).
build_holder_image() {
  if docker image inspect "$HOLDER_IMAGE" >/dev/null 2>&1; then
    log "using existing image $HOLDER_IMAGE"
    return 0
  fi
  [ -z "${E2E_HOLDER_IMAGE:-}" ] || die "E2E_HOLDER_IMAGE=$HOLDER_IMAGE is not present; ci-ensure-image.sh should have recovered it"
  log "building $HOLDER_IMAGE from build/holder/Dockerfile"
  docker build --file "$REPO_ROOT/build/holder/Dockerfile" --tag "$HOLDER_IMAGE" "$REPO_ROOT" >/dev/null \
    || die "building $HOLDER_IMAGE failed"
  HOLDER_IMAGE_BUILT=1
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

# start_holder runs the address holder (issue #126) with the hardening
# flags docs/enrolment.md prints, attached to the harness's own test
# network -- the one thing that differs from the printed command, which
# has no --network at all because an operator's holder sits on whatever
# network they choose. The canary and the lure both join this container's
# namespace below, so it has to exist, and be attached to $E2E_NET, before
# either of them starts.
start_holder() {
  docker run --detach --name "$HOLDER" \
    --network "$E2E_NET" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 16 \
    --memory 32m \
    --volume "$AUDIT_VOL:/audit:ro" \
    "$HOLDER_IMAGE" >/dev/null || die "starting $HOLDER failed"
}

# enrol_lure_canary mints an enrolment session the way smb-stack.sh's own
# enrol_smb_canary does. No extra flags: the SMB lure is on by default, so
# the printed command already carries the read-only audit mount, the
# holder join and MOCKINGBIRD_SMB_AUDIT_PATH, and this journey exercises
# exactly what an operator would paste.
enrol_lure_canary() {
  local image output
  image="$(docker inspect --format '{{.Config.Image}}' "$E2E_CANARY")" \
    || die "could not read the image $E2E_CANARY is running"

  output="$(docker exec --env "MOCKINGBIRD_IMAGE=$image" --env "OPENCANARY_IMAGE=$E2E_OPENCANARY_IMAGE_REF" "$E2E_BIRDCAGE" \
    /birdcage canary enrol --name "$LURE_CANARY_NAME" --lane "$LURE_CANARY_LANE")" \
    || die "birdcage canary enrol (lure canary) failed"

  printf '%s\n' "$output" | "$E2E_STACK" write-work lure-enrol-output.txt \
    || die "could not store the lure canary's enrolment output"
}

# run_lure_canary takes the printed `docker run` command and applies
# three of stack.sh's own substitutions (name, both volumes) plus one of
# its own: the audit volume's name, and joining THIS harness's holder
# rather than the literal name `holder` the printed command carries. The
# `:ro` mount, the `--network container:holder` line and the
# MOCKINGBIRD_SMB_AUDIT_PATH line are NOT added or removed here -- the
# enrol command prints them itself, and this journey is worth much less if
# the harness supplies them. The checks below are what notices if either
# ever stops.
#
# The extraction below matches the canary's own line (`--name mockingbird`)
# rather than any `docker run`, because since #126 the printed output
# carries three blocks -- the holder's, then the canary's, then the
# lure's -- and matching the first `docker run` line unconditionally would
# capture the holder's block instead (see stack.sh's own
# run_printed_command for the same fix, made first).
run_lure_canary() {
  local command
  command="$("$E2E_STACK" helper "sed -n '/^docker run -d --name mockingbird /,/[^\\\\]\$/{p;/[^\\\\]\$/q;}' /work/lure-enrol-output.txt")" \
    || die "could not read the lure canary's printed docker run command"

  case "$command" in
    *"-v smb-audit:/audit:ro"*) ;;
    *) die "the enrolment command printed no read-only audit mount -- did --lure default to off, or did the flag change?" ;;
  esac
  case "$command" in
    *"MOCKINGBIRD_SMB_AUDIT_PATH=/audit/smb.log"*) ;;
    *) die "the enrolment command printed no MOCKINGBIRD_SMB_AUDIT_PATH -- the agent's smb road would not run" ;;
  esac
  case "$command" in
    *"--network container:holder"*) ;;
    *) die "the enrolment command printed no holder join (issue #126) -- did the design change back to joining the canary directly?" ;;
  esac

  command="$(printf '%s\n' "$command" | sed \
    -e "s|--name mockingbird |--name $LURE_CANARY |" \
    -e "s|-v mockingbird-state:|-v $LURE_CANARY_STATE_VOL:|" \
    -e "s|-v mockingbird-log:|-v $LURE_CANARY_LOG_VOL:|" \
    -e "s|-v smb-audit:/audit:ro|-v $AUDIT_VOL:/audit:ro|" \
    -e "s|--network container:holder|--network container:$HOLDER|")"

  # Three independent substring checks, not one glob requiring an order:
  # --network comes before the audit mount in the printed command, and a
  # glob assuming the opposite order would refuse a perfectly good command.
  local looks_right=1
  case "$command" in docker\ run\ *"$LURE_CANARY"*) ;; *) looks_right=0 ;; esac
  case "$command" in *"$AUDIT_VOL"*) ;; *) looks_right=0 ;; esac
  case "$command" in *"container:$HOLDER"*) ;; *) looks_right=0 ;; esac
  [ "$looks_right" = 1 ] \
    || die "the lure canary's printed docker run command did not look the way this harness expects; got: $(printf '%s' "$command" | sed 's/MOCKINGBIRD_DEPLOY_TOKEN=[^ ]*/MOCKINGBIRD_DEPLOY_TOKEN=<redacted>/')"

  # Second use of the mockingbird build tag in this job -- stack.sh's own
  # enrol_canary already used it once, earlier, to start the base canary
  # this lure canary is modelled on. A concurrent pipeline's prune (#112)
  # can delete the local tag between the two uses even though the job's
  # own before-script recovery already ran once; re-check immediately
  # before this second `docker run`, same as the job's first call. A
  # no-op outside CI, where these variables are unset.
  if [ -n "${MOCKINGBIRD_BUILD_IMAGE:-}" ] && [ -n "${MOCKINGBIRD_BUILD_DIGEST:-}" ]; then
    "$REPO_ROOT/scripts/ci-ensure-image.sh" "$MOCKINGBIRD_BUILD_IMAGE" "$MOCKINGBIRD_BUILD_DIGEST" >&2 \
      || die "could not ensure $MOCKINGBIRD_BUILD_IMAGE is present before starting the lure canary"
  fi

  log "running: $(printf '%s' "$command" | tr -d '\\' | tr -s ' \n' ' ' | sed 's/MOCKINGBIRD_DEPLOY_TOKEN=[^ ]*/MOCKINGBIRD_DEPLOY_TOKEN=<redacted>/')"
  eval "$command" >/dev/null || die "the lure canary's docker run command failed to start"
}

# run_lure_opencanary is run_lure_canary's own twin for OpenCanary's
# printed block (issue #132): this second canary gets its own OpenCanary
# container too, joining this journey's own holder rather than the
# literal name `holder`, and sharing this canary's own log volume
# read-write (the agent mounts the same volume read-only on its side,
# already substituted above).
run_lure_opencanary() {
  local command
  command="$("$E2E_STACK" helper "sed -n '/^docker run -d --name opencanary /,/[^\\\\]\$/{p;/[^\\\\]\$/q;}' /work/lure-enrol-output.txt")" \
    || die "could not read the lure canary's printed OpenCanary command"

  command="$(printf '%s\n' "$command" | sed \
    -e "s|--name opencanary |--name $LURE_OPENCANARY |" \
    -e "s|-v mockingbird-log:|-v $LURE_CANARY_LOG_VOL:|" \
    -e "s|--network container:holder|--network container:$HOLDER|")"

  case "$command" in
    docker\ run\ *"$LURE_OPENCANARY"*"$E2E_OPENCANARY_IMAGE_REF"*) ;;
    *) die "the lure canary's printed OpenCanary command did not look the way this harness expects; got: $command" ;;
  esac

  log "running: $(printf '%s' "$command" | tr -d '\\' | tr -s ' \n' ' ')"
  eval "$command" >/dev/null || die "the lure canary's OpenCanary command failed to start"
}

# start_lure runs the lure in the holder's network namespace (issue #126,
# amending #87 decision 3's wording -- the lure joins the holder, not the
# canary), with the hardening flags docs/enrolment.md prints. This is the
# one thing that differs from the printed command, and only in naming
# this harness's holder instead of the literal name `holder`.
start_lure() {
  docker run --detach --name "$LURE" \
    --network "container:$HOLDER" \
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
# socket check. It asks over the HOLDER's Docker name, not the canary's
# own: since #126 the canary and the lure both join the holder's network
# namespace via `--network container:$HOLDER` rather than owning one, and
# a container joined this way gets no network endpoint -- and so no
# Docker embedded-DNS entry -- of its own (verified directly against this
# Docker version: `getent hosts` on a joiner's own name fails, while the
# owner's name resolves). The holder's address IS the canary's address
# (decision 3, amended by #126) -- they are, literally, the same
# interface -- so asking for the holder by name is asking for the
# canary's address by the one name this harness can actually resolve it
# under.
wait_for_lure() {
  local attempt
  for attempt in $(seq 1 30); do
    if smbclient -L "//$HOLDER" -N 2>/dev/null | grep -q "$LURE_SHARE"; then
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

# restart_canary restarts the canary ALONE -- issue #126's whole point.
# Before the address holder, this had to restart the lure too, because the
# lure joined the canary's own network namespace directly and a canary
# restart destroyed it. Now both the canary and the lure join the
# holder's namespace instead, so restarting the canary leaves that
# namespace, and the lure's listening smbd, completely alone. This
# function fails (wait_for_lure times out) if that stops being true.
restart_canary() {
  docker restart --time 10 "$LURE_CANARY" >/dev/null || die "restarting $LURE_CANARY failed"
  wait_for_lure
  wait_for_smb_road
}

# restart_lure restarts the lure ALONE and proves the canary's own
# reporting pipeline never noticed: the lure is, and always was, a joiner
# of a namespace it does not own, so restarting it must not touch the
# canary's agent, its heartbeat, or anything already in flight. Unlike
# restart_canary, this direction was never broken by the bug #126 fixes --
# it is here so a future change that makes the lure the namespace owner
# again would be caught the same way.
restart_lure() {
  docker restart --time 10 "$LURE" >/dev/null || die "restarting $LURE failed"
  wait_for_lure
  wait_for_smb_road
}

# restart_opencanary restarts this journey's own OpenCanary container
# ALONE (issue #132), the same "does not regress" shape restart_lure's
# own comment gives: OpenCanary was always a joiner of the holder's
# namespace, never its owner, so restarting it must not touch the
# canary's own network namespace, the lure's listening socket, or the
# agent's own reporting. wait_for_lure and wait_for_smb_road prove the
# lure and the agent's smb road are both still there; the caller (the
# journey script) is what counts alerts before and after to prove the
# canary's own reporting pipeline kept working throughout.
restart_opencanary() {
  docker restart --time 10 "$LURE_OPENCANARY" >/dev/null || die "restarting $LURE_OPENCANARY failed"
  wait_for_lure
  wait_for_smb_road
}

# audit_survives_extended_outage stops BOTH the canary and the lure --
# the exact scenario issue #126 names: "the smb-audit tmpfs volume is
# also wiped when no container holds it." Before the holder, nothing else
# ever mounted that volume, so a moment with both containers down freed
# its backing memory and lost whatever had not been read yet. The holder
# keeps it mounted throughout, so this reads the file through a
# throwaway container (never through the canary or the lure, which are
# down for the whole of this check) and expects the first bait file's
# line to still be there after well over a minute -- comfortably past
# both the log's own tmpfs GC and any read-off-by-a-few-seconds race.
audit_survives_extended_outage() {
  local outage_seconds="${1:-65}"
  docker stop --time 5 "$LURE" >/dev/null || die "stopping $LURE failed"
  docker stop --time 5 "$LURE_CANARY" >/dev/null || die "stopping $LURE_CANARY failed"
  log "both the canary and the lure are stopped; waiting ${outage_seconds}s"
  sleep "$outage_seconds"
  local content
  content="$(docker run --rm --volume "$AUDIT_VOL:/audit:ro" "${ALPINE_IMAGE:-alpine:3.24}" cat /audit/smb.log 2>/dev/null)" \
    || die "could not read the audit file while both containers were down"
  case "$content" in
    *"$LURE_BAIT_ONE"*) log "the audit file still names $LURE_BAIT_ONE after a ${outage_seconds}s outage" ;;
    *) die "the audit file lost its earlier line naming $LURE_BAIT_ONE during a ${outage_seconds}s outage -- the holder did not keep the volume mounted" ;;
  esac
  docker start "$LURE_CANARY" >/dev/null || die "starting $LURE_CANARY failed"
  docker start "$LURE" >/dev/null || die "starting $LURE failed"
  wait_for_lure
  wait_for_smb_road
}

up() {
  command -v docker >/dev/null 2>&1 || die "docker is not on PATH"
  [ -n "${E2E_STACK:-}" ] && [ -n "${E2E_NET:-}" ] && [ -n "${E2E_BIRDCAGE:-}" ] && [ -n "${E2E_CANARY:-}" ] && [ -n "${E2E_OPENCANARY_IMAGE_REF:-}" ] \
    || die "E2E_STACK/E2E_NET/E2E_BIRDCAGE/E2E_CANARY/E2E_OPENCANARY_IMAGE_REF unset -- run: eval \"\$(scripts/e2e/stack.sh up)\" first"
  down >/dev/null 2>&1 || true

  build_lure_image
  build_holder_image
  build_client_image
  create_audit_volume
  start_holder
  enrol_lure_canary
  run_lure_canary
  run_lure_opencanary
  wait_for_lure_canary
  start_lure
  wait_for_lure
  wait_for_smb_road

  cat <<EOF
export SMB_LURE=$LURE
export SMB_LURE_IMAGE_REF=$LURE_IMAGE
export SMB_LURE_HOLDER=$HOLDER
export SMB_LURE_HOLDER_IMAGE_REF=$HOLDER_IMAGE
export SMB_LURE_CLIENT_IMAGE=$CLIENT_IMAGE
export SMB_LURE_CANARY=$LURE_CANARY
export SMB_LURE_CANARY_ID=$LURE_CANARY_ID
export SMB_LURE_CANARY_NAME=$LURE_CANARY_NAME
export SMB_LURE_OPENCANARY=$LURE_OPENCANARY
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
  docker rm --force "$LURE_OPENCANARY" >/dev/null 2>&1 || true
  docker rm --force "$HOLDER" >/dev/null 2>&1 || true
  local vol
  for vol in "$AUDIT_VOL" "$LURE_CANARY_STATE_VOL" "$LURE_CANARY_LOG_VOL"; do
    docker volume rm --force "$vol" >/dev/null 2>&1 || true
  done
  # Only images this file built, and only ones carrying the prefix: never
  # the shipped tag CI passed in, which the pipeline's other jobs need.
  local image
  for image in "$LURE_IMAGE" "$HOLDER_IMAGE" "$CLIENT_IMAGE"; do
    case "$image" in
      "$E2E_PREFIX"*) docker image rm --force "$image" >/dev/null 2>&1 || true ;;
    esac
  done
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  restart-canary) restart_canary ;;
  restart-lure) restart_lure ;;
  restart-opencanary) restart_opencanary ;;
  audit-survives-outage) shift; audit_survives_extended_outage "$@" ;;
  audit-log) audit_log ;;
  *)
    echo "usage: $0 {up|down|restart-canary|restart-lure|restart-opencanary|audit-survives-outage [seconds]|audit-log}" >&2
    exit 2 ;;
esac
