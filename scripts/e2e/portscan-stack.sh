#!/usr/bin/env bash
# portscan-stack.sh -- the extra infrastructure scripts/e2e/portscan.sh
# (issue #79) needs and no other journey does: two more Mockingbird
# canaries, carrying the two capability shapes issue #65's detector
# cares about, plus a container to sweep them from.
#
# Why two canaries rather than one: the existing base canary from
# `stack.sh up` runs the operator's own printed `docker run` command,
# which is the right thing for journey 1 but does not carry
# `--cap-drop ALL` -- docker's own default capability set already
# includes NET_RAW, so that container is not a clean negative case. This
# file starts two canaries built for the purpose:
#
#   - POS_CANARY: --cap-drop ALL --cap-add NET_RAW, no
#     no-new-privileges -- issue #65's own capability, and nothing else.
#   - NEG_CANARY: the same flags plus --security-opt no-new-privileges
#     AND --init -- see below for why this file adds --init itself now.
#
# A third combination was tried and rejected while building this
# journey, worth recording here so nobody re-discovers it the hard way:
# `--cap-drop ALL` with no `--cap-add NET_RAW` and no
# `no-new-privileges` does not give a graceful "detection off" at all --
# the binary carries `cap_net_raw+ep` as a *file* capability, and
# execve() refuses to run a binary whose file capability is not even in
# the container's capability bounding set. The container exits
# immediately ("exec /mockingbird failed: Operation not permitted"),
# proving nothing about detection. NET_RAW has to stay in the bounding
# set (`--cap-add NET_RAW`) for the binary to start at all.
#
# Why NEG_CANARY needs --init added by hand, since issue #132: turning
# detection off with no-new-privileges needs an init process ahead of
# the agent, not just the flag on its own (docs/enrolment.md's own "If
# you also use --security-opt no-new-privileges" section has the detail).
# The agent binary carries NET_RAW as a *file* capability, kept across
# execve() only if the process's own parent already held it. When the
# agent is the container's first process, that parent is Docker's own
# runtime, which already holds NET_RAW because of --cap-add, so
# no-new-privileges changes nothing. When an init process sits in front
# of it instead, that init runs as uid 65532 with no capabilities of its
# own, and no-new-privileges then stops the agent picking NET_RAW back
# up -- detection goes off. Before #132 the printed agent command always
# carried --init (to reap OpenCanary, its child process then), so this
# combination fell out for free; since #132 OpenCanary is its own
# container and the agent's own line carries neither --sysctl nor --init
# any more (cmd/birdcage/canary.go), so this harness adds --init itself
# to keep exercising the documented "detection off" case. Verified
# locally against the built image, on rootless docker (the same engine
# the runner uses): a capsh probe carrying cap_net_raw+ep keeps
# `cap_net_raw=ep` under `--cap-drop ALL --cap-add NET_RAW
# --security-opt no-new-privileges` alone, and loses it (`=`) once
# `--init` is added.
#
# Since #132 every honeypot canary also gets its own OpenCanary
# container, joining its own address holder exactly as the product ships
# it (cmd/birdcage/canary_lure.go; stack.sh's own start_holder and
# run_opencanary_command are the model) -- so this file starts one
# prefixed holder and one OpenCanary container per canary, POS and NEG
# alike, even though neither journey asserts anything about OpenCanary
# directly.
#
#   eval "$(scripts/e2e/stack.sh up)"
#   eval "$(scripts/e2e/portscan-stack.sh up)"
#   scripts/e2e/portscan.sh
#   scripts/e2e/portscan-stack.sh down
#   scripts/e2e/stack.sh down
#
# Everything here is named from stack.sh's own E2E_PREFIX (required in
# the environment already, see the check below), so `down` only ever
# touches what this file created and two parallel pipelines never
# collide -- the same discipline stack.sh and smb-stack.sh use.
set -eu

[ -n "${E2E_PREFIX:-}" ] || {
  echo "portscan-stack: E2E_PREFIX unset -- run: eval \"\$(scripts/e2e/stack.sh up)\" first" >&2
  exit 2
}

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

POS_CANARY="${E2E_PREFIX}-portscan-pos"
POS_STATE_VOL="${E2E_PREFIX}-portscan-pos-state"
POS_LOG_VOL="${E2E_PREFIX}-portscan-pos-log"
POS_NAME="${E2E_PORTSCAN_POS_NAME:-e2e-portscan-pos}"
POS_LANE="${E2E_PORTSCAN_POS_LANE:-e2e-portscan-pos}"
# The address holder and OpenCanary's own container (#132) this canary
# joins, same shape as stack.sh's own HOLDER/OPENCANARY.
POS_HOLDER="${E2E_PREFIX}-portscan-pos-holder"
POS_OPENCANARY="${E2E_PREFIX}-portscan-pos-opencanary"

NEG_CANARY="${E2E_PREFIX}-portscan-neg"
NEG_STATE_VOL="${E2E_PREFIX}-portscan-neg-state"
NEG_LOG_VOL="${E2E_PREFIX}-portscan-neg-log"
NEG_NAME="${E2E_PORTSCAN_NEG_NAME:-e2e-portscan-neg}"
NEG_LANE="${E2E_PORTSCAN_NEG_LANE:-e2e-portscan-neg}"
NEG_HOLDER="${E2E_PREFIX}-portscan-neg-holder"
NEG_OPENCANARY="${E2E_PREFIX}-portscan-neg-opencanary"

# HOLDER_IMAGE is filled in by `up`, read off the already-running base
# holder (E2E_HOLDER) the same way MOCKINGBIRD_IMAGE below is read off
# the base canary -- whatever tag or override stack.sh's own `up` gave
# it, this reuses those exact bytes rather than guessing a name.
HOLDER_IMAGE=""

# The second container the journey sweeps from -- alpine's own busybox
# nc is enough to open and close a TCP connection per port (a real SYN
# on the wire either way), the same tool enrol-and-hit.sh already uses
# against the base canary's FTP port. Kept running for the length of
# the journey, unlike every other journey's throwaway `docker run --rm`
# calls, because the tracker in internal/agent/portscan keys a scan by
# source address: two sweeps from two different containers would be two
# different sources, not one continuing scan.
SWEEPER="${E2E_PREFIX}-portscan-sweep"

log() { echo "portscan-stack: $*" >&2; }
die() { echo "portscan-stack: $*" >&2; exit 1; }

helper() { "$E2E_STACK" helper "$@"; }

# enrol mints a session and stores its printed `docker run` command in
# the work volume -- MOCKINGBIRD_IMAGE is read off the already-running
# base canary, the same way smb-stack.sh's enrol_smb_canary does, so
# this always starts the same image stack.sh built, whatever tag or
# override name it was given. OPENCANARY_IMAGE is E2E_OPENCANARY_IMAGE_REF,
# stack.sh's own `up` export of the exact tag it built or was handed
# (#132) -- the same override convention, read directly rather than
# inspected off a container, because stack.sh already hands it over.
enrol() { # enrol <name> <lane> <work-file>
  local name="$1" lane="$2" work_file="$3" image output
  image="$(docker inspect --format '{{.Config.Image}}' "$E2E_CANARY")" \
    || die "could not read the image $E2E_CANARY is running"

  output="$(docker exec --env "MOCKINGBIRD_IMAGE=$image" --env "OPENCANARY_IMAGE=$E2E_OPENCANARY_IMAGE_REF" "$E2E_BIRDCAGE" \
    /birdcage canary enrol --name "$name" --lane "$lane")" \
    || die "birdcage canary enrol ($name) failed"

  printf '%s\n' "$output" | "$E2E_STACK" write-work "$work_file" \
    || die "could not store the enrolment output for $name"
}

# start_holder brings up this canary's own address holder (#126, #132),
# the same shape stack.sh's own start_holder uses: --network-alias names
# the canary that joins it, since a container that only joins another's
# namespace gets no Docker embedded-DNS entry of its own (stack.sh's own
# comment on this has the reproduction), and portscan.sh's own sweep()
# addresses both canaries by their bare container name.
start_holder() { # start_holder <holder-name> <network-alias>
  local holder="$1" alias="$2"
  docker run --detach --name "$holder" \
    --network "$E2E_NET" \
    --network-alias "$alias" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 16 \
    --memory 32m \
    "$HOLDER_IMAGE" >/dev/null || die "starting $holder failed"
}

# run takes the printed `docker run` command and edits it: stack.sh's
# own substitutions (name, both volumes, joining this canary's own
# holder rather than the literal name `holder`) plus the capability
# flags this canary needs, inserted where the printed command already
# carries `--cap-add NET_RAW \` so nothing about the rest of the command
# -- the two -e flags carrying the CA pin and deploy token, the image --
# is touched. No --sysctl or --init here any more (#132): the agent's
# own printed line carries neither; NEG_CANARY's cap_flags carries
# --init itself, for the reason this file's header comment gives.
run() { # run <work-file> <container> <holder> <state-vol> <log-vol> <cap-flags> <must-contain...>
  local work_file="$1" container="$2" holder="$3" state_vol="$4" log_vol="$5" cap_flags="$6"
  shift 6
  local command
  # The canary's own `docker run` block only, matched by its
  # `--name mockingbird` line rather than any `docker run`: the enrolment
  # output has carried three blocks since #126 (holder, canary, lure --
  # see stack.sh run_printed_command), and matching the first `docker run`
  # line unconditionally would capture the holder's block instead.
  command="$(helper "sed -n '/^docker run -d --name mockingbird /,/[^\\\\]\$/{p;/[^\\\\]\$/q;}' /work/$work_file")" \
    || die "could not read the printed docker run command for $container"

  command="$(printf '%s\n' "$command" | sed \
    -e "s|--name mockingbird |--name $container |" \
    -e "s|-v mockingbird-state:|-v $state_vol:|" \
    -e "s|-v mockingbird-log:|-v $log_vol:|" \
    -e "s|--network container:holder|--network container:$holder|" \
    -e "/-v smb-audit:/d" \
    -e "/MOCKINGBIRD_SMB_AUDIT_PATH/d" \
    -e "s|--cap-add NET_RAW \\\\|$cap_flags \\\\|")"

  case "$command" in
    docker\ run\ *"$container"*) ;;
    *) die "the printed docker run command for $container did not look the way this harness expects; got: $(printf '%s' "$command" | sed 's/MOCKINGBIRD_DEPLOY_TOKEN=[^ ]*/MOCKINGBIRD_DEPLOY_TOKEN=<redacted>/')" ;;
  esac
  local want
  for want in "$@"; do
    case "$command" in
      *"$want"*) ;;
      *) die "the docker run command for $container is missing $want after editing -- got: $(printf '%s' "$command" | sed 's/MOCKINGBIRD_DEPLOY_TOKEN=[^ ]*/MOCKINGBIRD_DEPLOY_TOKEN=<redacted>/')" ;;
    esac
  done

  # Second (and, for the NEG canary, third) use of the mockingbird build
  # tag in this job -- stack.sh's own enrol_canary already used it once,
  # earlier, to start the base canary both portscan canaries are modelled
  # on. A concurrent pipeline's prune (#112) can delete the local tag
  # between uses even though the job's own before-script recovery
  # already ran once; re-check immediately before each of these
  # `docker run`s, same as the job's first call. A no-op outside CI,
  # where these variables are unset.
  if [ -n "${MOCKINGBIRD_BUILD_IMAGE:-}" ] && [ -n "${MOCKINGBIRD_BUILD_DIGEST:-}" ]; then
    "$REPO_ROOT/scripts/ci-ensure-image.sh" "$MOCKINGBIRD_BUILD_IMAGE" "$MOCKINGBIRD_BUILD_DIGEST" >&2 \
      || die "could not ensure $MOCKINGBIRD_BUILD_IMAGE is present before starting $container"
  fi

  log "running ($container): $(printf '%s' "$command" | tr -d '\\' | tr -s ' \n' ' ' | sed 's/MOCKINGBIRD_DEPLOY_TOKEN=[^ ]*/MOCKINGBIRD_DEPLOY_TOKEN=<redacted>/')"
  eval "$command" >/dev/null || die "the docker run command for $container failed to start"
}

# run_opencanary is run's own twin for OpenCanary's printed block (#132):
# every canary this file starts gets its own OpenCanary container too,
# joining this canary's own holder rather than the literal name `holder`,
# and sharing this canary's own log volume read-write (the agent mounts
# the same volume read-only on its side, already substituted above by
# run). Run after run(), so the agent's webhook receiver is already
# listening before OpenCanary's first attempt to reach it (stack.sh's
# own run_opencanary_command has the reproduction of what happens the
# other way round).
run_opencanary() { # run_opencanary <work-file> <container> <holder> <log-vol>
  local work_file="$1" container="$2" holder="$3" log_vol="$4"
  local command
  command="$(helper "sed -n '/^docker run -d --name opencanary /,/[^\\\\]\$/{p;/[^\\\\]\$/q;}' /work/$work_file")" \
    || die "could not read OpenCanary's printed docker run command for $container"

  command="$(printf '%s\n' "$command" | sed \
    -e "s|--name opencanary |--name $container |" \
    -e "s|--network container:holder|--network container:$holder|" \
    -e "s|-v mockingbird-log:|-v $log_vol:|")"

  case "$command" in
    docker\ run\ *"$container"*"$E2E_OPENCANARY_IMAGE_REF"*) ;;
    *) die "OpenCanary's printed docker run command for $container did not look the way this harness expects; got: $command" ;;
  esac

  # Second (and third) use of the opencanary build tag in this job, the
  # same #112 concurrent-prune risk run()'s own comment names for
  # mockingbird -- stack.sh's own `up` already used this tag once, to
  # start the base stack's own OpenCanary container.
  if [ -n "${OPENCANARY_BUILD_IMAGE:-}" ] && [ -n "${OPENCANARY_BUILD_DIGEST:-}" ]; then
    "$REPO_ROOT/scripts/ci-ensure-image.sh" "$OPENCANARY_BUILD_IMAGE" "$OPENCANARY_BUILD_DIGEST" >&2 \
      || die "could not ensure $OPENCANARY_BUILD_IMAGE is present before starting $container"
  fi

  log "running opencanary ($container): $(printf '%s' "$command" | tr -d '\\' | tr -s ' \n' ' ')"
  eval "$command" >/dev/null || die "the OpenCanary docker run command for $container failed to start"
}

# wait_for_provision polls --status for one session by name, the same
# way stack.sh's own wait_for_enrolment and smb-stack.sh's
# wait_for_smb_canary do -- tail -1 rather than the first match, since a
# name can repeat across runs that never tore the birdcage database
# down (this script's own `down` does not touch it).
wait_for_provision() { # wait_for_provision <name> <container> -> prints canary id
  local name="$1" container="$2" attempt status line
  for attempt in $(seq 1 60); do
    status="$(docker exec "$E2E_BIRDCAGE" /birdcage canary enrol --status 2>/dev/null || true)"
    line="$(printf '%s\n' "$status" | grep "name=$name[[:space:]]" | tail -1 || true)"
    case "$line" in
      *state=provisioned*)
        log "$container enrolled on attempt $attempt"
        local id
        id="$(printf '%s\n' "$line" | sed -n 's/.*[[:space:]]canary=\([^[:space:]]*\).*/\1/p')"
        [ -n "$id" ] || die "$container's session is provisioned but --status printed no canary id"
        printf '%s' "$id"
        return 0
        ;;
    esac
    sleep 1
  done
  log "$container never contacted birdcage; its log follows"
  docker logs "$container" >&2 || true
  die "$container enrolment never completed"
}

# wait_for_line polls a container's own stdout for the startup line
# internal/agent/portscan's caller prints (cmd/mockingbird/portscan.go),
# so `up` only ever hands the journey a canary that has already reported
# what it thinks its own capability state is -- the same reason
# smb-stack.sh's wait_for_smb_module_ready waits for OpenCanary's own
# readiness line instead of assuming enrolment finishing was enough.
wait_for_line() { # wait_for_line <container> <substring>
  local container="$1" substring="$2" attempt
  for attempt in $(seq 1 30); do
    if docker logs "$container" 2>&1 | grep -qF "$substring"; then
      log "$container reported '$substring' on attempt $attempt"
      return 0
    fi
    sleep 1
  done
  log "$container never printed '$substring'; its log follows"
  docker logs "$container" >&2 || true
  die "$container never reported its port-scan startup state"
}

up() {
  command -v docker >/dev/null 2>&1 || die "docker is not on PATH"
  [ -n "${E2E_STACK:-}" ] && [ -n "${E2E_NET:-}" ] && [ -n "${E2E_BIRDCAGE:-}" ] && [ -n "${E2E_CANARY:-}" ] \
    && [ -n "${E2E_HOLDER:-}" ] && [ -n "${E2E_OPENCANARY_IMAGE_REF:-}" ] \
    || die "E2E_STACK/E2E_NET/E2E_BIRDCAGE/E2E_CANARY/E2E_HOLDER/E2E_OPENCANARY_IMAGE_REF unset -- run: eval \"\$(scripts/e2e/stack.sh up)\" first"
  down >/dev/null 2>&1 || true

  HOLDER_IMAGE="$(docker inspect --format '{{.Config.Image}}' "$E2E_HOLDER")" \
    || die "could not read the image $E2E_HOLDER is running"

  local vol
  for vol in "$POS_STATE_VOL" "$POS_LOG_VOL" "$NEG_STATE_VOL" "$NEG_LOG_VOL"; do
    docker volume create "$vol" >/dev/null || die "creating volume $vol failed"
  done

  start_holder "$POS_HOLDER" "$POS_CANARY"
  enrol "$POS_NAME" "$POS_LANE" portscan-pos-enrol-output.txt
  run portscan-pos-enrol-output.txt "$POS_CANARY" "$POS_HOLDER" "$POS_STATE_VOL" "$POS_LOG_VOL" \
    "--cap-drop ALL --cap-add NET_RAW" "--cap-drop ALL" "--cap-add NET_RAW"
  run_opencanary portscan-pos-enrol-output.txt "$POS_OPENCANARY" "$POS_HOLDER" "$POS_LOG_VOL"
  POS_CANARY_ID="$(wait_for_provision "$POS_NAME" "$POS_CANARY")"
  wait_for_line "$POS_CANARY" "port-scan detection active"

  start_holder "$NEG_HOLDER" "$NEG_CANARY"
  enrol "$NEG_NAME" "$NEG_LANE" portscan-neg-enrol-output.txt
  run portscan-neg-enrol-output.txt "$NEG_CANARY" "$NEG_HOLDER" "$NEG_STATE_VOL" "$NEG_LOG_VOL" \
    "--init --cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges" \
    "--init" "--cap-drop ALL" "--cap-add NET_RAW" "no-new-privileges"
  run_opencanary portscan-neg-enrol-output.txt "$NEG_OPENCANARY" "$NEG_HOLDER" "$NEG_LOG_VOL"
  NEG_CANARY_ID="$(wait_for_provision "$NEG_NAME" "$NEG_CANARY")"
  wait_for_line "$NEG_CANARY" "port-scan detection is OFF"

  # ${ALPINE_IMAGE:-alpine:3.24}: CI's dependency-proxy pin (refs #128,
  # .gitlab-ci.yml) when set, the plain Docker Hub tag on a workstation.
  docker run --detach --name "$SWEEPER" --network "$E2E_NET" --init \
    --pids-limit 32 --memory 64m --cpus 0.25 \
    "${ALPINE_IMAGE:-alpine:3.24}" sleep 3600 >/dev/null || die "starting $SWEEPER failed"

  cat <<EOF
export PORTSCAN_POS_CANARY=$POS_CANARY
export PORTSCAN_POS_CANARY_ID=$POS_CANARY_ID
export PORTSCAN_POS_HOLDER=$POS_HOLDER
export PORTSCAN_POS_OPENCANARY=$POS_OPENCANARY
export PORTSCAN_NEG_CANARY=$NEG_CANARY
export PORTSCAN_NEG_CANARY_ID=$NEG_CANARY_ID
export PORTSCAN_NEG_HOLDER=$NEG_HOLDER
export PORTSCAN_NEG_OPENCANARY=$NEG_OPENCANARY
export PORTSCAN_SWEEPER=$SWEEPER
EOF
}

down() {
  docker rm --force "$SWEEPER" >/dev/null 2>&1 || true
  docker rm --force "$POS_CANARY" >/dev/null 2>&1 || true
  docker rm --force "$POS_OPENCANARY" >/dev/null 2>&1 || true
  docker rm --force "$POS_HOLDER" >/dev/null 2>&1 || true
  docker rm --force "$NEG_CANARY" >/dev/null 2>&1 || true
  docker rm --force "$NEG_OPENCANARY" >/dev/null 2>&1 || true
  docker rm --force "$NEG_HOLDER" >/dev/null 2>&1 || true
  local vol
  for vol in "$POS_STATE_VOL" "$POS_LOG_VOL" "$NEG_STATE_VOL" "$NEG_LOG_VOL"; do
    docker volume rm --force "$vol" >/dev/null 2>&1 || true
  done
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *)
    echo "usage: $0 {up|down}" >&2
    exit 2 ;;
esac
