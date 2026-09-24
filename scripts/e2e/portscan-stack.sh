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
#   - NEG_CANARY: the same flags plus --security-opt no-new-privileges,
#     the exact hardening test:image:mockingbird already runs and
#     already proves (in that job's own comment) reports detection off.
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
# set (`--cap-add NET_RAW`) for the binary to start at all; the only
# clean way to turn the capability off without touching the binary is
# `no-new-privileges`, exactly as docs/enrolment.md's own "If you also
# use --security-opt no-new-privileges" section says. Verified locally
# against the built image, on rootless docker -- the same engine the
# runner uses.
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

POS_CANARY="${E2E_PREFIX}-portscan-pos"
POS_STATE_VOL="${E2E_PREFIX}-portscan-pos-state"
POS_LOG_VOL="${E2E_PREFIX}-portscan-pos-log"
POS_NAME="${E2E_PORTSCAN_POS_NAME:-e2e-portscan-pos}"
POS_LANE="${E2E_PORTSCAN_POS_LANE:-e2e-portscan-pos}"

NEG_CANARY="${E2E_PREFIX}-portscan-neg"
NEG_STATE_VOL="${E2E_PREFIX}-portscan-neg-state"
NEG_LOG_VOL="${E2E_PREFIX}-portscan-neg-log"
NEG_NAME="${E2E_PORTSCAN_NEG_NAME:-e2e-portscan-neg}"
NEG_LANE="${E2E_PORTSCAN_NEG_LANE:-e2e-portscan-neg}"

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
# override name it was given.
enrol() { # enrol <name> <lane> <work-file>
  local name="$1" lane="$2" work_file="$3" image output
  image="$(docker inspect --format '{{.Config.Image}}' "$E2E_CANARY")" \
    || die "could not read the image $E2E_CANARY is running"

  output="$(docker exec --env "MOCKINGBIRD_IMAGE=$image" "$E2E_BIRDCAGE" \
    /birdcage canary enrol --name "$name" --lane "$lane")" \
    || die "birdcage canary enrol ($name) failed"

  printf '%s\n' "$output" | "$E2E_STACK" write-work "$work_file" \
    || die "could not store the enrolment output for $name"
}

# run takes the printed `docker run` command and edits it: stack.sh's
# own three substitutions (name, both volumes, network) plus the
# capability flags this canary needs, inserted where the printed
# command already carries `--cap-add NET_RAW \` so nothing about the
# rest of the command -- the sysctl, the two -e flags carrying the CA
# pin and deploy token, the image -- is touched.
run() { # run <work-file> <container> <state-vol> <log-vol> <extra-cap-flags> <must-contain...>
  local work_file="$1" container="$2" state_vol="$3" log_vol="$4" cap_flags="$5"
  shift 5
  local command
  # First `docker run` block only, and quit: the enrolment output has
  # carried two since #87 (see stack.sh run_printed_command).
  command="$(helper "sed -n '/^docker run /,/[^\\\\]\$/{p;/[^\\\\]\$/q;}' /work/$work_file")" \
    || die "could not read the printed docker run command for $container"

  command="$(printf '%s\n' "$command" | sed \
    -e "s|^docker run -d |docker run -d --network $E2E_NET |" \
    -e "/-v smb-audit:/d" \
    -e "/MOCKINGBIRD_SMB_AUDIT_PATH/d" \
    -e "s|--name mockingbird |--name $container |" \
    -e "s|-v mockingbird-state:|-v $state_vol:|" \
    -e "s|-v mockingbird-log:|-v $log_vol:|" \
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

  log "running ($container): $(printf '%s' "$command" | tr -d '\\' | tr -s ' \n' ' ' | sed 's/MOCKINGBIRD_DEPLOY_TOKEN=[^ ]*/MOCKINGBIRD_DEPLOY_TOKEN=<redacted>/')"
  eval "$command" >/dev/null || die "the docker run command for $container failed to start"
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
    || die "E2E_STACK/E2E_NET/E2E_BIRDCAGE/E2E_CANARY unset -- run: eval \"\$(scripts/e2e/stack.sh up)\" first"
  down >/dev/null 2>&1 || true

  local vol
  for vol in "$POS_STATE_VOL" "$POS_LOG_VOL" "$NEG_STATE_VOL" "$NEG_LOG_VOL"; do
    docker volume create "$vol" >/dev/null || die "creating volume $vol failed"
  done

  enrol "$POS_NAME" "$POS_LANE" portscan-pos-enrol-output.txt
  run portscan-pos-enrol-output.txt "$POS_CANARY" "$POS_STATE_VOL" "$POS_LOG_VOL" \
    "--cap-drop ALL --cap-add NET_RAW" "--cap-drop ALL" "--cap-add NET_RAW"
  POS_CANARY_ID="$(wait_for_provision "$POS_NAME" "$POS_CANARY")"
  wait_for_line "$POS_CANARY" "port-scan detection active"

  enrol "$NEG_NAME" "$NEG_LANE" portscan-neg-enrol-output.txt
  run portscan-neg-enrol-output.txt "$NEG_CANARY" "$NEG_STATE_VOL" "$NEG_LOG_VOL" \
    "--cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges" \
    "--cap-drop ALL" "--cap-add NET_RAW" "no-new-privileges"
  NEG_CANARY_ID="$(wait_for_provision "$NEG_NAME" "$NEG_CANARY")"
  wait_for_line "$NEG_CANARY" "port-scan detection is OFF"

  docker run --detach --name "$SWEEPER" --network "$E2E_NET" --init \
    --pids-limit 32 --memory 64m --cpus 0.25 \
    alpine:3.24 sleep 3600 >/dev/null || die "starting $SWEEPER failed"

  cat <<EOF
export PORTSCAN_POS_CANARY=$POS_CANARY
export PORTSCAN_POS_CANARY_ID=$POS_CANARY_ID
export PORTSCAN_NEG_CANARY=$NEG_CANARY
export PORTSCAN_NEG_CANARY_ID=$NEG_CANARY_ID
export PORTSCAN_SWEEPER=$SWEEPER
EOF
}

down() {
  docker rm --force "$SWEEPER" >/dev/null 2>&1 || true
  docker rm --force "$POS_CANARY" >/dev/null 2>&1 || true
  docker rm --force "$NEG_CANARY" >/dev/null 2>&1 || true
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
