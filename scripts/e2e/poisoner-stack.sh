#!/usr/bin/env bash
# poisoner-stack.sh -- the extra infrastructure scripts/e2e/poisoner.sh
# (issue #86 slice C) needs and no other journey does: one more
# Mockingbird canary with the poisoner road paced to burst every few
# seconds, and a container running the real Responder next to it on the
# same network.
#
# Why a canary of its own rather than the base one `stack.sh up` starts:
# the pacing this journey needs is not the pacing a canary ships with. A
# shipped canary bursts at most twice an hour and waits up to three
# minutes for its first burst, which is correct on a real segment and
# useless in a journey. This canary is enrolled with a floor and ceiling
# of a few seconds, which also bounds the start-up delay
# (internal/agent/poisoner's Schedule.StartupDelay: a canary told to
# burst every N must not wait longer than N for its first), so the bait
# goes out within seconds of the container coming up.
#
# It is also enrolled through `birdcage canary enrol --bait-names`, so
# the journey exercises the operator's own path for setting them rather
# than a hand-placed environment variable.
#
# Why the real Responder rather than a hand-made reply: issue #86's
# "Done when" asks for it, and it has already earned its place -- running
# it against the real encoders found two faults no unit test had (an mDNS
# parser that dropped every real answer, because RFC 6762 forbids a
# question section in a response, and a missing MAC on the first hit).
# build/e2e-responder/Dockerfile holds the pin and the reasoning.
#
#   eval "$(scripts/e2e/stack.sh up)"
#   eval "$(scripts/e2e/poisoner-stack.sh up)"
#   scripts/e2e/poisoner.sh
#   scripts/e2e/poisoner-stack.sh down
#   scripts/e2e/stack.sh down
set -eu

STATE_VOL="${E2E_PREFIX}-poisoner-state"
LOG_VOL="${E2E_PREFIX}-poisoner-log"
CANARY="${E2E_PREFIX}-poisoner-canary"
CANARY_NAME="${E2E_POISONER_NAME:-e2e-poisoner}"
CANARY_LANE="${E2E_POISONER_LANE:-e2e-poisoner}"
RESPONDER="${E2E_PREFIX}-poisoner-responder"
# The default tag is prefixed, which is what makes `down` safe to let
# remove it: it only ever deletes an image tag beginning with E2E_PREFIX,
# so pointing this at an image you built yourself
# (E2E_RESPONDER_IMAGE=e2e-responder:local) never deletes it. Exactly the
# rule stack.sh states for its own two images.
RESPONDER_IMAGE="${E2E_RESPONDER_IMAGE:-${E2E_PREFIX}-e2e-responder}"

# The bait names this journey enrols the canary with. Two names in a
# plausible style plus the wpad the detector always adds itself. They are
# here, in a CI script, rather than shipped anywhere a real deployment
# reads: a real operator's names must never be greppable (issue #86
# decision 31), and these are a fixture, not a default.
BAIT_NAMES="${E2E_POISONER_BAIT_NAMES:-e2e-oldfs-01,e2e-oldfs-02}"

# Pacing tight enough for a journey. FLOOR is the longest gap between
# bursts and so also the bound on the start-up delay; CEILING is the
# shortest. HOURS is every hour of every day, because a journey must not
# depend on what time the runner thinks it is.
POISONER_FLOOR="${E2E_POISONER_FLOOR:-5s}"
POISONER_CEILING="${E2E_POISONER_CEILING:-2s}"
POISONER_HOURS='00:00-24:00/Mon,Tue,Wed,Thu,Fri,Sat,Sun'

log() { echo "poisoner-stack: $*" >&2; }
die() { echo "poisoner-stack: $*" >&2; exit 1; }

helper() { "$E2E_STACK" helper "$@"; }

# enrol mints a session and stores its printed `docker run` command in
# the work volume -- the same shape portscan-stack.sh's own enrol uses,
# including reading MOCKINGBIRD_IMAGE off the already-running base canary
# so this always starts the image stack.sh built, plus #86's
# --bait-names flag.
enrol() { # enrol <name> <lane> <work-file>
  local name="$1" lane="$2" work_file="$3" image output
  image="$(docker inspect --format '{{.Config.Image}}' "$E2E_CANARY")" \
    || die "could not read the image $E2E_CANARY is running"

  output="$(docker exec --env "MOCKINGBIRD_IMAGE=$image" "$E2E_BIRDCAGE" \
    /birdcage canary enrol --name "$name" --lane "$lane" --bait-names "$BAIT_NAMES")" \
    || die "birdcage canary enrol ($name) failed"

  # The flag has to have reached the printed command, or this journey
  # would silently test the derived-names path instead of the operator's.
  case "$output" in
    *MOCKINGBIRD_POISONER_NAMES=*) ;;
    *) die "birdcage canary enrol --bait-names printed no MOCKINGBIRD_POISONER_NAMES line" ;;
  esac

  printf '%s\n' "$output" | "$E2E_STACK" write-work "$work_file" \
    || die "could not store the enrolment output for $name"
}

# run takes the printed `docker run` command and edits it: stack.sh's own
# three substitutions (name, both volumes, network) plus this journey's
# pacing, inserted after the --sysctl flag the printed command already
# carries, so nothing else about it -- the capability, the CA pin, the
# deploy token, the bait names the enrol flag put there, the image -- is
# touched. Only the first `docker run` block is taken: enrolment now
# prints the SMB lure's block after the canary's (#87), and evalling both
# would start the lure with this harness's --network on top of its own.
# And, as stack.sh does, the lure's audit mount and its variable are
# deleted: this stack deploys no lure, and left in they create an
# unprefixed `smb-audit` volume that no `down` removes.
run() { # run <work-file> <container> <state-vol> <log-vol>
  local work_file="$1" container="$2" state_vol="$3" log_vol="$4"
  local command pacing
  command="$(helper "sed -n '/^docker run /,/[^\\\\]\$/{p;/[^\\\\]\$/q;}' /work/$work_file")" \
    || die "could not read the printed docker run command for $container"

  pacing="--sysctl net.ipv4.ip_unprivileged_port_start=0 \\\\\\n  -e MOCKINGBIRD_POISONER_FLOOR=$POISONER_FLOOR \\\\\\n  -e MOCKINGBIRD_POISONER_CEILING=$POISONER_CEILING \\\\\\n  -e MOCKINGBIRD_POISONER_HOURS=$POISONER_HOURS \\\\"

  command="$(printf '%s\n' "$command" | sed \
    -e "s|^docker run -d |docker run -d --network $E2E_NET |" \
    -e "s|--name mockingbird |--name $container |" \
    -e "s|-v mockingbird-state:|-v $state_vol:|" \
    -e "s|-v mockingbird-log:|-v $log_vol:|" \
    -e '/-v smb-audit:/d' \
    -e '/MOCKINGBIRD_SMB_AUDIT_PATH/d' \
    -e "s|--sysctl net.ipv4.ip_unprivileged_port_start=0 \\\\|$pacing|")"

  case "$command" in
    docker\ run\ *"$container"*) ;;
    *) die "the printed docker run command for $container did not look the way this harness expects; got: $(printf '%s' "$command" | sed 's/MOCKINGBIRD_DEPLOY_TOKEN=[^ ]*/MOCKINGBIRD_DEPLOY_TOKEN=<redacted>/')" ;;
  esac
  local want
  for want in "--sysctl net.ipv4.ip_unprivileged_port_start=0" \
              "MOCKINGBIRD_POISONER_FLOOR=$POISONER_FLOOR" \
              "MOCKINGBIRD_POISONER_CEILING=$POISONER_CEILING" \
              "MOCKINGBIRD_POISONER_NAMES="; do
    case "$command" in
      *"$want"*) ;;
      *) die "the docker run command for $container is missing $want after editing -- got: $(printf '%s' "$command" | sed 's/MOCKINGBIRD_DEPLOY_TOKEN=[^ ]*/MOCKINGBIRD_DEPLOY_TOKEN=<redacted>/')" ;;
    esac
  done

  log "running ($container): $(printf '%s' "$command" | tr -d '\\' | tr -s ' \n' ' ' | sed -e 's/MOCKINGBIRD_DEPLOY_TOKEN=[^ ]*/MOCKINGBIRD_DEPLOY_TOKEN=<redacted>/' -e 's/MOCKINGBIRD_POISONER_NAMES=[^ ]*/MOCKINGBIRD_POISONER_NAMES=<names>/')"
  eval "$command" >/dev/null || die "the docker run command for $container failed to start"
}

# wait_for_provision polls --status for one session by name, the same way
# portscan-stack.sh and smb-stack.sh do; tail -1 rather than the first
# match, since a name can repeat across runs that never tore the birdcage
# database down.
wait_for_provision() { # wait_for_provision <name> <container> -> prints canary id
  local name="$1" container="$2" attempt status line id
  for attempt in $(seq 1 60); do
    status="$(docker exec "$E2E_BIRDCAGE" /birdcage canary enrol --status 2>/dev/null || true)"
    # ${name} braced: without them shellcheck reads "$name[" as an array
    # expansion (SC1087). Same grep either way. portscan-stack.sh's own copy
    # of this line has the unbraced form.
    line="$(printf '%s\n' "$status" | grep "name=${name}[[:space:]]" | tail -1 || true)"
    case "$line" in
      *state=provisioned*)
        log "$container enrolled on attempt $attempt"
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

# wait_for_line polls a container's own stdout for a startup line, so `up`
# only ever hands the journey a canary that has already said what state
# its detector is in -- the same reason portscan-stack.sh waits for its
# own.
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
  die "$container never reported '$substring'"
}

# build_responder builds the CI-only Responder image if it is not already
# present. Built here rather than in build:images because it is not a
# shipped artefact and nothing but this journey ever wants it -- the same
# call build/e2e-samba makes.
build_responder() {
  if docker image inspect "$RESPONDER_IMAGE" >/dev/null 2>&1; then
    log "$RESPONDER_IMAGE already built"
    return 0
  fi
  log "building $RESPONDER_IMAGE"
  docker build -q -f build/e2e-responder/Dockerfile -t "$RESPONDER_IMAGE" . >/dev/null \
    || die "building $RESPONDER_IMAGE failed"
}

up() {
  command -v docker >/dev/null 2>&1 || die "docker is not on PATH"
  [ -n "${E2E_STACK:-}" ] && [ -n "${E2E_NET:-}" ] && [ -n "${E2E_BIRDCAGE:-}" ] && [ -n "${E2E_CANARY:-}" ] \
    || die "E2E_STACK/E2E_NET/E2E_BIRDCAGE/E2E_CANARY unset -- run: eval \"\$(scripts/e2e/stack.sh up)\" first"
  down >/dev/null 2>&1 || true

  build_responder

  local vol
  for vol in "$STATE_VOL" "$LOG_VOL"; do
    docker volume create "$vol" >/dev/null || die "creating volume $vol failed"
  done

  # Responder first, and listening, before the canary can ask anything:
  # a bait query that goes out before the poisoner is up gets the silence
  # a clean segment gives, which is the pass this journey is not testing.
  docker run --detach --name "$RESPONDER" --network "$E2E_NET" --init \
    --memory 512m --cpus 1.0 \
    "$RESPONDER_IMAGE" >/dev/null || die "starting $RESPONDER failed"
  wait_for_line "$RESPONDER" "Listening for events..."

  enrol "$CANARY_NAME" "$CANARY_LANE" poisoner-enrol-output.txt
  run poisoner-enrol-output.txt "$CANARY" "$STATE_VOL" "$LOG_VOL"
  CANARY_ID="$(wait_for_provision "$CANARY_NAME" "$CANARY")"
  wait_for_line "$CANARY" "poisoner detection active"

  cat <<EOF
export POISONER_CANARY=$CANARY
export POISONER_CANARY_ID=$CANARY_ID
export POISONER_RESPONDER=$RESPONDER
EOF
}

down() {
  docker rm --force "$RESPONDER" >/dev/null 2>&1 || true
  docker rm --force "$CANARY" >/dev/null 2>&1 || true
  local vol
  for vol in "$STATE_VOL" "$LOG_VOL"; do
    docker volume rm --force "$vol" >/dev/null 2>&1 || true
  done
  # Only ever an image tag this harness named itself -- see
  # RESPONDER_IMAGE's own comment. It has to go: E2E_PREFIX carries
  # $CI_JOB_ID in the pipeline, so the tag is unique per job and could
  # never be reused anyway -- keeping it would just fill a long-lived
  # runner's disk one journey at a time.
  case "$RESPONDER_IMAGE" in
    "$E2E_PREFIX"*) docker image rm --force "$RESPONDER_IMAGE" >/dev/null 2>&1 || true ;;
  esac
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac
