#!/usr/bin/env bash
# smb-stack.sh -- the extra infrastructure scripts/e2e/smb.sh (issue #78
# journey 3) needs and no other journey does: a real Samba server, and a
# second Mockingbird canary, with its own OpenCanary container (#132)
# configured to watch the Samba server's audit log.
#
# This is deliberately its own file rather than an addition to
# scripts/e2e/stack.sh's `up`. stack.sh's header says journey logic does
# not go in that file, and more concretely: `stack.sh up` already deploys
# birdcage plus one canary for the two journeys that need nothing else,
# and building a Samba image and standing up a second canary on every
# run would slow both of them down for a feature only one journey
# exercises. This file is only ever invoked by scripts/e2e/smb.sh.
#
# Since #132, OpenCanary is its own container, joining its own address
# holder exactly as the product ships it (cmd/birdcage/canary_lure.go;
# stack.sh's own start_holder and run_opencanary_command are the model),
# and the smb module -- and so the overriding opencanary.conf and the
# Samba server's audit-log mount -- moved with it: the agent never ran
# any OpenCanary module and has no business mounting either any more
# (build/opencanary/README.md, "Why it has no access to the agent's own
# state").
#
#   eval "$(scripts/e2e/stack.sh up)"
#   eval "$(scripts/e2e/smb-stack.sh up)"
#   scripts/e2e/smb.sh
#   scripts/e2e/smb-stack.sh down
#   scripts/e2e/stack.sh down
#
# Everything here is named from stack.sh's own E2E_PREFIX (required in
# the environment already, see the check below), so `down` only ever
# touches what this file created and two parallel pipelines never
# collide, the same discipline stack.sh itself uses.
set -eu

[ -n "${E2E_PREFIX:-}" ] || {
  echo "smb-stack: E2E_PREFIX unset -- run: eval \"\$(scripts/e2e/stack.sh up)\" first" >&2
  exit 2
}

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

SAMBA_IMAGE="${E2E_PREFIX}-samba-image"
SAMBA="${E2E_PREFIX}-smb"
SMB_LOG_VOL="${E2E_PREFIX}-smb-log"
SMB_CONF_VOL="${E2E_PREFIX}-smb-conf"

SMB_CANARY="${E2E_PREFIX}-smb-canary"
SMB_CANARY_STATE_VOL="${E2E_PREFIX}-smb-canary-state"
SMB_CANARY_LOG_VOL="${E2E_PREFIX}-smb-canary-log"
SMB_CANARY_NAME="${E2E_SMB_CANARY_NAME:-e2e-smb-canary}"
SMB_CANARY_LANE="${E2E_SMB_CANARY_LANE:-e2e-smb}"
# The address holder and OpenCanary's own container this canary joins
# (#132), same shape as stack.sh's own HOLDER/OPENCANARY.
SMB_HOLDER="${E2E_PREFIX}-smb-holder"
SMB_OPENCANARY="${E2E_PREFIX}-smb-opencanary"
# Filled in by `up`, read off the already-running base holder
# (E2E_HOLDER) the same way MOCKINGBIRD_IMAGE below is read off the base
# canary.
HOLDER_IMAGE=""

log() { echo "smb-stack: $*" >&2; }
die() { echo "smb-stack: $*" >&2; exit 1; }

helper() { "$E2E_STACK" helper "$@"; }

build_samba_image() {
  if docker image inspect "$SAMBA_IMAGE" >/dev/null 2>&1; then
    log "using existing image $SAMBA_IMAGE"
    return 0
  fi
  log "building $SAMBA_IMAGE from build/e2e-samba/Dockerfile"
  # --build-arg BASE_IMAGE: CI's dependency-proxy pin (refs #128,
  # .gitlab-ci.yml) when set, the Dockerfile's own default on a workstation.
  docker build --build-arg BASE_IMAGE="${DEBIAN_TRIXIE_SLIM_IMAGE:-debian:trixie-slim}" \
    --file "$REPO_ROOT/build/e2e-samba/Dockerfile" --tag "$SAMBA_IMAGE" "$REPO_ROOT" >/dev/null \
    || die "building $SAMBA_IMAGE failed"
}

# write_smb_conf writes the overriding opencanary.conf this journey's
# canary needs -- the shipped conf (build/opencanary/opencanary.conf)
# with only smb.enabled and smb.auditfile changed -- into a fresh named
# volume. Piped through stdin into a throwaway container, not written to
# a host path and bind-mounted: the docker daemon this script talks to
# is not guaranteed to share a filesystem with the job container it runs
# in (see stack.sh's own helper_in), so the volume is the only thing
# both sides can reach.
write_smb_conf() {
  sed \
    -e 's|"smb.enabled": false|"smb.enabled": true|' \
    -e 's|"smb.auditfile": "/var/log/samba-audit.log"|"smb.auditfile": "/samba-audit/samba-audit.log"|' \
    "$REPO_ROOT/build/opencanary/opencanary.conf" \
    | docker run --rm --interactive --volume "$SMB_CONF_VOL:/out" "${ALPINE_IMAGE:-alpine:3.24}" sh -c 'cat > /out/opencanary.conf' \
    || die "writing the overriding opencanary.conf failed"
  # Fails loudly rather than silently shipping the stock conf (smb
  # disabled) if either sed pattern ever stops matching the file it is
  # editing. ${ALPINE_IMAGE:-alpine:3.24}: CI's dependency-proxy pin
  # (refs #128, .gitlab-ci.yml) when set, the plain Docker Hub tag on a
  # workstation.
  docker run --rm --volume "$SMB_CONF_VOL:/out:ro" "${ALPINE_IMAGE:-alpine:3.24}" \
    sh -c 'grep -q "\"smb.enabled\": true" /out/opencanary.conf && grep -q "/samba-audit/samba-audit.log" /out/opencanary.conf' \
    || die "the overriding opencanary.conf does not enable smb -- sed pattern out of date?"
}

start_samba() {
  docker run --detach --name "$SAMBA" --network "$E2E_NET" --init \
    --pids-limit 128 --memory 256m --cpus 0.5 \
    --volume "$SMB_LOG_VOL:/samba-audit" \
    "$SAMBA_IMAGE" >/dev/null || die "starting $SAMBA failed"

  # smbclient -L, not a bare port check: this proves smbd is actually
  # answering SMB, the same reason enrol-and-hit.sh waits for FTP's 220
  # greeting rather than a socket accept.
  local attempt
  for attempt in $(seq 1 30); do
    if docker run --rm --network "$E2E_NET" --entrypoint smbclient "$SAMBA_IMAGE" \
         -L "//$SAMBA" -N 2>/dev/null | grep -q 'Disk'; then
      log "smbd answered on attempt $attempt"
      return 0
    fi
    sleep 1
  done
  log "smbd never answered; its log follows"
  docker logs "$SAMBA" >&2 || true
  die "smbd did not become ready"
}

# enrol_smb_canary mints a second enrolment session exactly the way
# stack.sh's own enrol_canary does (see that file for why the two
# addresses are set first -- already done by `stack.sh up`, once, for
# the whole birdcage instance). MOCKINGBIRD_IMAGE is discovered from the
# already-running primary canary rather than guessed, so this always
# starts the same image stack.sh built, whatever tag or override name it
# was given. OPENCANARY_IMAGE is E2E_OPENCANARY_IMAGE_REF, stack.sh's own
# `up` export of the exact tag it built or was handed (#132).
enrol_smb_canary() {
  local image output
  image="$(docker inspect --format '{{.Config.Image}}' "$E2E_CANARY")" \
    || die "could not read the image $E2E_CANARY is running"

  output="$(docker exec --env "MOCKINGBIRD_IMAGE=$image" --env "OPENCANARY_IMAGE=$E2E_OPENCANARY_IMAGE_REF" "$E2E_BIRDCAGE" \
    /birdcage canary enrol --name "$SMB_CANARY_NAME" --lane "$SMB_CANARY_LANE")" \
    || die "birdcage canary enrol (smb canary) failed"

  printf '%s\n' "$output" | "$E2E_STACK" write-work smb-enrol-output.txt \
    || die "could not store the smb canary's enrolment output"
}

# start_holder brings up this canary's own address holder (#126, #132),
# the same shape stack.sh's own start_holder uses. --network-alias names
# the canary itself: since #132 the canary joins this holder's namespace
# rather than owning one, so it gets no Docker embedded-DNS entry of its
# own (stack.sh's own comment on this has the reproduction).
start_holder() {
  docker run --detach --name "$SMB_HOLDER" \
    --network "$E2E_NET" \
    --network-alias "$SMB_CANARY" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 16 \
    --memory 32m \
    "$HOLDER_IMAGE" >/dev/null || die "starting $SMB_HOLDER failed"
}

# run_smb_canary takes the printed `docker run` command and edits it:
# stack.sh's own substitutions (name, both volumes, joining this canary's
# own holder rather than the literal name `holder`). Since #132 this
# canary mounts nothing of its own beyond that: the overriding
# opencanary.conf and the Samba server's audit-log volume are OpenCanary's
# own mounts now (run_smb_opencanary below) -- this agent never ran any
# OpenCanary module and has no access to that configuration or that log
# (build/opencanary/README.md, "Why it has no access to the agent's own
# state" makes the same point the other way round, about the agent's own
# state volume).
run_smb_canary() {
  local command
  # The canary's own `docker run` block only, matched by its
  # `--name mockingbird` line rather than any `docker run`: the enrolment
  # output has carried three blocks since #126 (holder, canary, lure --
  # see stack.sh run_printed_command), and matching the first `docker run`
  # line unconditionally would capture the holder's block instead.
  command="$(helper "sed -n '/^docker run -d --name mockingbird /,/[^\\\\]\$/{p;/[^\\\\]\$/q;}' /work/smb-enrol-output.txt")" \
    || die "could not read the smb canary's printed docker run command"

  command="$(printf '%s\n' "$command" | sed \
    -e "s|--name mockingbird |--name $SMB_CANARY |" \
    -e "s|-v mockingbird-state:|-v $SMB_CANARY_STATE_VOL:|" \
    -e "s|-v mockingbird-log:|-v $SMB_CANARY_LOG_VOL:|" \
    -e "s|--network container:holder|--network container:$SMB_HOLDER|" \
    -e "/-v smb-audit:/d" \
    -e "/MOCKINGBIRD_SMB_AUDIT_PATH/d")"

  case "$command" in
    docker\ run\ *"$SMB_CANARY"*) ;;
    *) die "the smb canary's printed docker run command did not look the way this harness expects; got: $(printf '%s' "$command" | sed 's/MOCKINGBIRD_DEPLOY_TOKEN=[^ ]*/MOCKINGBIRD_DEPLOY_TOKEN=<redacted>/')" ;;
  esac

  # Second use of the mockingbird build tag in this job -- stack.sh's own
  # enrol_canary already used it once, earlier, to start the primary
  # canary this smb canary is modelled on. In CI a concurrent pipeline's
  # prune (#112) can delete the local tag between the two uses even
  # though the job's own before-script recovery already ran once; re-run
  # it immediately before this second `docker run`, same as the job's
  # first call, rather than assume the earlier check still holds. A
  # no-op outside CI, where these variables are unset.
  if [ -n "${MOCKINGBIRD_BUILD_IMAGE:-}" ] && [ -n "${MOCKINGBIRD_BUILD_DIGEST:-}" ]; then
    "$REPO_ROOT/scripts/ci-ensure-image.sh" "$MOCKINGBIRD_BUILD_IMAGE" "$MOCKINGBIRD_BUILD_DIGEST" >&2 \
      || die "could not ensure $MOCKINGBIRD_BUILD_IMAGE is present before starting the smb canary"
  fi

  log "running: $(printf '%s' "$command" | tr -d '\\' | tr -s ' \n' ' ' | sed 's/MOCKINGBIRD_DEPLOY_TOKEN=[^ ]*/MOCKINGBIRD_DEPLOY_TOKEN=<redacted>/')"
  eval "$command" >/dev/null || die "the smb canary's docker run command failed to start"
}

# run_smb_opencanary is run_smb_canary's own twin for OpenCanary's
# printed block (#132): this canary's own OpenCanary container, joining
# this canary's own holder rather than the literal name `holder`, and
# carrying two mounts of our own on top of stack.sh's own substitution
# (the shared log volume, read-write here since this is the writer) --
# the overriding opencanary.conf (a single file out of $SMB_CONF_VOL, via
# volume-subpath, so nothing else /etc/opencanaryd ships is disturbed)
# and the Samba container's audit-log volume, read-only: this is the
# container that watches it now. Run after run_smb_canary, so the
# agent's webhook receiver is already listening before OpenCanary's first
# attempt to reach it (stack.sh's own run_opencanary_command has the
# reproduction of what happens the other way round).
run_smb_opencanary() {
  local command
  command="$(helper "sed -n '/^docker run -d --name opencanary /,/[^\\\\]\$/{p;/[^\\\\]\$/q;}' /work/smb-enrol-output.txt")" \
    || die "could not read the smb canary's printed OpenCanary command"

  command="$(printf '%s\n' "$command" | sed \
    -e "s|--name opencanary |--name $SMB_OPENCANARY |" \
    -e "s|--network container:holder|--network container:$SMB_HOLDER|" \
    -e "s|-v mockingbird-log:/var/log/opencanary \\\\|-v $SMB_CANARY_LOG_VOL:/var/log/opencanary -v $SMB_LOG_VOL:/samba-audit:ro --mount type=volume,source=$SMB_CONF_VOL,target=/etc/opencanaryd/opencanary.conf,volume-subpath=opencanary.conf \\\\|")"

  case "$command" in
    docker\ run\ *"$SMB_OPENCANARY"*"$E2E_OPENCANARY_IMAGE_REF"*) ;;
    *) die "the smb canary's printed OpenCanary command did not look the way this harness expects; got: $command" ;;
  esac
  case "$command" in
    *"$SMB_LOG_VOL:/samba-audit:ro"*) ;;
    *) die "the smb canary's OpenCanary command is missing the samba-audit mount after editing -- got: $command" ;;
  esac
  case "$command" in
    *"volume-subpath=opencanary.conf"*) ;;
    *) die "the smb canary's OpenCanary command is missing the overriding opencanary.conf mount after editing -- got: $command" ;;
  esac

  # Second use of the opencanary build tag in this job, the same #112
  # concurrent-prune risk this file's own mockingbird check names --
  # stack.sh's own `up` already used this tag once, to start the base
  # stack's own OpenCanary container.
  if [ -n "${OPENCANARY_BUILD_IMAGE:-}" ] && [ -n "${OPENCANARY_BUILD_DIGEST:-}" ]; then
    "$REPO_ROOT/scripts/ci-ensure-image.sh" "$OPENCANARY_BUILD_IMAGE" "$OPENCANARY_BUILD_DIGEST" >&2 \
      || die "could not ensure $OPENCANARY_BUILD_IMAGE is present before starting the smb canary's OpenCanary container"
  fi

  log "running: $(printf '%s' "$command" | tr -d '\\' | tr -s ' \n' ' ')"
  eval "$command" >/dev/null || die "the smb canary's OpenCanary docker run command failed to start"
}

wait_for_smb_canary() {
  local attempt status line
  for attempt in $(seq 1 60); do
    status="$(docker exec "$E2E_BIRDCAGE" /birdcage canary enrol --status 2>/dev/null || true)"
    # tail -1, not just the grep match: a name can repeat across runs
    # that never tore the birdcage database down (this script's own
    # `down` does not touch it -- only stack.sh's does), so more than
    # one session can carry this name. The most recently minted one is
    # always last in `--status`'s own output, the same assumption
    # stack.sh's wait_for_enrolment makes for the primary canary.
    line="$(printf '%s\n' "$status" | grep "name=$SMB_CANARY_NAME[[:space:]]" | tail -1 || true)"
    case "$line" in
      *state=provisioned*)
        log "the smb canary enrolled on attempt $attempt"
        SMB_CANARY_ID="$(printf '%s\n' "$line" | sed -n 's/.*[[:space:]]canary=\([^[:space:]]*\).*/\1/p')"
        [ -n "$SMB_CANARY_ID" ] || die "the smb canary session is provisioned but --status printed no canary id"
        return 0
        ;;
    esac
    sleep 1
  done
  log "the smb canary never contacted birdcage; its log follows"
  docker logs "$SMB_CANARY" >&2 || true
  die "smb canary enrolment never completed"
}

# wait_for_smb_module_ready closes a real race, found by running this
# journey rather than guessed at: OpenCanary's FileSystemWatcher
# (opencanary/modules/__init__.py) seeks to the *end* of the audit file
# the moment it starts watching, so any smbd_audit line already written
# before that seek is silently skipped forever, not queued. Enrolment
# finishing (wait_for_smb_canary above) only proves the agent has
# talked to birdcage -- since #132 OpenCanary is a separate container the
# agent no longer supervises, and its own module startup (loading every
# service, including the smb watcher) takes a further couple of seconds
# after it starts. Checked against $SMB_OPENCANARY's own log, not the
# agent's: OpenCanary prints this line to its own stdout, which the
# agent's container never sees (before #132 the two were the same
# container, and this line appeared in the agent's log because OpenCanary
# was its child process). Without this, scripts/e2e/smb.sh's real SMB
# write could land before the watcher ever attached, and every alert
# would silently be lost -- which is exactly what happened the first time
# this journey was run back-to-back rather than by hand with pauses
# between commands.
wait_for_smb_module_ready() {
  local attempt
  for attempt in $(seq 1 30); do
    if docker logs "$SMB_OPENCANARY" 2>&1 | grep -q "Ran startYourEngines on class CanarySamba"; then
      log "OpenCanary's smb module attached to the audit file on attempt $attempt"
      return 0
    fi
    sleep 1
  done
  log "OpenCanary's smb module never reported ready; $SMB_OPENCANARY's log follows"
  docker logs "$SMB_OPENCANARY" >&2 || true
  die "the smb module in $SMB_OPENCANARY never started watching its audit file"
}

up() {
  command -v docker >/dev/null 2>&1 || die "docker is not on PATH"
  [ -n "${E2E_STACK:-}" ] && [ -n "${E2E_NET:-}" ] && [ -n "${E2E_BIRDCAGE:-}" ] && [ -n "${E2E_CANARY:-}" ] \
    && [ -n "${E2E_HOLDER:-}" ] && [ -n "${E2E_OPENCANARY_IMAGE_REF:-}" ] \
    || die "E2E_STACK/E2E_NET/E2E_BIRDCAGE/E2E_CANARY/E2E_HOLDER/E2E_OPENCANARY_IMAGE_REF unset -- run: eval \"\$(scripts/e2e/stack.sh up)\" first"
  down >/dev/null 2>&1 || true

  HOLDER_IMAGE="$(docker inspect --format '{{.Config.Image}}' "$E2E_HOLDER")" \
    || die "could not read the image $E2E_HOLDER is running"

  build_samba_image
  docker volume create "$SMB_LOG_VOL" >/dev/null || die "creating volume $SMB_LOG_VOL failed"
  docker volume create "$SMB_CONF_VOL" >/dev/null || die "creating volume $SMB_CONF_VOL failed"
  write_smb_conf
  start_samba
  start_holder
  enrol_smb_canary
  run_smb_canary
  run_smb_opencanary
  wait_for_smb_canary
  wait_for_smb_module_ready

  cat <<EOF
export SMB_SAMBA=$SAMBA
export SMB_SAMBA_IMAGE=$SAMBA_IMAGE
export SMB_CANARY=$SMB_CANARY
export SMB_CANARY_ID=$SMB_CANARY_ID
export SMB_CANARY_NAME=$SMB_CANARY_NAME
export SMB_HOLDER=$SMB_HOLDER
export SMB_OPENCANARY=$SMB_OPENCANARY
EOF
}

down() {
  docker rm --force "$SMB_CANARY" >/dev/null 2>&1 || true
  docker rm --force "$SMB_OPENCANARY" >/dev/null 2>&1 || true
  docker rm --force "$SMB_HOLDER" >/dev/null 2>&1 || true
  docker rm --force "$SAMBA" >/dev/null 2>&1 || true
  local vol
  for vol in "$SMB_LOG_VOL" "$SMB_CONF_VOL" "$SMB_CANARY_STATE_VOL" "$SMB_CANARY_LOG_VOL"; do
    docker volume rm --force "$vol" >/dev/null 2>&1 || true
  done
  case "$SAMBA_IMAGE" in
    "$E2E_PREFIX"*) docker image rm --force "$SAMBA_IMAGE" >/dev/null 2>&1 || true ;;
  esac
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *)
    echo "usage: $0 {up|down}" >&2
    exit 2 ;;
esac
