#!/usr/bin/env bash
# live-check.sh -- issue #237: trip every lure on a real, enrolled canary and
# follow each alert to the dashboard, entirely on this host.
#
#   LIVE_CHECK_RELEASE_ENV=/path/to/release.env scripts/e2e/live-check.sh
#
# What it does, in order:
#   1. pulls the images a CI build:images job already built, BY DIGEST, from
#      the project registry (owner decision 75b: nothing is built from source
#      here, so the check tests that CI build), plus the poisoner fixture;
#   2. builds the two tool images (a helper and an attacker) from layers that
#      are already on the host -- no package mirror is reachable;
#   3. brings up birdcage and one enrolled canary with every container it is
#      shipped with (holder, mockingbird, OpenCanary, smb-lure), on ONE docker
#      network created with --internal, so nothing can leave the host;
#   4. trips each lure from a separate attacker container, and for each one
#      records when it was tripped, when the alert first showed in
#      GET /api/alerts, and the alert's fields;
#   5. samples the canary's status and active states every 5 s throughout and
#      reads its self-test runs before and after;
#   6. takes two Playwright screenshots (cage events list, canary page);
#   7. tears everything down, even on failure (EXIT trap): containers, the
#      network, volumes, and the images this run pulled or built.
#
# It reuses stack.sh (birdcage, helper, sign-in, a first canary that is only
# harness scaffolding) and smb-lure-stack.sh (the canary under test: holder +
# mockingbird + OpenCanary + smb-lure). The per-lure journey scripts
# (snmp.sh, portscan.sh, smb-lure.sh, ...) need images built with a package
# manager, so the trips live in live-check/attack.py instead (standard library
# only); see docs/live-checks/ for what that means for coverage.
#
# Inputs (environment):
#   LIVE_CHECK_RELEASE_ENV   path to build:images' release.env (required). Its
#                            lines are <NAME>_BUILD_DIGEST=<repo>@sha256:...
#                            Get one from a green pipeline's build:images job,
#                            or from the `cat release.env` at the end of its log.
#   LIVE_CHECK_OUT           where raw results go (default: a fresh temp dir)
#   LIVE_CHECK_BASE_IMAGE    local base for the tool images (default
#                            node:26-trixie; must already be on this host)
#   LIVE_CHECK_PLAYWRIGHT    directory holding the playwright and
#                            playwright-core npm packages (v1.63 matches the
#                            image); default: the birdcage frontend's
#   LIVE_CHECK_PW_IMAGE      the Playwright image (default
#                            mcr.microsoft.com/playwright:v1.63.0-noble, pinned by digest)
#   LIVE_CHECK_KEEP_IMAGES=1 leave pulled and built images in place
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$REPO_ROOT/scripts/e2e"
ATTACK_DIR="$HERE/live-check"

export E2E_PREFIX="${E2E_PREFIX:-birdcage-live}"
OUT="${LIVE_CHECK_OUT:-$(mktemp -d "${TMPDIR:-/tmp}/live-check.XXXXXX")}"
BASE_IMAGE="${LIVE_CHECK_BASE_IMAGE:-node:26-trixie}"
PW_IMAGE="${LIVE_CHECK_PW_IMAGE:-mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27}"
PW_MODULES="${LIVE_CHECK_PLAYWRIGHT:-$REPO_ROOT/frontend/node_modules}"
[ -d "$PW_MODULES/playwright" ] || PW_MODULES="$HOME/projects/birdcage/frontend/node_modules"

HELPER_SRC="live-check-helper:local"
CLIENT_IMAGE="live-check-smbclient:local"
PROBE="$E2E_PREFIX-probe"
ATTACKER="$E2E_PREFIX-attacker"
FIXTURE="$E2E_PREFIX-fixture"

log() { echo "live-check: $*" >&2; }
die() { log "$*"; exit 1; }
now() { date +%s.%N; }

[ -n "${LIVE_CHECK_RELEASE_ENV:-}" ] && [ -r "$LIVE_CHECK_RELEASE_ENV" ] \
  || die "set LIVE_CHECK_RELEASE_ENV to a build:images release.env (see the header)"
command -v docker >/dev/null || die "docker is not on PATH"
command -v jq >/dev/null || die "jq is not on PATH"
docker image inspect "$BASE_IMAGE" >/dev/null 2>&1 \
  || die "$BASE_IMAGE is not on this host and this script pulls nothing but the project's digests"
mkdir -p "$OUT"

digest_of() { sed -n "s|^$1_BUILD_DIGEST=||p" "$LIVE_CHECK_RELEASE_ENV" | tail -1; }
BC="$(digest_of BIRDCAGE)"; MB="$(digest_of MOCKINGBIRD)"; HO="$(digest_of HOLDER)"
OC="$(digest_of OPENCANARY)"; SL="$(digest_of SMB_LURE)"
for v in BC MB HO OC SL; do
  case "${!v}" in *@sha256:*) ;; *) die "no $v digest in $LIVE_CHECK_RELEASE_ENV" ;; esac
done
REGISTRY="${BC%%/*}"
FIXTURE_DIGEST="$(sed -n 's|^ *E2E_POISONER_FIXTURE_DIGEST: \$CI_REGISTRY/||p' "$REPO_ROOT/.gitlab-ci.yml" | head -1)"
[ -n "$FIXTURE_DIGEST" ] || die "no E2E_POISONER_FIXTURE_DIGEST in .gitlab-ci.yml"
FIXTURE_IMAGE="$REGISTRY/$FIXTURE_DIGEST"
case "$FIXTURE_IMAGE" in *@sha256:*) ;; *) die "fixture is not pinned by digest: $FIXTURE_IMAGE" ;; esac

PULLED=()
BUILT=("$HELPER_SRC" "$CLIENT_IMAGE")
UP=0
CTX=""
SHOTS="$E2E_PREFIX-shots"

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  log "tearing down (exit status $rc)"
  docker rm --force "$PROBE" "$ATTACKER" "$FIXTURE" "$SHOTS" >/dev/null 2>&1 || true
  if [ -n "$CTX" ]; then rm -rf "$CTX"; fi
  if [ "$UP" = 1 ] || docker network inspect "$E2E_PREFIX-net" >/dev/null 2>&1; then
    export E2E_NET="$E2E_PREFIX-net" E2E_STACK="$HERE/stack.sh" E2E_BIRDCAGE="$E2E_PREFIX-birdcage" \
      E2E_CANARY="$E2E_PREFIX-canary" E2E_OPENCANARY_IMAGE_REF="$OC" E2E_SMB_LURE_IMAGE="$SL" \
      E2E_HOLDER_IMAGE="$HO" E2E_BIRDCAGE_IMAGE="$BC" E2E_MOCKINGBIRD_IMAGE="$MB" E2E_OPENCANARY_IMAGE="$OC" \
      E2E_SMB_CLIENT_IMAGE="$CLIENT_IMAGE"
    "$HERE/smb-lure-stack.sh" down >/dev/null 2>&1 || true
    "$HERE/stack.sh" down >&2 || true
  fi
  if [ "${LIVE_CHECK_KEEP_IMAGES:-}" != 1 ]; then
    local image
    for image in "${BUILT[@]}" "${PULLED[@]}"; do
      docker image rm --force "$image" >/dev/null 2>&1 || true
    done
  fi
  log "left behind: containers=$(docker ps -a --format '{{.Names}}' | grep -c "^$E2E_PREFIX" || true)" \
    "networks=$(docker network ls --format '{{.Name}}' | grep -c "^$E2E_PREFIX" || true)" \
    "volumes=$(docker volume ls -q | grep -c "^$E2E_PREFIX" || true)"
  exit "$rc"
}
trap cleanup EXIT INT TERM

# ---- 1. images, by digest only --------------------------------------------
log "pulling by digest from $REGISTRY"
for image in "$BC" "$MB" "$HO" "$OC" "$SL" "$FIXTURE_IMAGE"; do
  if docker image inspect "$image" >/dev/null 2>&1; then
    log "already present: $image"
  else
    PULLED+=("$image")
    docker pull --quiet "$image" >/dev/null || die "pulling $image failed"
  fi
done
{
  echo "birdcage $BC"; echo "mockingbird $MB"; echo "holder $HO"; echo "opencanary $OC"
  echo "smb-lure $SL"; echo "poisoner-fixture $FIXTURE_IMAGE"
} > "$OUT/images.txt"

# ---- 2. tool images from layers already on the host -----------------------
# The helper stack.sh wants (sh, curl, openssl, jq, sqlite3) and the attacker
# share one image: $BASE_IMAGE plus the host's own jq and sqlite3 with their
# libraries. stack.sh normally builds its helper with `apk add`, which needs a
# mirror; E2E_HELPER_IMAGE_SOURCE hands it this one instead.
CTX="$(mktemp -d "${TMPDIR:-/tmp}/live-check-ctx.XXXXXX")"
mkdir -p "$CTX/bin" "$CTX/lib" "$CTX/attack"
cp "$(command -v jq)" "$(command -v sqlite3)" "$CTX/bin/"
for lib in $(ldd "$CTX/bin/jq" "$CTX/bin/sqlite3" | awk '/=> \//{print $3}' | sort -u \
             | grep -v '/libc\.so\|/libm\.so\|/libdl\|/libpthread\|/ld-linux'); do
  cp -L "$lib" "$CTX/lib/"
done
cp "$ATTACK_DIR/attack.py" "$CTX/attack/attack.py"
cat > "$CTX/Dockerfile" <<EOF
FROM $BASE_IMAGE
COPY bin/ /usr/local/bin/
COPY lib/ /usr/local/lib/hostlib/
COPY attack/ /opt/attack/
ENV LD_LIBRARY_PATH=/usr/local/lib/hostlib
EOF
docker build --pull=false -q -t "$HELPER_SRC" "$CTX" >/dev/null || die "building the helper image failed"
cat > "$CTX/Dockerfile.client" <<EOF
FROM $HELPER_SRC
ENTRYPOINT ["python3", "-I", "/opt/attack/attack.py", "smbclient"]
EOF
docker build --pull=false -q -f "$CTX/Dockerfile.client" -t "$CLIENT_IMAGE" "$CTX" >/dev/null \
  || die "building the smbclient stand-in failed"
rm -rf "$CTX"

# ---- 3. the stack, on one --internal network ------------------------------
export E2E_NET_INTERNAL=1 E2E_HELPER_IMAGE_SOURCE="$HELPER_SRC" E2E_KEEP_LOGIN=1
export E2E_BIRDCAGE_IMAGE="$BC" E2E_MOCKINGBIRD_IMAGE="$MB" E2E_OPENCANARY_IMAGE="$OC" E2E_HOLDER_IMAGE="$HO"
export E2E_SMB_LURE_IMAGE="$SL" E2E_SMB_CLIENT_IMAGE="$CLIENT_IMAGE"
UP=1
log "stack.sh up (birdcage + the harness's first canary)"
eval "$("$HERE/stack.sh" up)"
[ "$(docker network inspect "$E2E_NET" --format '{{.Internal}}')" = true ] \
  || die "$E2E_NET is not an --internal network; refusing to attack on a routable one"

# The answerer must be listening before the canary under test starts, because
# the canary's first poisoner burst comes within minutes of its own start.
# The fixture's own entrypoint picks its interface from the default route,
# and an --internal network has none, so it falls back to a name that carries
# an "@ifN" suffix and Responder refuses it (reported in the record); the same
# Responder command is started here on eth0 instead.
log "starting the poisoner fixture's Responder on eth0"
docker run -d --name "$FIXTURE" --network "$E2E_NET" --init --memory 512m --cpus 1 \
  --entrypoint sh "$FIXTURE_IMAGE" -c 'cd /opt/responder && exec python3 -u ./Responder.py -I eth0 -v' >/dev/null \
  || die "starting the fixture failed"
for _ in $(seq 1 30); do
  docker logs "$FIXTURE" 2>&1 | grep -q 'Listening for events' && break
  sleep 1
done
docker logs "$FIXTURE" 2>&1 | grep -q 'Listening for events' || die "Responder never started: $(docker logs "$FIXTURE" 2>&1 | tail -3)"

log "smb-lure-stack.sh up (the canary under test: holder, mockingbird, OpenCanary, smb-lure)"
eval "$("$HERE/smb-lure-stack.sh" up)"
TARGET="$SMB_LURE_HOLDER"     # the canary's address on the network, by name
CANARY_ID="$SMB_LURE_CANARY_ID"
CANARY_STARTED="$(docker inspect --format '{{.State.StartedAt}}' "$SMB_LURE_CANARY")"
echo "$CANARY_ID" > "$OUT/canary-id.txt"

# ---- 4. probe (holds the dashboard token) and attacker (holds nothing) ----
docker run -d --name "$PROBE" --network "$E2E_NET" -e "BIRDCAGE_URL=$BIRDCAGE_URL" \
  -v "$E2E_PREFIX-tls:/tls:ro" -v "$E2E_PREFIX-work:/work:ro" "$HELPER_SRC" sleep infinity >/dev/null
docker run -d --name "$ATTACKER" --network "$E2E_NET" "$HELPER_SRC" sleep infinity >/dev/null
probe() { docker exec "$PROBE" python3 -I /opt/attack/attack.py "$@"; }
attacker() { docker exec "$ATTACKER" python3 -I /opt/attack/attack.py "$@"; }

# Health is sampled every 5 s from here to the end, including the pending phase.
docker exec -d "$PROBE" python3 -I /opt/attack/attack.py health "$CANARY_ID" 5 /tmp/health.jsonl

# Poisoner: the canary baits on its own schedule, so this watcher starts now,
# before anything else, and runs in the background to the end.
POIS_BASE="$(probe baseline "$CANARY_ID")"
probe poll poisoner "$CANARY_ID" "$POIS_BASE" 900 > "$OUT/poisoner.poll.json" &
POIS_PID=$!

# ---- 5. wait for the canary to leave "pending" ----------------------------
log "waiting for the first self-test to pass (status ok)"
status=""
for _ in $(seq 1 360); do
  status="$(probe canary "$CANARY_ID" | jq -r '.canary.status')" || status=""
  [ "$status" = ok ] && break
  sleep 2
done
[ "$status" = ok ] || { probe canary "$CANARY_ID" >&2 || true; die "the canary never reached status ok"; }
echo "seconds_from_canary_start_to_ok=$(( $(date +%s) - $(date -d "$CANARY_STARTED" +%s) ))" > "$OUT/time-to-ok.txt"
probe canary "$CANARY_ID" > "$OUT/health-before.json"
sleep 6

# ---- 6. trip every lure ----------------------------------------------------
trip() { # trip <lure> <service> [marker]
  local lure="$1" service="$2" marker="${3:-}" base
  log "tripping $lure"
  base="$(probe baseline "$CANARY_ID")"
  probe poll "$service" "$CANARY_ID" "$base" 40 $marker > "$OUT/$lure.poll.json" &
  local poll_pid=$!
  sleep 0.7                                   # let the watcher start first
  attacker trip "$lure" "$TARGET" > "$OUT/$lure.trip.json" || true
  wait "$poll_pid" || true
  jq -c '{lure, error}' "$OUT/$lure.trip.json" >&2 || true
}
# portscan before smb: the scan detector must not have an SMB connection in its
# 30 s window (see the extra check below, and the record).
for pair in ftp:ftp ssh:ssh ssh-modern:ssh telnet:telnet http:http mysql:mysql mssql:mssql redis:redis \
            rdp:rdp sip:sip tftp:tftp snmp:snmp portscan:portscan smb:smb; do
  trip "${pair%%:*}" "${pair##*:}" "$([ "${pair%%:*}" = snmp ] && echo live-check-snmp || true)"
  sleep 4
done

# Extra: does an ordinary SMB visit count towards a port scan? Wait out the
# detector's per-source quiet minute, visit the share once, then touch four
# closed ports (not five): a scan alert here means the share's port 445 was
# counted as one of the five.
log "extra: one SMB visit then four closed ports, after the portscan quiet minute"
sleep 65
base="$(probe baseline "$CANARY_ID")"
probe poll portscan "$CANARY_ID" "$base" 45 > "$OUT/portscan-after-smb.poll.json" &
poll_pid=$!
sleep 0.7
attacker trip smb "$TARGET" > "$OUT/portscan-after-smb.smb.json" || true
docker exec "$ATTACKER" python3 -I -c '
import socket
for p in range(20010, 20014):
    s = socket.socket(); s.settimeout(1); s.connect_ex(("'"$TARGET"'", p)); s.close()'
wait "$poll_pid" || true

# ---- 7. the poisoner: wait for the watcher -------------------------------
log "waiting for the poisoner watcher (the canary's own schedule)"
wait "$POIS_PID" || true
docker logs "$FIXTURE" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -i 'poison\|llmnr\|nbt\|mdns\|hash\|ntlm' | head -20 > "$OUT/fixture-log.txt" || true
{
  echo "canary_started=$CANARY_STARTED"
  echo "fixture_address_matches_alert_source=$(docker inspect --format '{{(index .NetworkSettings.Networks "'"$E2E_NET"'").IPAddress}}' "$FIXTURE" \
    | jq -Rr --slurpfile p "$OUT/poisoner.poll.json" '. as $ip | [$p[0].alerts[].source_ip] | map(. == $ip) | any')"
} > "$OUT/poisoner.meta.txt"

probe dump "$CANARY_ID" > "$OUT/alerts-all.json"

# ---- 8. health and self-test after, then the screenshots ------------------
sleep 5
probe canary "$CANARY_ID" > "$OUT/health-after.json"
docker cp "$PROBE:/tmp/health.jsonl" "$OUT/health-samples.jsonl" >/dev/null
docker exec "$PROBE" pkill -f 'attack.py health' >/dev/null 2>&1 || true
probe canary "$E2E_CANARY_ID" > "$OUT/health-harness-canary.json" || true

mkdir -p "$OUT/shots"
chmod 777 "$OUT/shots"
log "screenshots"
docker run --rm --name "$SHOTS" --network "$E2E_NET" --user root \
  -v "$E2E_PREFIX-work:/work:ro" -v "$ATTACK_DIR:/shot:ro" \
  -v "$PW_MODULES/playwright:/pw/node_modules/playwright:ro" \
  -v "$PW_MODULES/playwright-core:/pw/node_modules/playwright-core:ro" \
  -e NODE_PATH=/pw/node_modules -v "$OUT/shots:/out" "$PW_IMAGE" \
  node /shot/shot.js "$BIRDCAGE_URL" "$CANARY_ID" /out > "$OUT/shots.log" 2>&1 || log "screenshots failed: $(tail -3 "$OUT/shots.log")"

# ---- 9. logs worth keeping, then the report -------------------------------
docker logs "$SMB_LURE_CANARY" 2>&1 | tail -60 > "$OUT/agent.log" || true
docker logs "$E2E_BIRDCAGE" 2>&1 | sed -E 's/with (setup|unlock) code [A-Za-z0-9-]+/with \1 code <redacted>/g' | tail -80 > "$OUT/birdcage.log" || true
python3 -I "$ATTACK_DIR/report.py" "$OUT"
log "raw results are in $OUT"
