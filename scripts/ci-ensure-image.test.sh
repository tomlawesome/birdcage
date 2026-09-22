#!/usr/bin/env bash
# Tests for ci-ensure-image.sh (#112). There is no daemon and no registry
# here, and this script is called from CI jobs as a subprocess rather than
# sourced, so the fake has to work at that boundary too: a `docker` stub
# goes on PATH ahead of the real binary, and every scenario below drives
# the real script exactly as a CI job would -- real argv, real exit code.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/ci-ensure-image.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

ok() { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; shift; [ $# -gt 0 ] && printf '%s\n' "$*" | sed 's/^/       /'; fail=$((fail + 1)); }

# The stub: PRESENT_FILE lists every reference `docker image inspect`
# should currently find (one per line); CALL_LOG records every invocation
# so a scenario can assert what did, or did not, happen. *_SHOULD_FAIL
# flags let a scenario make login/pull/tag fail without a real daemon.
mkdir -p "$work/bin"
cat > "$work/bin/docker" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$CALL_LOG"
case "$1" in
  login)
    [ "${LOGIN_SHOULD_FAIL:-0}" = 1 ] && exit 1
    exit 0 ;;
  image)
    # image inspect <ref>
    grep -qxF "$3" "$PRESENT_FILE" 2>/dev/null && exit 0 || exit 1 ;;
  pull)
    [ "${PULL_SHOULD_FAIL:-0}" = 1 ] && exit 1
    exit 0 ;;
  tag)
    [ "${TAG_SHOULD_FAIL:-0}" = 1 ] && exit 1
    printf '%s\n' "$3" >> "$PRESENT_FILE"
    exit 0 ;;
  *) exit 1 ;;
esac
SHIM
chmod +x "$work/bin/docker"

local_tag="birdcage-build:1437"
digest_ref="registry.example/ai/birdcage/birdcage-build@sha256:$(printf 'a%.0s' $(seq 64))"

# reset_fixtures -- back to a happy-path baseline before each scenario:
# creds present, nothing fails, nothing pre-seeded as already local.
reset_fixtures() {
  CALL_LOG="$work/calls.log"; PRESENT_FILE="$work/present.txt"
  : > "$CALL_LOG"; : > "$PRESENT_FILE"
  export CALL_LOG PRESENT_FILE
  export CI_REGISTRY_USER=ci-job-token
  export CI_REGISTRY_PASSWORD=fake-job-token
  unset LOGIN_SHOULD_FAIL PULL_SHOULD_FAIL TAG_SHOULD_FAIL 2>/dev/null || true
}

# run <args...> -- invokes the real script as a subprocess, stub `docker`
# ahead of the real one on PATH, stdout and stderr combined.
run() {
  local got=0 out
  out="$(PATH="$work/bin:$PATH" "$script" "$@" 2>&1)" || got=$?
  printf '%s\x1f%s' "$got" "$out"
}

split() { GOT="${1%%$'\x1f'*}"; OUT="${1#*$'\x1f'}"; }

# --- 1: local tag present -> no pull, no login, no retag; exit 0 ---------
reset_fixtures
printf '%s\n' "$local_tag" >> "$PRESENT_FILE"
split "$(run "$local_tag" "$digest_ref")"
calls="$(cat "$CALL_LOG")"
if [ "$GOT" = 0 ] && [[ "$OUT" == *"already present locally"* ]] \
   && [[ "$calls" != *"pull "* ]] && [[ "$calls" != *"login "* ]] && [[ "$calls" != *"tag "* ]]; then
  ok "a present local tag is used as-is, no pull and no login"
else
  bad "a present local tag is used as-is, no pull and no login" "exit $GOT: $OUT / calls: $calls"
fi

# --- 2: local tag missing, digest recorded -> pull + retag + the log line
reset_fixtures
split "$(run "$local_tag" "$digest_ref")"
if [ "$GOT" = 0 ] && [[ "$OUT" == *"pulled after local tag missing"* ]] \
   && grep -qxF "pull $digest_ref" "$CALL_LOG" \
   && grep -qxF "tag $digest_ref $local_tag" "$CALL_LOG"; then
  ok "a missing local tag with a recorded digest is pulled, retagged, and logged"
else
  bad "a missing local tag with a recorded digest is pulled, retagged, and logged" "exit $GOT: $OUT / calls: $(cat "$CALL_LOG")"
fi

# --- 2b: the login targets the digest's OWN registry host, not something
# left over from an outer scope. This is the case that would have stayed
# green with a `local a=$1 b=$a` bug (each name declared in its own `local`
# below, not folded into one statement, precisely so a bug like that trips
# here): $registry in registry_login is computed from ITS OWN argument, and
# the only way to see that from outside is to check what actually reached
# `docker login`.
reset_fixtures
split "$(run "$local_tag" "$digest_ref")"
if grep -qxF "login registry.example --username ci-job-token --password-stdin" "$CALL_LOG"; then
  ok "docker login is called with the digest's own registry host"
else
  bad "docker login is called with the digest's own registry host" "calls: $(cat "$CALL_LOG")"
fi

# --- 3: neither present nor a digest recorded -> hard failure, no pull ---
reset_fixtures
split "$(run "$local_tag" "")"
if [ "$GOT" != 0 ] && [[ "$OUT" == *"no digest was recorded"* ]] \
   && [[ "$(cat "$CALL_LOG")" != *"pull "* ]]; then
  ok "no local tag and no digest is a loud failure, never a silent pull attempt"
else
  bad "no local tag and no digest is a loud failure, never a silent pull attempt" "exit $GOT: $OUT"
fi

# --- 4: the registry pull itself fails -> hard failure naming a retry ----
reset_fixtures
export PULL_SHOULD_FAIL=1
split "$(run "$local_tag" "$digest_ref")"
if [ "$GOT" != 0 ] && [[ "$OUT" == *"pulling $digest_ref failed"* ]]; then
  ok "a failing registry pull is a loud failure naming the digest"
else
  bad "a failing registry pull is a loud failure naming the digest" "exit $GOT: $OUT"
fi

# --- 5: the retag after a successful pull fails -> hard failure ----------
reset_fixtures
export TAG_SHOULD_FAIL=1
split "$(run "$local_tag" "$digest_ref")"
if [ "$GOT" != 0 ] && [[ "$OUT" == *"could not tag it as $local_tag"* ]]; then
  ok "a failing retag after a successful pull is a loud failure"
else
  bad "a failing retag after a successful pull is a loud failure" "exit $GOT: $OUT"
fi

# --- 6: missing registry credentials on the miss path -> hard failure ----
reset_fixtures
unset CI_REGISTRY_PASSWORD
split "$(run "$local_tag" "$digest_ref")"
if [ "$GOT" != 0 ] && [[ "$OUT" == *"CI_REGISTRY_PASSWORD is not set"* ]] \
   && [[ "$(cat "$CALL_LOG")" != *"pull "* ]]; then
  ok "missing registry credentials on the miss path is a loud failure, never a silent pull"
else
  bad "missing registry credentials on the miss path is a loud failure, never a silent pull" "exit $GOT: $OUT"
fi

# --- 7: usage errors -------------------------------------------------------
reset_fixtures
split "$(run "$local_tag")"
[ "$GOT" != 0 ] && ok "a missing digest argument is a usage error" \
  || bad "a missing digest argument is a usage error" "exit $GOT: $OUT"

split "$(run)"
[ "$GOT" != 0 ] && ok "no arguments is a usage error" \
  || bad "no arguments is a usage error" "exit $GOT: $OUT"

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
