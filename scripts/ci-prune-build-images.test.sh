#!/usr/bin/env bash
# Tests for ci-prune-build-images.sh (#145). There is no daemon here, so a
# `docker` stub goes on PATH ahead of the real binary, exactly as
# ci-ensure-image.test.sh fakes it: the script under test runs as a real
# subprocess, over its real argv and exit codes -- not sourced.
#
# The script under test is #!/bin/sh and runs under busybox sh in CI
# (docker:29-cli). This harness itself uses bash for convenience -- arrays
# of scenarios, [[ ]], etc -- and that is fine: nothing here requires the
# harness's own shell to be busybox, only the script under test's shell,
# which its shebang already pins. The one busybox-specific piece is
# `date -D`, which GNU date (this host's default) rejects outright, so a
# `date` shim backed by this host's own `busybox` binary goes on PATH ahead
# of GNU date too -- the same busybox date the docker:29-cli image ships,
# not an approximation of it.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/ci-prune-build-images.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

ok() { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; shift; [ $# -gt 0 ] && printf '%s\n' "$*" | sed 's/^/       /'; fail=$((fail + 1)); }

mkdir -p "$work/bin"

# date shim: busybox's own date, not GNU's -- ci-prune-build-images.sh calls
# `date -D ...`, an option GNU date does not have.
cat > "$work/bin/date" <<'SHIM'
#!/usr/bin/env bash
exec busybox date "$@"
SHIM
chmod +x "$work/bin/date"

# docker shim: PRESENT_FILE holds one "tag<TAB>created" line per image the
# fake daemon currently has. `image ls --format '{{.Repository}}:{{.Tag}}'
# <ref>` lists every present tag whose repository is exactly <ref>; `image
# inspect --format '{{.Created}}' <tag>` answers from the same file, or
# fails outright for a tag named in INSPECT_FAIL (case d); `image rm
# --force <tag>` deletes the line and records the removal.
cat > "$work/bin/docker" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$CALL_LOG"
[ "$1" = "image" ] || exit 1
case "$2" in
  ls)
    # $3=--format $4=fmt $5=ref
    ref="$5"
    while IFS=$'\t' read -r tag _created; do
      [ -n "$tag" ] || continue
      case "$tag" in
        "$ref":*) printf '%s\n' "$tag" ;;
      esac
    done < "$PRESENT_FILE"
    exit 0 ;;
  inspect)
    # $3=--format $4=fmt $5=tag
    tag="$5"
    if [ -f "${INSPECT_FAIL:-/dev/null}" ] && grep -qxF "$tag" "${INSPECT_FAIL:-/dev/null}"; then
      exit 1
    fi
    created="$(awk -F'\t' -v t="$tag" '$1 == t { print $2; found=1 } END { exit !found }' "$PRESENT_FILE")" || exit 1
    printf '%s\n' "$created"
    exit 0 ;;
  rm)
    # $3=--force $4=tag
    tag="$4"
    awk -F'\t' -v t="$tag" '$1 != t' "$PRESENT_FILE" > "$PRESENT_FILE.tmp"
    mv "$PRESENT_FILE.tmp" "$PRESENT_FILE"
    printf '%s\n' "$tag" >> "$REMOVED_LOG"
    exit 0 ;;
  *) exit 1 ;;
esac
SHIM
chmod +x "$work/bin/docker"

registry="fake.example/ai/birdcage"

# add_image <tag> <age-seconds> -- records a present image whose Created
# timestamp is <age-seconds> before "now", in the RFC3339Nano form Docker
# actually reports (fractional seconds included, exactly what the script's
# `${created%%.*}` strips).
add_image() {
  local tag="$1" age="$2" created
  created="$(busybox date -u -d "@$(( $(busybox date -u +%s) - age ))" '+%Y-%m-%dT%H:%M:%S.000000000Z')"
  printf '%s\t%s\n' "$tag" "$created" >> "$PRESENT_FILE"
}

reset_fixtures() {
  CALL_LOG="$work/calls.log"; REMOVED_LOG="$work/removed.log"; PRESENT_FILE="$work/present.txt"
  : > "$CALL_LOG"; : > "$REMOVED_LOG"; : > "$PRESENT_FILE"
  export CALL_LOG REMOVED_LOG PRESENT_FILE
  unset INSPECT_FAIL PRUNE_MAX_AGE_SECONDS 2>/dev/null || true
}

# run <extra-env...> -- invokes the real script as a subprocess with the
# stub docker/date ahead of the real ones on PATH.
run() {
  PATH="$work/bin:$PATH" CI_PIPELINE_ID="$CI_PIPELINE_ID" CI_REGISTRY_IMAGE="$registry" \
    PRUNE_MAX_AGE_SECONDS="${PRUNE_MAX_AGE_SECONDS:-21600}" "$script"
}

six_hours=21600
old_age=$((six_hours + 3600))    # 7h -- past the cutoff
young_age=$((six_hours - 3600))  # 5h -- under the cutoff

# --- a: the reproduction -------------------------------------------------
# An old image (pipeline 1) tagged both ways, current pipeline is 2. The
# pre-fix loop (#145's bug, copied verbatim from d62e315's .gitlab-ci.yml)
# only ever queries the bare repo name, so it removes the local tag and
# never touches the registry-named one -- that is the whole defect. The
# fixed script must remove both.
CI_PIPELINE_ID=2
reset_fixtures
add_image "birdcage-build:1" "$old_age"
add_image "$registry/birdcage-build:ci-1" "$old_age"

old_loop() {
cat <<'OLDLOOP' > "$work/old-loop.sh"
set -eu
max_age_seconds=$((6 * 3600))
now_epoch="$(date -u +%s)"
for repo in birdcage-build mockingbird-build nightjar-build smb-lure-build holder-build opencanary-build; do
  docker image ls --format '{{.Repository}}:{{.Tag}}' "$repo" \
    | grep -v ":${CI_PIPELINE_ID}$" \
    | while IFS= read -r tag; do
        created="$(docker image inspect --format '{{.Created}}' "$tag" 2>/dev/null)" || continue
        created_epoch="$(date -u -D '%Y-%m-%dT%H:%M:%S' -d "${created%%.*}" +%s 2>/dev/null)" || continue
        age=$((now_epoch - created_epoch))
        [ "$age" -gt "$max_age_seconds" ] || continue
        docker image rm --force "$tag" >/dev/null 2>&1 || true
      done || true
done
OLDLOOP
  PATH="$work/bin:$PATH" CI_PIPELINE_ID="$CI_PIPELINE_ID" sh "$work/old-loop.sh"
}
old_loop
removed_old="$(sort "$REMOVED_LOG")"
if [ "$removed_old" = "birdcage-build:1" ]; then
  ok "old loop reproduction: removes only the local tag, registry tag survives (the bug)"
else
  bad "old loop reproduction: removes only the local tag, registry tag survives (the bug)" "removed: $removed_old"
fi

reset_fixtures
add_image "birdcage-build:1" "$old_age"
add_image "$registry/birdcage-build:ci-1" "$old_age"
run
removed_new="$(sort "$REMOVED_LOG")"
if [ "$removed_new" = "$(printf '%s\n%s' "$registry/birdcage-build:ci-1" "birdcage-build:1" | sort)" ]; then
  ok "fixed script: removes both the local and registry-named tag"
else
  bad "fixed script: removes both the local and registry-named tag" "removed: $removed_new"
fi

# --- b: this pipeline's own tags, both forms, are always kept ------------
CI_PIPELINE_ID=2
reset_fixtures
add_image "birdcage-build:2" "$old_age"
add_image "$registry/birdcage-build:ci-2" "$old_age"
run
if [ ! -s "$REMOVED_LOG" ]; then
  ok "this pipeline's own tags are kept however old"
else
  bad "this pipeline's own tags are kept however old" "removed: $(cat "$REMOVED_LOG")"
fi

# --- c: a young image under an old pipeline id is kept -------------------
CI_PIPELINE_ID=2
reset_fixtures
add_image "birdcage-build:1" "$young_age"
add_image "$registry/birdcage-build:ci-1" "$young_age"
run
if [ ! -s "$REMOVED_LOG" ]; then
  ok "a young image under an old pipeline id is kept"
else
  bad "a young image under an old pipeline id is kept" "removed: $(cat "$REMOVED_LOG")"
fi

# --- d: an inspect failure on one tag does not stop the others -----------
CI_PIPELINE_ID=2
reset_fixtures
add_image "birdcage-build:1" "$old_age"
add_image "$registry/birdcage-build:ci-1" "$old_age"
printf '%s\n' "birdcage-build:1" > "$work/inspect-fail.txt"
INSPECT_FAIL="$work/inspect-fail.txt"
export INSPECT_FAIL
run
if [ "$(cat "$REMOVED_LOG")" = "$registry/birdcage-build:ci-1" ]; then
  ok "an inspect failure on one tag does not stop the others being pruned"
else
  bad "an inspect failure on one tag does not stop the others being pruned" "removed: $(cat "$REMOVED_LOG")"
fi
unset INSPECT_FAIL

# --- e: a repo with no images at all is fine ------------------------------
CI_PIPELINE_ID=2
reset_fixtures
run
if [ ! -s "$REMOVED_LOG" ]; then
  ok "no images anywhere is fine, nothing removed, no error"
else
  bad "no images anywhere is fine, nothing removed, no error" "removed: $(cat "$REMOVED_LOG")"
fi

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
