#!/usr/bin/env bash
# scanner-stack.sh -- the extra infrastructure scripts/e2e/scanner.sh
# (issue #108 slice 1, commit 5) needs and no other journey does: the
# Nightjar image, a fixture tree standing in for the operator's host
# filesystem, and Grype's vulnerability database fetched once into a
# named volume every leg that needs a real database shares.
#
# Why a fixture *volume*, not a bind mount of a directory built on this
# job's own filesystem: the docker:29-cli job container and the docker
# daemon it talks to are not guaranteed to share a filesystem
# (smb-stack.sh's write_smb_conf makes the same point about its own
# opencanary.conf override). So the "host" the printed run command's own
# `-v /:/host:ro` covers is a named volume here, populated the same
# indirect way -- piped through stdin into a throwaway container -- and
# scanner.sh substitutes that volume's name for `/` the same way
# stack.sh's run_printed_command substitutes its own state/log volumes.
#
# This file only builds the infrastructure. Enrolling a scanner canary,
# running the printed command and asserting on the result is
# scanner.sh's job -- three separate legs, each its own enrolment and
# its own edit to the printed command, so that logic belongs to the
# journey, not here (stack.sh's own header states the same split).
#
#   eval "$(scripts/e2e/stack.sh up)"
#   eval "$(scripts/e2e/scanner-stack.sh up)"
#   scripts/e2e/scanner.sh
#   scripts/e2e/scanner-stack.sh down
#   scripts/e2e/stack.sh down
set -eu

# Only E2E_PREFIX is required: this file builds the image, the fixture
# and the database volume, none of which touch the base stack's network
# or birdcage container, so it never needs stack.sh's own runtime
# exports (E2E_STACK/E2E_NET/E2E_BIRDCAGE). That matters for `down` in
# particular -- CI's after_script is a separate shell from script:, with
# none of those runtime exports still in scope, only job-level
# variables: (E2E_PREFIX among them) -- so down must be able to
# reconstruct every name it cleans up from E2E_PREFIX alone.
[ -n "${E2E_PREFIX:-}" ] || {
  echo "scanner-stack: E2E_PREFIX unset -- run: eval \"\$(scripts/e2e/stack.sh up)\" first" >&2
  exit 2
}

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# E2E_NIGHTJAR_IMAGE mirrors stack.sh's own E2E_BIRDCAGE_IMAGE /
# E2E_MOCKINGBIRD_IMAGE (#98): CI sets it to the tag build:images already
# built from this exact commit (NIGHTJAR_BUILD_IMAGE in its dotenv), so
# this journey tests those bytes rather than a second build of the same
# source. Unset on a workstation, build_image below builds from scratch.
NIGHTJAR_IMAGE="${E2E_NIGHTJAR_IMAGE:-$E2E_PREFIX-nightjar-image}"
FIXTURE_VOL="${E2E_PREFIX}-scanner-fixture"
DB_VOL="${E2E_PREFIX}-scanner-grype-db"
EMPTY_DB_VOL="${E2E_PREFIX}-scanner-empty-db"

log() { echo "scanner-stack: $*" >&2; }
die() { echo "scanner-stack: $*" >&2; exit 1; }

build_image() {
  # In CI, $NIGHTJAR_IMAGE is the shared build tag build:images built and
  # this job's own before-script already recovered once (#112). It is
  # also the first thing in this script's `up` to touch that tag, but
  # only after `stack.sh up` has already run, which is enough of a
  # window for a concurrent pipeline's prune to have deleted it again
  # since -- re-check rather than let the "no local image" branch below
  # wrongly refuse to build a replacement. A no-op outside CI, where
  # these variables are unset.
  if [ -n "${E2E_NIGHTJAR_IMAGE:-}" ] && [ -n "${NIGHTJAR_BUILD_IMAGE:-}" ] && [ -n "${NIGHTJAR_BUILD_DIGEST:-}" ]; then
    "$REPO_ROOT/scripts/ci-ensure-image.sh" "$NIGHTJAR_BUILD_IMAGE" "$NIGHTJAR_BUILD_DIGEST" >&2 \
      || die "could not ensure $NIGHTJAR_BUILD_IMAGE is present before using it"
  fi
  if docker image inspect "$NIGHTJAR_IMAGE" >/dev/null 2>&1; then
    log "using existing image $NIGHTJAR_IMAGE"
    return 0
  fi
  if [ -n "${E2E_NIGHTJAR_IMAGE:-}" ]; then
    die "E2E_NIGHTJAR_IMAGE=$NIGHTJAR_IMAGE names no local image -- it should have been built by build:images and handed to this job; refusing rather than building a different one"
  fi
  log "building $NIGHTJAR_IMAGE from build/nightjar/Dockerfile (this takes a few minutes the first time)"
  docker build --file "$REPO_ROOT/build/nightjar/Dockerfile" --tag "$NIGHTJAR_IMAGE" "$REPO_ROOT" >/dev/null \
    || die "building $NIGHTJAR_IMAGE failed"
}

# write_fixture_file pipes stdin into path under FIXTURE_VOL's own
# "/host" -- the same indirection write_smb_conf uses and for the same
# reason. Creating the parent directory here is also how every
# directory-shaped hostmask.Masks entry (etc/ssh, root, proc, run, sys,
# dev, tmp, var/tmp, home) comes to exist in the fixture at all: each
# gets a throwaway ".keep" file so mkdir -p runs for it, matching what
# the real host has (the printed run command's own tmpfs/dev-null flags
# need a mount *point* to exist under the read-only root bind, or the
# container refuses to start -- docs/enrolment.md's own trap).
write_fixture_file() { # write_fixture_file <path-under-/host> [mode]
  local path="$1" mode="${2:-644}"
  # ${ALPINE_IMAGE:-alpine:3.24}: CI's dependency-proxy pin (refs #128,
  # .gitlab-ci.yml) when set, the plain Docker Hub tag on a workstation.
  docker run --rm --interactive --volume "$FIXTURE_VOL:/host" "${ALPINE_IMAGE:-alpine:3.24}" sh -c "
set -eu
mkdir -p \"\$(dirname \"/host$path\")\"
cat > \"/host$path\"
chmod $mode \"/host$path\"
" || die "writing /host$path into the fixture failed"
}

# build_fixture stands in for the operator's real host filesystem. It
# holds every path internal/hostmask.Masks names, plus a manifest Grype
# reliably matches in two places: /opt/app, which the mask list leaves
# visible, and /home/user/app, which --tmpfs /host/home:ro covers --
# so leg 1 can prove the second copy is blind rather than merely
# present, the shape issue #108's own "second opinion on the host
# mount" comment describes ("run the printed command verbatim over a
# fixture holding the same known-vulnerable package both inside the
# fixture's /home and outside it").
#
# lodash 4.17.15 in a package-lock.json (the npm ecosystem, so no
# distro identification is needed the way an apk/dpkg database would)
# was checked against a real, freshly-fetched Grype database before
# this file was written: 6 matches, stable across two independent cold
# runs (CVE-2020-28500, CVE-2020-8203, CVE-2021-23337 among them -- see
# the commit message for the full measurement). The exact CVE set can
# drift as the database updates, so scanner.sh compares against a
# reference count taken fresh at journey time rather than hard-coding
# one.
build_fixture() {
  docker volume create "$FIXTURE_VOL" >/dev/null || die "creating volume $FIXTURE_VOL failed"

  local pkg
  pkg='{
  "name": "fixture-app",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "requires": true,
  "packages": {
    "": { "name": "fixture-app", "version": "1.0.0", "dependencies": { "lodash": "4.17.15" } },
    "node_modules/lodash": { "version": "4.17.15" }
  },
  "dependencies": { "lodash": { "version": "4.17.15" } }
}'
  printf '%s\n' "$pkg" | write_fixture_file /opt/app/package-lock.json
  printf '%s\n' "$pkg" | write_fixture_file /home/user/app/package-lock.json
  # Never masked (internal/hostmask's own doc comment): Grype needs this
  # to identify the distribution. Nothing in this fixture depends on it
  # -- the npm ecosystem match needs no distro at all -- but a fixture
  # missing it would be a fixture no real host ever is.
  printf 'ID=alpine\nVERSION_ID=3.20\n' | write_fixture_file /etc/os-release

  printf '' | write_fixture_file /etc/shadow
  printf '' | write_fixture_file /etc/gshadow
  local dir
  for dir in /etc/ssh /root /proc /run /sys /dev /tmp /var/tmp /home; do
    printf '' | write_fixture_file "$dir/.keep"
  done
}

# prefetch_db runs Grype directly, once, against the fixture -- so every
# leg that needs a real database (scanner.sh's legs 1 and 2) shares an
# already-warm one and this job pays the fetch once rather than twice.
# Measured locally before this file was written: about two minutes
# cold, about two seconds warm, stable across two independent runs --
# see the commit message. If that ever grows past about three minutes
# or turns flaky, this is the line to look at first.
prefetch_db() {
  # Second use of the nightjar build tag in this job -- build_image
  # above already used it once, and build_fixture's own run in between
  # is more window for a concurrent pipeline's prune (#112) to have
  # deleted it again. A no-op outside CI, where these variables are
  # unset.
  if [ -n "${E2E_NIGHTJAR_IMAGE:-}" ] && [ -n "${NIGHTJAR_BUILD_IMAGE:-}" ] && [ -n "${NIGHTJAR_BUILD_DIGEST:-}" ]; then
    "$REPO_ROOT/scripts/ci-ensure-image.sh" "$NIGHTJAR_BUILD_IMAGE" "$NIGHTJAR_BUILD_DIGEST" >&2 \
      || die "could not ensure $NIGHTJAR_BUILD_IMAGE is present before prefetching the database"
  fi
  docker volume create "$DB_VOL" >/dev/null || die "creating volume $DB_VOL failed"
  log "fetching Grype's vulnerability database into $DB_VOL (a couple of minutes the first time)"
  docker run --rm \
    --volume "$FIXTURE_VOL:/host:ro" \
    --volume "$DB_VOL:/var/lib/nightjar-grype-db" \
    --entrypoint /usr/local/bin/grype \
    "$NIGHTJAR_IMAGE" dir:/host/opt/app -o json >/dev/null \
    || die "prefetching the Grype database failed"
}

up() {
  command -v docker >/dev/null 2>&1 || die "docker is not on PATH"
  down >/dev/null 2>&1 || true
  build_image
  build_fixture
  prefetch_db
  docker volume create "$EMPTY_DB_VOL" >/dev/null || die "creating volume $EMPTY_DB_VOL failed"

  cat <<EOF
export SCANNER_NIGHTJAR_IMAGE=$NIGHTJAR_IMAGE
export SCANNER_FIXTURE_VOL=$FIXTURE_VOL
export SCANNER_DB_VOL=$DB_VOL
export SCANNER_EMPTY_DB_VOL=$EMPTY_DB_VOL
EOF
}

down() {
  local n
  for n in 1 2 3; do
    docker rm --force "${E2E_PREFIX}-scanner-leg$n" >/dev/null 2>&1 || true
    docker volume rm --force "${E2E_PREFIX}-scanner-state-leg$n" >/dev/null 2>&1 || true
  done
  docker volume rm --force "$EMPTY_DB_VOL" "$FIXTURE_VOL" "$DB_VOL" >/dev/null 2>&1 || true
  case "$NIGHTJAR_IMAGE" in
    "$E2E_PREFIX"*) docker image rm --force "$NIGHTJAR_IMAGE" >/dev/null 2>&1 || true ;;
  esac
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *)
    echo "usage: $0 {up|down}" >&2
    exit 2 ;;
esac
