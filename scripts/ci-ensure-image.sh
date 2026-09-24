#!/usr/bin/env bash
# ci-ensure-image.sh -- make sure the local image tag build:images built for
# this pipeline is actually still there before a consumer job uses it.
#
# Issue #112: this host runs pipelines concurrently on one shared Docker
# daemon. build:images' own prune (self-healing on its own -- see that
# job's header) deletes every build tag except its own pipeline's, which
# also means it deletes a tag a DIFFERENT, still-running pipeline is
# using. Two pipelines can each prune the other's image within minutes of
# each other, and whichever job loses the race fails for a reason that has
# nothing to do with the code under test.
#
# The fix has two parts. build:images' prune only removes a tag old
# enough that no pipeline still running could have built it (see that
# job's own comment in .gitlab-ci.yml), so it can no longer delete a tag
# a live pipeline is mid-use of. Belt and braces: build:images also pushes
# each image to this project's own container registry and records its
# repo@digest in release.env. This script is what every consumer calls
# before EACH use of a shared build tag -- not just once per job -- so a
# pruned local tag (a late prune from before the age guard existed, or a
# window the age guard's margin does not cover) costs one recovery pull
# instead of a failed job. test:image:*, every e2e:* journey that
# consumes build:images' output, release:push, and any script within
# those jobs that uses the same tag a second time (e.g.
# scripts/e2e/smb-stack.sh's run_smb_canary) all call it.
#
# Usage:
#   scripts/ci-ensure-image.sh <local-tag> <repo@digest>
#
#   <local-tag>   the tag build:images gave this image for this pipeline,
#                 e.g. birdcage-build:1437 ($BIRDCAGE_BUILD_IMAGE).
#   <repo@digest> where build:images pushed it, e.g.
#                 registry.example/ai/birdcage/birdcage-build@sha256:...
#                 ($BIRDCAGE_BUILD_DIGEST). The argument must be given even
#                 when empty -- see exit 1 below.
#
# Idempotent: if <local-tag> is already there, this does nothing but say
# so -- no login, no pull. It never builds anything itself: an image this
# script had to construct from source would not be the bytes build:images
# tested.
#
# Exit codes:
#   0  <local-tag> already existed, or was recovered from the registry.
#   1  usage error, or <local-tag> is missing and there is nothing to
#      recover it with: no digest was recorded (build:images never ran
#      for this pipeline, or its dotenv never reached this job), the
#      login failed, or the registry pull itself failed -- unreachable
#      registry, or the recorded digest already swept by the registry's
#      own cleanup policy. All three are loud, never silent; the pull
#      failure is the one where a retry is the right response.
#
# image_exists/registry_login/pull_image/tag_image are their own
# functions not because anything sources this file the way
# scripts/publish-image.test.sh sources publish-image.sh, but so
# scripts/ci-ensure-image.test.sh can fake `docker` itself: a stub goes on
# PATH ahead of the real binary, and this script runs exactly as a CI job
# runs it -- as a subprocess, over its real argv and exit codes.
set -euo pipefail

log() { printf 'ci-ensure-image: %s\n' "$1"; }
fail() { printf 'ci-ensure-image: %s\n' "$1" >&2; exit 1; }

image_exists() {
  docker image inspect "$1" >/dev/null 2>&1
}

# registry_login <repo@digest> -- only called on the miss path below, so
# the common case (the local tag is still there) costs no credential
# exchange at all. Job-token creds, the same ones build:images pushes
# with -- never a personal token -- and the password never touches argv
# or a log line.
registry_login() {
  local digest_ref="$1"
  local registry="${digest_ref%%/*}"
  [ -n "${CI_REGISTRY_USER:-}" ] ||
    fail "$digest_ref is recorded but CI_REGISTRY_USER is not set -- cannot log in to pull it"
  [ -n "${CI_REGISTRY_PASSWORD:-}" ] ||
    fail "$digest_ref is recorded but CI_REGISTRY_PASSWORD is not set -- cannot log in to pull it"
  echo "$CI_REGISTRY_PASSWORD" | docker login "$registry" --username "$CI_REGISTRY_USER" --password-stdin >/dev/null
}

pull_image() {
  docker pull "$1" >/dev/null
}

tag_image() {
  docker tag "$1" "$2" >/dev/null
}

main() {
  [ $# -eq 2 ] || fail "usage: ci-ensure-image.sh <local-tag> <repo@digest>"
  local local_tag="$1" digest_ref="$2"
  [ -n "$local_tag" ] || fail "usage: ci-ensure-image.sh <local-tag> <repo@digest> -- local-tag must not be empty"

  if image_exists "$local_tag"; then
    log "$local_tag already present locally, nothing to do"
    return 0
  fi

  [ -n "$digest_ref" ] ||
    fail "$local_tag is missing locally and no digest was recorded for it -- build:images did not run for this pipeline, or its dotenv never reached this job"

  registry_login "$digest_ref" ||
    fail "could not log in to ${digest_ref%%/*} to pull $digest_ref"

  pull_image "$digest_ref" ||
    fail "$local_tag is missing locally and pulling $digest_ref failed -- the registry may be unreachable, or the recorded digest has already been swept by its cleanup policy; retrying this job usually recovers"

  tag_image "$digest_ref" "$local_tag" ||
    fail "pulled $digest_ref but could not tag it as $local_tag"

  log "pulled after local tag missing: $local_tag recovered from $digest_ref"
}

# Guard so scripts/ci-ensure-image.test.sh could source this file if it
# ever needed to; the suite in fact runs it as a real subprocess against a
# faked `docker` on PATH, but the guard costs nothing and matches every
# other script in this directory.
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  main "$@"
fi
