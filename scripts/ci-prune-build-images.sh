#!/bin/sh
# ci-prune-build-images.sh -- prune old build:images tags for this project
# from the shared runner-host Docker daemon (#145).
#
# build:images tags each image twice: a local "<name>-build:<pipeline id>"
# for later jobs in the same pipeline, and a registry-named
# "${CI_REGISTRY_IMAGE}/<name>-build:ci-<pipeline id>", pushed as transport
# between jobs (#112). Both tags point at the same image. The prune used to
# list only the local repo name, so it removed the local tag after 6 hours
# and left the registry-named tag on the very same image -- which kept the
# image alive forever, since nothing else ever untags it. On the runner
# host on 2026-09-27: 9 local mockingbird-build tags against 70
# registry.tomlawson.io/ai/birdcage/mockingbird-build tags, and 268 of the
# host's 305 images in all were this project's build images. The fix is to
# prune both repo names for each build, with the keep-guard extended to
# both tag forms so this pipeline's own images are never touched.
#
# Runs under busybox sh -- the job image is docker:29-cli (Alpine/busybox,
# no GNU date) -- so busybox `date -D` is used for parsing, exactly as
# before this was split out (see docs/ci-hops.md and #112's write-up for
# why the RFC3339Nano fractional seconds are stripped first).
#
# A prune failure must never fail the build: every removal is `|| true`,
# and a missing or unparseable image is skipped rather than counted as
# young.
#
# Inputs (environment):
#   CI_PIPELINE_ID        this pipeline's id -- both of its own tag forms
#                          are always kept, however old.
#   CI_REGISTRY_IMAGE     this project's registry path, e.g.
#                          registry.tomlawson.io/ai/birdcage.
#   PRUNE_MAX_AGE_SECONDS override for the age cutoff, tests only.
#                          Defaults to 21600 (6 hours) -- see build:images'
#                          own comment for why that margin was chosen.
set -eu

max_age_seconds="${PRUNE_MAX_AGE_SECONDS:-21600}"
now_epoch="$(date -u +%s)"

for repo in birdcage-build mockingbird-build nightjar-build smb-lure-build holder-build opencanary-build; do
  for image in "$repo" "${CI_REGISTRY_IMAGE}/${repo}"; do
    docker image ls --format '{{.Repository}}:{{.Tag}}' "$image" \
      | grep -v ":${CI_PIPELINE_ID}$" \
      | grep -v ":ci-${CI_PIPELINE_ID}$" \
      | while IFS= read -r tag; do
          created="$(docker image inspect --format '{{.Created}}' "$tag" 2>/dev/null)" || continue
          created_epoch="$(date -u -D '%Y-%m-%dT%H:%M:%S' -d "${created%%.*}" +%s 2>/dev/null)" || continue
          age=$((now_epoch - created_epoch))
          [ "$age" -gt "$max_age_seconds" ] || continue
          docker image rm --force "$tag" >/dev/null 2>&1 || true
        done || true
  done
done
