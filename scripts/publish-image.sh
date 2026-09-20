#!/usr/bin/env bash
# Pushes an already-built local image to the registry and proves that what
# the registry now holds is byte-for-byte the image the test jobs exercised
# (issue #90). This is the "push, then verify the round trip" step: it never
# builds anything, and it never trusts docker's push output on its own,
# because a registry-side substitution -- a stale cache, a mirror serving a
# different manifest, a race with another push to the same tag -- would be
# invisible to a script that only checked "did the push command exit zero".
#
# So after pushing, this script asks the daemon what digest the registry
# gave the pushed reference, pulls that exact digest back down, and compares
# its image config ID with the config ID the test jobs actually ran
# (<tested-image-id>, e.g. from `docker image inspect --format '{{.Id}}'`
# right after building and testing it). Any mismatch anywhere in that chain
# is refused, never waved through.
#
# The reference passed in must carry a tag and must NOT already carry a
# digest: handing this script a "repo@sha256:..." reference would mean
# asking it to push an identity that already exists, which is not what a
# publish step does -- a tag names something; a digest is that something.
# Digest identities are consumed by scripts/attest-tested-image.sh and
# scripts/verify-validation-evidence.sh, not minted here a second time.
#
# Usage:
#   scripts/publish-image.sh <image-reference-with-tag> <tested-image-id>
#
#   <image-reference-with-tag>  e.g. ghcr.io/tomlawesome/birdcage:sha-<40hex>
#   <tested-image-id>           the local image config ID the test jobs
#                                exercised, "sha256:<64 hex>" (what
#                                `docker image inspect --format '{{.Id}}'`
#                                printed for the image under test).
#
# Exit codes:
#   0  the pushed digest's config ID matches <tested-image-id>; the bare
#      digest is printed on stdout and nothing else -- all commentary goes
#      to stderr, so a caller can capture the digest with $(...).
#   1  usage or validation error (bad or missing arguments).
#   2  the round trip did not match: the push failed, the pushed digest
#      could not be resolved, was malformed, or belonged to another
#      repository, the pull-back failed, or the pulled-back config ID
#      differs from <tested-image-id>. This is the substitution this
#      script exists to catch.
#
# Every call that touches the daemon or the registry -- run_docker_push,
# resolve_pushed_digest, pull_digest, image_config_id -- is its own small
# function, so scripts/publish-image.test.sh can replace all four and drive
# argument validation and the round-trip comparison for real, without a
# daemon or a registry.
set -euo pipefail

fail() { printf 'publish-image: %s\n' "$1" >&2; exit 1; }
refuse() { printf 'publish-image: %s\n' "$1" >&2; exit 2; }

# validate_reference <image-reference> -- refuses anything that is not a
# plain "<repo>:<tag>" registry reference. A reference already pinned to a
# digest (@sha256:...) is refused: this script assigns a digest identity to
# a tag, it does not consume one that already exists.
validate_reference() {
  local image_reference="$1"
  [ -n "$image_reference" ] || fail 'an image reference is required as the first argument'
  [[ "$image_reference" != *@sha256:* ]] ||
    fail "image reference must not already carry a digest (this script assigns an identity to a tag, it does not consume one): ${image_reference}"
  [[ "$image_reference" =~ ^[A-Za-z0-9._-]+(:[0-9]+)?(/[A-Za-z0-9._-]+)+:[A-Za-z0-9._-]+$ ]] ||
    fail "image reference is not a plain registry reference carrying a tag (<repo>:<tag>): ${image_reference}"
}

# validate_tested_image_id <tested-image-id> -- the ID must already be an
# immutable image config ID, not something a later step could still change
# underneath us.
validate_tested_image_id() {
  local tested_image_id="$1"
  [ -n "$tested_image_id" ] || fail 'a tested image ID is required as the second argument'
  [[ "$tested_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    fail "tested image ID is not an immutable image config ID (sha256:<64 hex>): ${tested_image_id}"
}

# run_docker_push <image-reference> -- the one call that actually publishes
# anything. Its progress chatter goes to stderr so this script's own stdout
# stays reserved for the final digest.
run_docker_push() {
  local image_reference="$1"
  docker push "$image_reference" >&2
}

# resolve_pushed_digest <image-reference> -- asks the daemon what digest it
# now associates with the just-pushed reference, rather than scraping
# `docker push`'s human-readable progress output. Prints the raw
# "<repo>@sha256:..." RepoDigests entry on stdout; the caller validates its
# shape and that the repo matches the one being published.
resolve_pushed_digest() {
  local image_reference="$1"
  docker image inspect --format '{{index .RepoDigests 0}}' "$image_reference"
}

# pull_digest <repo@digest> -- pulls the given digest back down so its
# locally cached config ID can be compared with the one that was tested.
# Progress chatter goes to stderr, same reasoning as run_docker_push.
pull_digest() {
  local digest_reference="$1"
  docker pull "$digest_reference" >&2
}

# image_config_id <reference> -- the immutable config ID docker assigned the
# named image: the same value `docker image inspect --format '{{.Id}}'`
# gives the test job right after it builds and tests the image.
image_config_id() {
  local reference="$1"
  docker image inspect --format '{{.Id}}' "$reference"
}

main() {
  [ $# -ge 1 ] || fail 'usage: publish-image.sh <image-reference-with-tag> <tested-image-id>'
  [ $# -le 2 ] || fail "too many arguments (expected exactly 2): $*"
  local image_reference="$1" tested_image_id="${2:-}"
  validate_reference "$image_reference"
  validate_tested_image_id "$tested_image_id"

  local repo="${image_reference%:*}"

  run_docker_push "$image_reference" ||
    refuse "docker push failed for ${image_reference}; nothing was published"

  local pushed_repo_digest
  pushed_repo_digest="$(resolve_pushed_digest "$image_reference")" || pushed_repo_digest=""
  [ -n "$pushed_repo_digest" ] ||
    refuse "could not resolve a pushed digest for ${image_reference}; the daemon reported no RepoDigests entry after the push"

  [[ "$pushed_repo_digest" =~ ^([A-Za-z0-9._-]+(:[0-9]+)?(/[A-Za-z0-9._-]+)+)@(sha256:[0-9a-f]{64})$ ]] ||
    refuse "the pushed digest is malformed: ${pushed_repo_digest}"
  local pushed_repo="${BASH_REMATCH[1]}" pushed_digest="${BASH_REMATCH[4]}"

  [ "$pushed_repo" = "$repo" ] ||
    refuse "the resolved digest belongs to ${pushed_repo}, not the repository being published (${repo}): ${pushed_repo_digest}"

  local digest_reference="${repo}@${pushed_digest}"
  pull_digest "$digest_reference" ||
    refuse "could not pull ${digest_reference} back down to verify it"

  local pulled_config_id
  pulled_config_id="$(image_config_id "$digest_reference")" ||
    refuse "could not inspect ${digest_reference} after pulling it back"

  [[ "$pulled_config_id" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    refuse "the pulled-back image's config ID is malformed: ${pulled_config_id}"

  [ "$pulled_config_id" = "$tested_image_id" ] ||
    refuse "the registry now holds a different image than was tested: ${digest_reference} has config ID ${pulled_config_id}, but the tested image ID was ${tested_image_id}"

  printf '%s\n' "$pushed_digest"
}

# Guard so scripts/publish-image.test.sh can source this file -- to reuse
# validate_reference/validate_tested_image_id/main directly, and to override
# run_docker_push/resolve_pushed_digest/pull_digest/image_config_id -- without
# main running on import.
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  main "$@"
fi
