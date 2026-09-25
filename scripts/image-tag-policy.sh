#!/usr/bin/env bash
# The one allow-list of image tag names the release path may create, move
# or mirror (issue #90; owner decision, 2026-09-25). Every script that puts
# a name on a digest sources this file and calls image_tag_check before it
# touches a registry; anything not listed here is refused.
#
# Allowed, and nothing else:
#   vX.Y.Z             version tag, digits only; never moves
#   preview, latest    channel names; move
#   sha-<40 hex>       per-commit anchor, lowercase hex
#   ci-<...>           build:images transport tags; only on the GitLab
#                      registry (registry.gitlab.tomlawson.io), never GHCR
#   sha256-<64 hex>.att
#                      cosign's attestation object, named by cosign, not
#                      us; only when the caller passes --cosign-attestation
#                      (scripts/mirror-image.sh, which copies it to GHCR)
#
# Usage, sourced:
#   image_tag_check <repository> <tag> [--cosign-attestation]
#     returns 0 if allowed; otherwise prints the reason to stderr and
#     returns 1. Never exits, so the caller keeps its own exit codes.
# Usage, run directly: the same arguments; exit 0 allowed, 1 refused.

IMAGE_TAG_POLICY_GITLAB_REGISTRY="registry.gitlab.tomlawson.io"

image_tag_check() {
  local repo="${1:-}" tag="${2:-}" allow_att="${3:-}"
  local host="${repo%%/*}"
  local why="allowed: vX.Y.Z, preview, latest, sha-<40 lowercase hex>, ci-* on ${IMAGE_TAG_POLICY_GITLAB_REGISTRY} only"

  case "$allow_att" in
    ''|--cosign-attestation) ;;
    *) printf 'image-tag-policy: unknown option: %s\n' "$allow_att" >&2; return 1 ;;
  esac
  if [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
     [[ "$tag" =~ ^(preview|latest)$ ]] ||
     [[ "$tag" =~ ^sha-[0-9a-f]{40}$ ]]; then
    return 0
  fi
  if [[ "$tag" =~ ^ci-[A-Za-z0-9._-]{1,125}$ ]]; then
    [ "$host" = "$IMAGE_TAG_POLICY_GITLAB_REGISTRY" ] && return 0
    printf 'image-tag-policy: refused tag %s on %s: ci- transport tags live on %s only\n' \
      "'$tag'" "$repo" "$IMAGE_TAG_POLICY_GITLAB_REGISTRY" >&2
    return 1
  fi
  if [ "$allow_att" = "--cosign-attestation" ] && [[ "$tag" =~ ^sha256-[0-9a-f]{64}\.att$ ]]; then
    return 0
  fi
  printf 'image-tag-policy: refused tag %s on %s: not in the allow-list (%s)\n' \
    "'$tag'" "$repo" "$why" >&2
  return 1
}

if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  set -euo pipefail
  if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    echo 'usage: image-tag-policy.sh <repository> <tag> [--cosign-attestation]' >&2
    exit 1
  fi
  image_tag_check "$@"
fi
