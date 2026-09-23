#!/usr/bin/env bash
# Mirrors an already-published tag from the GitLab registry to GHCR, under
# the identical tag name (issue #90, note 22233: GitLab is where releases
# are published and promoted -- the digest validation evidence is bound to
# -- and GHCR is the public download point users are told to pull from).
#
# This script never judges anything and is never the first thing to touch a
# digest: by the time it runs, release:preview or release:promote has
# already verified the evidence and given the digest the tag being mirrored
# here. It only copies that already-named digest to the second registry and
# proves the copy landed byte-for-byte the same manifest -- it does not
# re-run scripts/verify-validation-evidence.sh, and must not, because doing
# so would make this the second job judging the same evidence rather than a
# copy of a decision already made.
#
# It never pulls image layers through a local daemon: `docker buildx
# imagetools create` copies a manifest -- and, across registries, the blobs
# it references -- registry-to-registry, so the identity that lands on GHCR
# is the exact digest already validated on GitLab. Nothing is rebuilt, and
# there is no local image ever tagged with a name a caller might later push
# by hand.
#
# Usage:
#   scripts/mirror-image.sh <source-repository> <tag> <dest-repository>
#
#   <source-repository>  no tag, no digest, e.g.
#                        registry.gitlab.tomlawson.io/ai/birdcage/birdcage --
#                        the already-published GitLab repository.
#   <tag>                 the channel or version tag already published on
#                        <source-repository>, e.g. preview or v0.1.0-beta.
#                        Mirrored under the identical name on
#                        <dest-repository>.
#   <dest-repository>     no tag, no digest, e.g. ghcr.io/tomlawesome/birdcage.
#
# Exit codes:
#   0  the destination tag now resolves to the same digest as the source;
#      the bare digest is printed on stdout and nothing else.
#   1  usage or validation error. Nothing was touched.
#   2  the source tag did not resolve, the copy failed, the destination tag
#      did not resolve afterwards, or it resolved to a different digest
#      than the source -- the substitution this script exists to catch.
#
# Every call that touches a registry -- resolve_source_digest, run_mirror,
# resolve_dest_digest -- is its own function so scripts/mirror-image.test.sh
# can replace all three and drive argument validation and the round-trip
# comparison for real, without a daemon or a registry.
set -euo pipefail

fail() { printf 'mirror-image: %s\n' "$1" >&2; exit 1; }
refuse() { printf 'mirror-image: %s\n' "$1" >&2; exit 2; }

# validate_repo <label> <repository> -- refuses anything carrying a tag or a
# digest: both arguments here name a bare repository, not a reference.
validate_repo() {
  local label="$1" repo="$2"
  [ -n "$repo" ] || fail "$label is required"
  case "$repo" in
    *:*) fail "$label must not carry a tag (found ':'): ${repo}" ;;
    *@*) fail "$label must not carry a digest (found '@'): ${repo}" ;;
  esac
  [[ "$repo" =~ ^[A-Za-z0-9._-]+(:[0-9]+)?(/[A-Za-z0-9._-]+)+$ ]] ||
    fail "$label is not a plain image repository reference: ${repo}"
}

# validate_tag <tag> -- Docker's own tag grammar.
validate_tag() {
  local tag="$1"
  [ -n "$tag" ] || fail 'a tag is required as the second argument'
  [[ "$tag" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$ ]] ||
    fail "not a valid Docker tag: ${tag}"
}

# resolve_source_digest <repo> <tag> -- what the source tag currently
# points at. A non-zero return (nothing pushed under this tag yet, or the
# source registry is unreachable) is the caller's cue to refuse rather than
# mirror nothing.
resolve_source_digest() {
  local repo="$1" tag="$2"
  docker buildx imagetools inspect "${repo}:${tag}" --format '{{json .Manifest.Digest}}' 2>/dev/null | tr -d '"'
}

# run_mirror <source-reference@digest> <dest-reference:tag> -- the one call
# that copies anything. A registry-to-registry manifest (and, where needed,
# blob) copy: no rebuild, no local daemon pull of the image itself.
run_mirror() {
  local source_ref="$1" dest_ref="$2"
  docker buildx imagetools create --tag "$dest_ref" "$source_ref"
}

# resolve_dest_digest <repo> <tag> -- re-resolves the tag just mirrored, so
# main can refuse a copy that did not land, or landed on something other
# than what was just mirrored, rather than reporting success on trust.
resolve_dest_digest() {
  local repo="$1" tag="$2"
  docker buildx imagetools inspect "${repo}:${tag}" --format '{{json .Manifest.Digest}}' 2>/dev/null | tr -d '"'
}

main() {
  [ $# -eq 3 ] || fail "usage: mirror-image.sh <source-repository> <tag> <dest-repository>"
  local source_repo="$1" tag="$2" dest_repo="$3"
  validate_repo "source repository" "$source_repo"
  validate_tag "$tag"
  validate_repo "destination repository" "$dest_repo"

  local source_digest
  source_digest="$(resolve_source_digest "$source_repo" "$tag")" || source_digest=""
  [ -n "$source_digest" ] ||
    refuse "${source_repo}:${tag} does not resolve; there is nothing published under that tag to mirror"
  [[ "$source_digest" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    refuse "the source digest is malformed: ${source_digest}"

  run_mirror "${source_repo}@${source_digest}" "${dest_repo}:${tag}" ||
    refuse "could not mirror ${source_repo}@${source_digest} to ${dest_repo}:${tag}"

  local dest_digest
  dest_digest="$(resolve_dest_digest "$dest_repo" "$tag")" || dest_digest=""
  [ -n "$dest_digest" ] ||
    refuse "${dest_repo}:${tag} does not resolve after mirroring"
  [[ "$dest_digest" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    refuse "the mirrored digest is malformed: ${dest_digest}"
  [ "$dest_digest" = "$source_digest" ] ||
    refuse "${dest_repo}:${tag} resolved to ${dest_digest}, not the digest that was mirrored (${source_digest}); the copy did not land the same image"

  printf 'mirror-image: %s now points at %s, matching %s:%s\n' \
    "${dest_repo}:${tag}" "$source_digest" "$source_repo" "$tag" >&2
  printf '%s\n' "$source_digest"
}

# Guard so scripts/mirror-image.test.sh can source this file -- to reuse
# validate_repo/validate_tag/main directly, and to override
# resolve_source_digest/run_mirror/resolve_dest_digest -- without main
# running on import.
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  main "$@"
fi
