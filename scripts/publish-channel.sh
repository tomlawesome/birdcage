#!/usr/bin/env bash
# Gives an already-validated digest a consumer-visible channel name (issue
# #90, following orbit's ADR-0020): a tag like "preview" that a consumer can
# pull without knowing the digest underneath. This is the publication half
# of the house rule that no job both judges an artefact and ships it --
# scripts/attest-tested-image.sh mints the evidence that a digest passed the
# bar, this script only ever moves a tag onto a digest that evidence already
# names. It never builds an image, never pushes image bytes, and never
# signs anything.
#
# Before it moves anything it calls the one shared verifier,
# scripts/verify-validation-evidence.sh, and refuses on whatever ground that
# script refuses on. THIS SCRIPT DOES NOT RE-CHECK ANY OF THAT ITSELF -- no
# second digest/commit/ref/policy comparison, no second evidence-age check.
# Re-implementing any of it here would be drift from the one place that
# check lives, not a shortcut.
#
# Usage:
#   scripts/publish-channel.sh <image-repository> <digest> <channel-tag>
#
#   <image-repository>  No tag and no digest, e.g.
#                        ghcr.io/tomlawesome/birdcage. A repository carrying
#                        ':' or '@' is a usage error -- this is a stricter
#                        rule than the verifier's own BIRDCAGE_IMAGE check
#                        (which tolerates a registry port), because this
#                        argument is typed by a human or a CI job template,
#                        not derived from a resolved reference.
#   <digest>             "sha256:<64 hex>", the digest being published.
#   <channel-tag>        e.g. preview. Validated against Docker's tag
#                         grammar: [A-Za-z0-9_][A-Za-z0-9._-]{0,127}.
#
# Inputs (environment):
#   BIRDCAGE_COMMIT   Required, 40 hex: the commit the publisher is acting
#                      for. Passed straight through to the verifier.
#   BIRDCAGE_REF       Optional; passed straight through to the verifier.
#
# Exit codes:
#   0   the channel tag now points at the given digest.
#   1   usage, argument or environment error -- nothing was touched.
#   10/11/12/13
#       the verifier's own mismatch/missing/ambiguous/expired grounds,
#       propagated unchanged so the caller sees exactly what it refused on.
#       Any other non-zero the verifier returns (its own misconfiguration
#       codes) is also propagated unchanged, for the same reason.
#   2   the tag could not be created, or did not resolve back to the digest
#       just published, after the verifier accepted.
#
# Every external call -- the verifier invocation, the registry-side retag,
# the after-the-fact resolve -- is isolated in its own function so
# scripts/publish-channel.test.sh can override each one by sourcing this
# script, without a registry, cosign or a Docker daemon.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

fail() { printf 'publish-channel: %s\n' "$1" >&2; exit 1; }
fail_publish() { printf 'publish-channel: %s\n' "$1" >&2; exit 2; }

# run_verifier <image> <digest> <commit> <ref> -- delegates the entire
# accept/refuse decision to the one shared verifier. Its exit code is
# returned to the caller untouched, whatever it is: 10/11/12/13 name a
# refusal ground, anything else names the verifier's own misconfiguration.
# The only function replaced under test, so a fixture governs the ground
# without a real registry, cosign binary or signing key.
run_verifier() {
  local image="$1" digest="$2" commit="$3" ref="$4"
  BIRDCAGE_IMAGE="$image" BIRDCAGE_DIGEST="$digest" BIRDCAGE_COMMIT="$commit" \
    BIRDCAGE_REF="$ref" "$here/verify-validation-evidence.sh"
}

# create_channel_tag <repo> <tag> <digest> -- a registry-side retag: cosign
# and buildx call this "imagetools create", but no image bytes move, only
# manifest metadata. The digest cannot change between validation and
# publication because nothing is rebuilt or re-pushed here -- the tag is
# just made to point at the exact digest the verifier already accepted.
create_channel_tag() {
  local repo="$1" tag="$2" digest="$3"
  docker buildx imagetools create --tag "${repo}:${tag}" "${repo}@${digest}"
}

# resolve_tag_digest <repo> <tag> -- re-resolves the tag just published and
# prints the digest it now points at, so main can refuse a tag that did not
# land, or landed on something other than what was just published, rather
# than reporting success on trust.
resolve_tag_digest() {
  local repo="$1" tag="$2"
  docker buildx imagetools inspect "${repo}:${tag}" --format '{{json .Manifest.Digest}}' 2>/dev/null | tr -d '"'
}

main() {
  [ $# -eq 3 ] || fail "usage: $(basename "${BASH_SOURCE[0]:-$0}") <image-repository> <digest> <channel-tag>"
  local repo="$1" digest="$2" tag="$3"

  case "$repo" in
    *:*) fail "image repository must not carry a tag (found ':'): ${repo}" ;;
    *@*) fail "image repository must not carry a digest (found '@'): ${repo}" ;;
  esac
  [[ "$repo" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)+$ ]] ||
    fail "not a plain image repository reference: ${repo}"

  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    fail "not an immutable manifest digest: ${digest}"

  [[ "$tag" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$ ]] ||
    fail "not a valid Docker channel tag: ${tag}"

  : "${BIRDCAGE_COMMIT:?BIRDCAGE_COMMIT is required: the commit the publisher is acting for}"
  [[ "$BIRDCAGE_COMMIT" =~ ^[0-9a-f]{40}$ ]] ||
    fail "BIRDCAGE_COMMIT is not an exact commit SHA: ${BIRDCAGE_COMMIT}"

  local ref="${BIRDCAGE_REF:-}"

  local verifier_rc=0
  run_verifier "$repo" "$digest" "$BIRDCAGE_COMMIT" "$ref" || verifier_rc=$?
  [ "$verifier_rc" -eq 0 ] || exit "$verifier_rc"

  create_channel_tag "$repo" "$tag" "$digest" ||
    fail_publish "could not create channel tag ${repo}:${tag} from ${digest}"

  local resolved
  resolved="$(resolve_tag_digest "$repo" "$tag")" ||
    fail_publish "could not resolve ${repo}:${tag} after publishing"
  [ -n "$resolved" ] ||
    fail_publish "${repo}:${tag} did not resolve to any digest after publishing"
  [ "$resolved" = "$digest" ] ||
    fail_publish "${repo}:${tag} resolved to ${resolved}, not the digest just published (${digest}); a tag that did not land, or landed on something else, must not pass silently"

  printf 'publish-channel: %s now points at %s\n' "${repo}:${tag}" "$digest"
}

# Guard so scripts/publish-channel.test.sh can source this file -- to
# override run_verifier/create_channel_tag/resolve_tag_digest and then
# drive main() for real over everything else -- without main running on
# import.
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  main "$@"
fi
