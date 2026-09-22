#!/usr/bin/env bash
# Promotes one already-validated image digest to its version tag (issue #90).
# It never rebuilds and never signs: those already happened, on `preview`,
# where the digest was built and stamped, and where
# scripts/attest-tested-image.sh minted the evidence this script checks
# before it moves anything. All this script does is resolve the digest that
# was tested, prove the evidence still stands, and move a name onto it.
#
# WHY THE VERSION NEVER COMES FROM THE COMMAND LINE. A typed version is
# exactly the manual input this design refuses: the version is decided in
# one place, the tracked VERSION file, read only through
# scripts/release-version.sh. This script asks that script for both the raw
# version and the tag name, and never parses VERSION itself.
#
# WHY A VERSION TAG IS NEVER OVERWRITTEN. A version tag is a promise:
# `v0.1.0-beta` means one specific digest, forever. If that tag already
# resolves to anything, promotion refuses outright (exit 3) rather than
# repointing it -- a forgotten version bump must fail closed, not silently
# republish a different digest under a name someone has already trusted.
#
# WHY PROMOTION NEVER MOVES BYTES. Step 7 uses
# `docker buildx imagetools create`, a registry-side copy of a manifest
# reference: it can only ever point the new tag at the exact digest given to
# it, so the digest cannot change between the evidence check in step 5 and
# the tag appearing in step 7. Re-resolving the tag afterwards (step 8) is a
# check on the registry doing what it was asked, not a defence against this
# script doing something else.
#
# Usage:
#   scripts/promote-release.sh [--expect-stamp] <image-repository> <commit>
#     <image-repository>  no tag, no digest, e.g. registry.gitlab.tomlawson.io/ai/birdcage/birdcage
#     <commit>             the 40-hex commit whose build is being released
#     --expect-stamp       also require the image's own `version` output to
#                           equal the stamp scripts/release-version.sh would
#                           compute for this commit (step 6 below)
#
# Exit codes:
#   0   promoted; the bare digest is printed on stdout
#   1   usage or argument validation error
#   2   the version tag could not be created, or did not resolve back to the
#       digest just promoted
#   3   the version tag already exists (never overwritten)
#   4   --expect-stamp was given and the image's embedded stamp does not
#       match the version being released
#   10/11/12/13  propagated unchanged from
#       scripts/verify-validation-evidence.sh: mismatch / missing / ambiguous
#       / expired evidence. Never re-derived here -- that script's header
#       forbids re-implementing any of its checks.
#   11 is also used for one case of this script's own: the commit's anchor
#       tag does not resolve at all, so there is nothing to promote.
#
# Every external call -- resolving a tag to a digest, running the shared
# verifier, reading the image's own version, creating the tag -- is its own
# function, named below, so scripts/promote-release.test.sh can redefine
# them by sourcing this script and prove every refusal without a registry
# or a docker daemon.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

fail() { printf 'promote-release: %s\n' "$1" >&2; exit 1; } # usage/validation only
refuse() { # $1 exit code, $2 message
  printf 'promote-release: refused: %s\n' "$2" >&2
  exit "$1"
}

# resolve_tag_digest <repo:ref> -- prints the digest a tag or other reference
# currently resolves to, or fails (non-zero, nothing on stdout) when it does
# not resolve at all. The one function every step below uses to ask the
# registry "what does this name point at right now".
resolve_tag_digest() {
  local ref="$1" out digest
  out="$(docker buildx imagetools inspect "$ref" 2>/dev/null)" || return 1
  digest="$(printf '%s\n' "$out" | sed -n 's/^Digest:[[:space:]]*//p' | head -n1)"
  [ -n "$digest" ] || return 1
  printf '%s\n' "$digest"
}

# run_verifier <repo> <digest> <commit> -- runs the one shared verifier over
# the resolved digest, in a fresh environment carrying exactly the inputs it
# documents, plus BIRDCAGE_REF passed through when the caller has it set.
# Its exit code is returned unchanged; this function never inspects or
# re-judges its output.
run_verifier() {
  local repo="$1" digest="$2" commit="$3"
  local env_args=(BIRDCAGE_IMAGE="$repo" BIRDCAGE_DIGEST="$digest" BIRDCAGE_COMMIT="$commit")
  if [ -n "${BIRDCAGE_REF:-}" ]; then
    env_args+=(BIRDCAGE_REF="$BIRDCAGE_REF")
  fi
  env "${env_args[@]}" "$here/verify-validation-evidence.sh"
}

# image_reported_version <repo> <digest> -- asks the image itself what
# version it thinks it is, by running its `version` command. Only used
# under --expect-stamp.
image_reported_version() {
  local repo="$1" digest="$2"
  docker run --rm "${repo}@${digest}" version
}

# create_version_tag <repo> <tag> <digest> -- the registry-side, byte-free
# copy that gives the digest its version name.
create_version_tag() {
  local repo="$1" tag="$2" digest="$3"
  docker buildx imagetools create --tag "${repo}:${tag}" "${repo}@${digest}"
}

main() {
  local expect_stamp=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --expect-stamp) expect_stamp=1; shift ;;
      --) shift; break ;;
      -*) fail "unknown flag: $1" ;;
      *) break ;;
    esac
  done
  [ $# -eq 2 ] || fail "usage: promote-release.sh [--expect-stamp] <image-repository> <commit>"

  local repo="$1" commit="$2"

  # 1. Validate arguments. A repository carrying ":" or "@" already names a
  # tag or a digest, which is exactly the manual pinning this script resolves
  # for itself; a commit that is not 40 lowercase hex cannot be the exact sha
  # the anchor tag in step 3 is built from.
  case "$repo" in
    *:*|*@*) fail "image repository must carry no tag and no digest: ${repo}" ;;
  esac
  [ -n "$repo" ] || fail "image repository is required"
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]] ||
    fail "commit is not 40 lowercase hex characters: ${commit}"

  # 2. The version comes from nowhere else. See the header for why.
  local version tag
  version="$("$here/release-version.sh")"
  tag="$("$here/release-version.sh" --tag)"

  # 3. The anchor tag is written by the build that ran the tests: if it does
  # not resolve, this commit was never published through the validated path
  # at all, and there is nothing here to promote.
  local anchor_tag="${repo}:sha-${commit}" anchor_digest
  if ! anchor_digest="$(resolve_tag_digest "$anchor_tag")"; then
    refuse 11 "${anchor_tag} does not resolve; commit ${commit} was never published through the validated path"
  fi

  # 4. A VERSION TAG IS NEVER OVERWRITTEN. If <repo>:<tag> already resolves
  # to anything -- the same digest or a different one -- promotion refuses
  # rather than repointing a name someone may already have trusted. This is
  # a required behaviour of issue #90.
  local existing_digest
  if existing_digest="$(resolve_tag_digest "${repo}:${tag}")"; then
    refuse 3 "${repo}:${tag} already exists, pointing at ${existing_digest}; a version tag is never overwritten"
  fi

  # 5. Prove the evidence still stands. Propagate the verifier's exit code
  # unchanged -- never re-derive what it means.
  local verifier_status=0
  run_verifier "$repo" "$anchor_digest" "$commit" || verifier_status=$?
  if [ "$verifier_status" -ne 0 ]; then
    exit "$verifier_status"
  fi

  # 6. --expect-stamp: the one check that the bytes being released actually
  # carry the version being released, rather than a VERSION file bumped
  # after the build. Optional because only the birdcage image answers
  # `version` today.
  if [ "$expect_stamp" -eq 1 ]; then
    local expected_stamp reported_version
    expected_stamp="$("$here/release-version.sh" --stamp "$commit")"
    reported_version="$(image_reported_version "$repo" "$anchor_digest")" ||
      fail "could not run '${repo}@${anchor_digest} version' to read the embedded stamp"
    if [ "$reported_version" != "$expected_stamp" ]; then
      refuse 4 "the image reports version '${reported_version}', not the version being released '${expected_stamp}'"
    fi
  fi

  # 7. No bytes move: this only ever points the new tag at the digest given
  # to it, so the digest cannot change between the check above and here.
  create_version_tag "$repo" "$tag" "$anchor_digest" ||
    refuse 2 "could not create ${repo}:${tag} from ${anchor_digest}"

  # 8. Trust nothing the registry was merely asked to do; check it happened.
  local final_digest
  if ! final_digest="$(resolve_tag_digest "${repo}:${tag}")"; then
    refuse 2 "${repo}:${tag} was created but does not resolve"
  fi
  [ "$final_digest" = "$anchor_digest" ] ||
    refuse 2 "${repo}:${tag} resolved to ${final_digest}, not the promoted digest ${anchor_digest}"

  # 9. Commentary to stderr, the bare digest to stdout -- so a caller can
  # capture exactly the promoted digest and nothing else.
  printf 'promote-release: promoted %s to %s:%s (version %s)\n' \
    "$anchor_digest" "$repo" "$tag" "$version" >&2
  printf '%s\n' "$anchor_digest"
}

# Guard so scripts/promote-release.test.sh can source this file -- to
# override resolve_tag_digest, run_verifier, image_reported_version and
# create_version_tag -- without main running on import.
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  main "$@"
fi
