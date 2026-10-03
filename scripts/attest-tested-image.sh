#!/usr/bin/env bash
# Mints validation evidence: a cosign key-based attestation, pushed to the
# registry beside the image, saying "this digest passed the full bar under
# policy version P at time T" (issue #90, following orbit's ADR-0020). It is
# minted the moment the pushed digest first exists -- before any
# consumer-visible tag -- and every job that later gives that digest a name
# verifies it first with scripts/verify-validation-evidence.sh.
#
# Only the signing job may run this: the key pair exists solely on the
# dedicated signing runner's host, mounted read-only into its jobs, so the
# publish job never holds the key. This GitLab is CE, which has no protected
# environments or environment-scoped variables -- a CI/CD variable would be
# readable by every job on a protected branch -- so the runner mount, not
# GitLab configuration, is what keeps the key away from publication.
#
# It signs the DIGEST, never a tag: a tag can be repointed between signing
# and verifying, which is exactly the substitution this script exists to
# make impossible. A reference that is not pinned to a digest is refused.
#
# Usage:
#   scripts/attest-tested-image.sh <image-reference@digest> <image-digest>
#
# Inputs (environment):
#   BIRDCAGE_SIGNING_DIR   The signing runner's read-only key mount: must
#                          hold `cosign.key` and `password`. When set it
#                          supplies both values below, which is how CI runs
#                          this script.
#   COSIGN_PRIVATE_KEY     Path to the cosign private key. Derived from
#                          BIRDCAGE_SIGNING_DIR when that is set; settable
#                          directly for tests. Never printed.
#   COSIGN_PASSWORD        The key's password; cosign reads it from the
#                          environment itself. Read from
#                          BIRDCAGE_SIGNING_DIR/password when that is set.
#   CI_COMMIT_SHA          }
#   CI_COMMIT_REF_NAME     }  the predicate's provenance fields, from the
#   CI_PIPELINE_ID         }  predefined GitLab job environment
#   CI_PIPELINE_URL        }
#   BIRDCAGE_POLICY_VERSION  Optional; the policy version to bind. Computed
#                          by scripts/policy-version.sh when unset.
#   BIRDCAGE_COSIGN        Optional; the cosign command to run, overridable
#                          only so tests can stub it. Real use resolves the
#                          pinned binary via scripts/ensure-cosign.sh.
#
# Every step that needs the registry or the signing key -- run_cosign_attest
# below -- is its own function so scripts/attest-tested-image.test.sh can
# replace it and drive everything else (input validation, predicate
# construction, signing-key resolution) without either.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"

# The predicate type names what this attestation claims. Verifiers filter on
# it; scripts/verify-validation-evidence.sh carries the same constant.
readonly PREDICATE_TYPE="https://tomlawson.io/attestations/birdcage-validation/v1"

# Cleaned up on any exit, including a fail()-triggered one; declared here
# (not `local` inside a function) so the trap can always find it.
predicate_file=""
trap 'rm -f "${predicate_file}"' EXIT

fail() { printf 'attest-tested-image: %s\n' "$1" >&2; exit 1; }

# validate_reference <image-reference> <image-digest> -- refuses anything
# that is not a plain "<repo>@sha256:<64 hex>" reference naming exactly the
# digest passed alongside it. This is the "signs the digest, never a tag"
# rule, enforced before anything else runs.
validate_reference() {
  local image_reference="$1" image_digest="$2"
  [ -n "$image_reference" ] || fail 'an image reference is required as the first argument'
  [ -n "$image_digest" ] || fail 'an image digest is required as the second argument'
  [[ "$image_digest" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    fail "image digest is not an immutable manifest digest: ${image_digest}"
  [[ "$image_reference" =~ ^[A-Za-z0-9._-]+(:[0-9]+)?(/[A-Za-z0-9._-]+)+@sha256:[0-9a-f]{64}$ ]] ||
    fail "image reference is not a plain registry reference pinned to a digest (a tag is not accepted): ${image_reference}"
  [ "${image_reference##*@}" = "$image_digest" ] ||
    fail "image reference ${image_reference} does not name digest ${image_digest}"
}

# resolve_signing_key -- sets COSIGN_PRIVATE_KEY/COSIGN_PASSWORD from
# BIRDCAGE_SIGNING_DIR when it is set, else requires both to already be in
# the environment (how tests supply them). Never prints COSIGN_PASSWORD.
resolve_signing_key() {
  if [ -n "${BIRDCAGE_SIGNING_DIR:-}" ]; then
    [ -d "$BIRDCAGE_SIGNING_DIR" ] ||
      fail "BIRDCAGE_SIGNING_DIR is not a directory: ${BIRDCAGE_SIGNING_DIR}. It is the signing runner's read-only key mount; either this job is not running on that runner, or the owner setup has not created the host directory yet."
    COSIGN_PRIVATE_KEY="${BIRDCAGE_SIGNING_DIR}/cosign.key"
    [ -f "${BIRDCAGE_SIGNING_DIR}/password" ] ||
      fail "BIRDCAGE_SIGNING_DIR has no password file: ${BIRDCAGE_SIGNING_DIR}/password. The owner setup places the key password there."
    COSIGN_PASSWORD="$(< "${BIRDCAGE_SIGNING_DIR}/password")"
    export COSIGN_PASSWORD
  fi
  [ -n "${COSIGN_PRIVATE_KEY:-}" ] ||
    fail 'COSIGN_PRIVATE_KEY is not set and BIRDCAGE_SIGNING_DIR is not set either. CI supplies BIRDCAGE_SIGNING_DIR; tests may set COSIGN_PRIVATE_KEY directly.'
  [ -f "$COSIGN_PRIVATE_KEY" ] ||
    fail "COSIGN_PRIVATE_KEY does not point at a readable file: ${COSIGN_PRIVATE_KEY}. On the signing runner this is BIRDCAGE_SIGNING_DIR/cosign.key."
  [ -n "${COSIGN_PASSWORD:-}" ] ||
    fail 'COSIGN_PASSWORD is not set. It comes from BIRDCAGE_SIGNING_DIR/password on the signing runner; tests may set it directly.'
}

# build_predicate <commit> <ref> <pipeline-id> <pipeline-url> <digest>
#                 <policy-version> <recorded-at> <outfile>
# Every field is validated to a shape that needs no JSON escaping before it
# is written; anything else is a bug in the caller, not a value to quote
# around.
build_predicate() {
  local commit="$1" ref="$2" pipeline_id="$3" pipeline_url="$4" digest="$5" \
    policy_version="$6" recorded_at="$7" outfile="$8"
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || fail "CI_COMMIT_SHA is not an exact commit SHA: ${commit:-<unset>}"
  [[ "$ref" =~ ^[A-Za-z0-9._/-]+$ ]] || fail "CI_COMMIT_REF_NAME is not a plain ref name: ${ref:-<unset>}"
  [[ "$pipeline_id" =~ ^[0-9]+$ ]] || fail "CI_PIPELINE_ID is not numeric: ${pipeline_id:-<unset>}"
  [[ "$pipeline_url" =~ ^https://[A-Za-z0-9._:/-]+$ ]] || fail "CI_PIPELINE_URL is not an https URL: ${pipeline_url:-<unset>}"
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "image digest is not an immutable manifest digest: ${digest}"
  [[ "$policy_version" =~ ^[0-9a-f]{64}$ ]] || fail "policy version is not a sha256 hex value: ${policy_version}"
  [[ "$recorded_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] ||
    fail "recordedAt is not RFC3339 UTC: ${recorded_at}"

  cat > "$outfile" <<JSON
{
  "commit": "${commit}",
  "ref": "${ref}",
  "pipelineId": ${pipeline_id},
  "pipelineUrl": "${pipeline_url}",
  "imageDigest": "${digest}",
  "policyVersion": "${policy_version}",
  "recordedAt": "${recorded_at}"
}
JSON
}

# run_cosign_attest <predicate-file> <image-reference> -- the one call that
# needs the signing key and a reachable registry. It is the only function
# scripts/attest-tested-image.test.sh replaces; everything else in this
# script (validation, predicate construction, signing-key resolution) runs
# for real under test.
#
# --use-signing-config=false and --tlog-upload=false: this attestation is
# key-based against no transparency log (there is no Rekor here); cosign v3
# refuses --tlog-upload=false unless --use-signing-config is also turned
# off. --yes answers cosign's interactive prompts, which a job cannot.
run_cosign_attest() {
  local predicate_file="$1" image_reference="$2"
  "$cosign_cmd" attest \
    --predicate "$predicate_file" \
    --type "$PREDICATE_TYPE" \
    --key "$COSIGN_PRIVATE_KEY" \
    --use-signing-config=false \
    --tlog-upload=false \
    --yes \
    "$image_reference"
}

main() {
  local image_reference="${1:-}" image_digest="${2:-}"
  validate_reference "$image_reference" "$image_digest"
  resolve_signing_key

  local commit="${CI_COMMIT_SHA:-}" ref="${CI_COMMIT_REF_NAME:-}" \
    pipeline_id="${CI_PIPELINE_ID:-}" pipeline_url="${CI_PIPELINE_URL:-}"

  local policy_version="${BIRDCAGE_POLICY_VERSION:-}"
  if [ -z "$policy_version" ]; then
    policy_version="$("$here/policy-version.sh")"
  fi

  local recorded_at
  recorded_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  cosign_cmd="${BIRDCAGE_COSIGN:-}"
  if [ -z "$cosign_cmd" ]; then
    cosign_cmd="$("$here/ensure-cosign.sh")"
  fi

  predicate_file="$(mktemp)"
  build_predicate "$commit" "$ref" "$pipeline_id" "$pipeline_url" \
    "$image_digest" "$policy_version" "$recorded_at" "$predicate_file"

  run_cosign_attest "$predicate_file" "$image_reference" ||
    fail "cosign could not attest ${image_reference}"

  printf 'attest-tested-image: attested %s (policy %s) as %s\n' \
    "$image_digest" "$policy_version" "$PREDICATE_TYPE"
}

# Guard so scripts/attest-tested-image.test.sh can source this file -- to
# reuse validate_reference/build_predicate/main directly, and to override
# run_cosign_attest -- without main running on import.
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  main "$@"
fi
