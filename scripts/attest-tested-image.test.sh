#!/usr/bin/env bash
# Tests for attest-tested-image.sh. No registry and no signing key are
# available in this environment, so these tests never call cosign for real:
# they source the script (its sourcing guard keeps main() from running on
# import), override run_cosign_attest -- the one function that needs the
# registry and the key -- with a fixture recorder, and then drive main()
# for real over everything else: reference validation (including the
# digest-only rule), signing-key resolution, and predicate construction.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/attest-tested-image.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

ok() { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; shift; [ $# -gt 0 ] && printf '%s\n' "$*" | sed 's/^/       /'; fail=$((fail + 1)); }

# shellcheck source=/dev/null
source "$script"

digest="sha256:$(printf 'a%.0s' $(seq 64))"
commit="$(printf 'b%.0s' $(seq 40))"
ref_ok="preview"
pipeline_id="42"
pipeline_url="https://gitlab.tomlawson.io/ai/birdcage/-/pipelines/42"
policy="$(printf 'c%.0s' $(seq 64))"
digest_ref="registry.tomlawson.io/ai/birdcage/birdcage@${digest}"

# A valid signing key and password, fixture-only: never a real cosign key.
key_dir="$work/signing"
mkdir -p "$key_dir"
printf 'fixture cosign key, not a real key\n' > "$key_dir/cosign.key"
printf 'fixture-password\n' > "$key_dir/password"

# recorded_predicate -- run_cosign_attest, replaced so no cosign binary and
# no registry are ever touched. Records what it was called with, and the
# predicate file's contents at call time, into $work, then always
# "succeeds" unless FAIL_COSIGN_ATTEST=1 asks it to fail (proving main()
# surfaces that failure).
run_cosign_attest() {
  local predicate_file="$1" image_reference="$2"
  printf '%s' "$image_reference" > "$work/recorded_image_reference"
  cp "$predicate_file" "$work/recorded_predicate.json"
  [ "${FAIL_COSIGN_ATTEST:-0}" = "1" ] && return 1
  return 0
}

# run <args...> -- invokes main() with a clean, valid environment as a
# baseline, letting the caller override specific variables first. Runs in a
# subshell (command substitution) so main()'s `exit` (via fail(), on every
# path) never kills the test runner.
run() {
  local got=0 out
  out="$(
    CI_COMMIT_SHA="$commit" CI_COMMIT_REF_NAME="$ref_ok" \
    CI_PIPELINE_ID="$pipeline_id" CI_PIPELINE_URL="$pipeline_url" \
    BIRDCAGE_POLICY_VERSION="$policy" \
    COSIGN_PRIVATE_KEY="$key_dir/cosign.key" COSIGN_PASSWORD="fixture-password" \
    main "$@" 2>&1
  )" || got=$?
  printf '%s\x1f%s' "$got" "$out"
}

# --- a valid call attests the digest reference and builds the right
# predicate -----------------------------------------------------------
rm -f "$work/recorded_image_reference" "$work/recorded_predicate.json"
result="$(run "$digest_ref" "$digest")"
got="${result%%$'\x1f'*}"; out="${result#*$'\x1f'}"
if [ "$got" = 0 ] && [ -f "$work/recorded_predicate.json" ] \
   && [ "$(cat "$work/recorded_image_reference")" = "$digest_ref" ]; then
  ok "a valid digest reference is accepted and passed through to run_cosign_attest"
else
  bad "a valid digest reference is accepted and passed through to run_cosign_attest" "exit $got: $out"
fi

expected_predicate="$(cat <<JSON
{
  "commit": "${commit}",
  "ref": "${ref_ok}",
  "pipelineId": ${pipeline_id},
  "pipelineUrl": "${pipeline_url}",
  "imageDigest": "${digest}",
  "policyVersion": "${policy}",
  "recordedAt": "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["recordedAt"])' "$work/recorded_predicate.json" 2>/dev/null)"
}
JSON
)"
if [ -f "$work/recorded_predicate.json" ] && diff -q <(printf '%s\n' "$expected_predicate") "$work/recorded_predicate.json" > /dev/null 2>&1; then
  ok "the predicate has exactly the seven specified fields with the right values"
else
  bad "the predicate has exactly the seven specified fields with the right values" \
    "$(cat "$work/recorded_predicate.json" 2>/dev/null)"
fi

recorded_at="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["recordedAt"])' "$work/recorded_predicate.json" 2>/dev/null)"
case "$recorded_at" in
  ????-??-??T??:??:??Z) ok "recordedAt is RFC3339 UTC (Z-suffixed)" ;;
  *) bad "recordedAt is RFC3339 UTC (Z-suffixed)" "got: $recorded_at" ;;
esac

# --- the digest-only rule: a tag reference is refused -------------------
result="$(run "registry.tomlawson.io/ai/birdcage/birdcage:preview" "$digest")"
got="${result%%$'\x1f'*}"; out="${result#*$'\x1f'}"
if [ "$got" != 0 ]; then
  ok "a tag reference (no @digest) is refused"
else
  bad "a tag reference (no @digest) is refused" "exit $got: $out"
fi

result="$(run "registry.tomlawson.io/ai/birdcage/birdcage@sha256:not-hex" "sha256:not-hex")"
got="${result%%$'\x1f'*}"; out="${result#*$'\x1f'}"
if [ "$got" != 0 ]; then
  ok "a malformed digest is refused"
else
  bad "a malformed digest is refused" "exit $got: $out"
fi

result="$(run "registry.tomlawson.io/ai/birdcage/birdcage@${digest}" "sha256:$(printf 'f%.0s' $(seq 64))")"
got="${result%%$'\x1f'*}"; out="${result#*$'\x1f'}"
if [ "$got" != 0 ]; then
  ok "a reference whose @digest does not match the given digest argument is refused"
else
  bad "a reference whose @digest does not match the given digest argument is refused" "exit $got: $out"
fi

# A reference carrying BOTH a tag and a digest ("repo:tag@digest") ends in
# exactly the expected "@<digest>", so the suffix-agreement check above
# would let it through on its own -- only the full anchored shape check
# (no ":" allowed in a path segment) catches this one. Isolates that check
# from the suffix-agreement check, which a looser mutation could otherwise
# hide behind.
result="$(run "registry.tomlawson.io/ai/birdcage/birdcage:preview@${digest}" "$digest")"
got="${result%%$'\x1f'*}"; out="${result#*$'\x1f'}"
if [ "$got" != 0 ]; then
  ok "a reference carrying both a tag and a digest is refused (not a plain digest reference)"
else
  bad "a reference carrying both a tag and a digest is refused (not a plain digest reference)" "exit $got: $out"
fi

# --- signing key resolution ---------------------------------------------
got=0
out="$(
  CI_COMMIT_SHA="$commit" CI_COMMIT_REF_NAME="$ref_ok" \
  CI_PIPELINE_ID="$pipeline_id" CI_PIPELINE_URL="$pipeline_url" \
  BIRDCAGE_POLICY_VERSION="$policy" \
  main "$digest_ref" "$digest" 2>&1
)" || got=$?
case "$out" in
  *"COSIGN_PRIVATE_KEY is not set and BIRDCAGE_SIGNING_DIR is not set either"*)
    [ "$got" != 0 ] && ok "no signing key at all (no BIRDCAGE_SIGNING_DIR, no COSIGN_PRIVATE_KEY) is refused, naming the cause" \
      || bad "no signing key at all (no BIRDCAGE_SIGNING_DIR, no COSIGN_PRIVATE_KEY) is refused, naming the cause" "exit $got: $out" ;;
  *) bad "no signing key at all (no BIRDCAGE_SIGNING_DIR, no COSIGN_PRIVATE_KEY) is refused, naming the cause" "exit $got: $out" ;;
esac

got=0
out="$(
  CI_COMMIT_SHA="$commit" CI_COMMIT_REF_NAME="$ref_ok" \
  CI_PIPELINE_ID="$pipeline_id" CI_PIPELINE_URL="$pipeline_url" \
  BIRDCAGE_POLICY_VERSION="$policy" \
  BIRDCAGE_SIGNING_DIR="$key_dir" \
  main "$digest_ref" "$digest" 2>&1
)" || got=$?
if [ "$got" = 0 ]; then
  ok "BIRDCAGE_SIGNING_DIR supplies the key and password when set"
else
  bad "BIRDCAGE_SIGNING_DIR supplies the key and password when set" "exit $got: $out"
fi

got=0
out="$(
  CI_COMMIT_SHA="$commit" CI_COMMIT_REF_NAME="$ref_ok" \
  CI_PIPELINE_ID="$pipeline_id" CI_PIPELINE_URL="$pipeline_url" \
  BIRDCAGE_POLICY_VERSION="$policy" \
  BIRDCAGE_SIGNING_DIR="$work/no-such-signing-dir" \
  main "$digest_ref" "$digest" 2>&1
)" || got=$?
case "$out" in
  *"is not a directory: $work/no-such-signing-dir"*)
    if [ "$got" != 0 ]; then
      ok "a missing BIRDCAGE_SIGNING_DIR is refused, naming the missing directory"
    else
      bad "a missing BIRDCAGE_SIGNING_DIR is refused, naming the missing directory" "exit $got: $out"
    fi
    ;;
  *) bad "a missing BIRDCAGE_SIGNING_DIR is refused, naming the missing directory" "exit $got: $out" ;;
esac

# --- provenance field validation ----------------------------------------
got=0
out="$(
  CI_COMMIT_SHA="not-a-sha" CI_COMMIT_REF_NAME="$ref_ok" \
  CI_PIPELINE_ID="$pipeline_id" CI_PIPELINE_URL="$pipeline_url" \
  BIRDCAGE_POLICY_VERSION="$policy" \
  COSIGN_PRIVATE_KEY="$key_dir/cosign.key" COSIGN_PASSWORD="fixture-password" \
  main "$digest_ref" "$digest" 2>&1
)" || got=$?
if [ "$got" != 0 ]; then
  ok "a malformed CI_COMMIT_SHA is refused"
else
  bad "a malformed CI_COMMIT_SHA is refused" "exit $got: $out"
fi

# --- a failing cosign call surfaces as a failure, not a silent success --
FAIL_COSIGN_ATTEST=1
result="$(run "$digest_ref" "$digest")"
got="${result%%$'\x1f'*}"; out="${result#*$'\x1f'}"
FAIL_COSIGN_ATTEST=0
if [ "$got" != 0 ]; then
  ok "a failing cosign attest call is surfaced as a failure"
else
  bad "a failing cosign attest call is surfaced as a failure" "exit $got: $out"
fi

# --- predicate type matches the verifier's -------------------------------
verifier_type="$(sed -n 's/^readonly PREDICATE_TYPE="\(.*\)"$/\1/p' "$here/verify-validation-evidence.sh")"
if [ "$verifier_type" = "$PREDICATE_TYPE" ]; then
  ok "PREDICATE_TYPE matches scripts/verify-validation-evidence.sh"
else
  bad "PREDICATE_TYPE matches scripts/verify-validation-evidence.sh" "attester=$PREDICATE_TYPE verifier=$verifier_type"
fi

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
