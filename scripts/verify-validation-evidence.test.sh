#!/usr/bin/env bash
# Tests for verify-validation-evidence.sh. A gate that has never refused
# proves nothing, so every one of the four refusal grounds in the script's
# header has a case here that proves it fires, plus the retried-job case and
# the boundary either side of seven days. No registry and no network are
# available in this environment, so these tests never call cosign for real:
# they source the script (its sourcing guard keeps main() from running on
# import) and drive judge_evidence directly against fixture DSSE envelopes --
# exactly the JSONL shape `cosign verify-attestation` would have already
# verified and handed to this script.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/verify-validation-evidence.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

ok() { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; shift; [ $# -gt 0 ] && printf '%s\n' "$*" | sed 's/^/       /'; fail=$((fail + 1)); }

# Sourcing runs every top-level declaration (functions, the PREDICATE_TYPE
# constant, the EXIT trap) but not main(), because BASH_SOURCE[0] != $0 when
# sourced -- the same guard scripts/ensure-cosign.sh already uses.
# shellcheck source=/dev/null
source "$script"

digest="sha256:$(printf 'a%.0s' $(seq 64))"
other_digest="sha256:$(printf 'e%.0s' $(seq 64))"
commit="$(printf 'b%.0s' $(seq 40))"
other_commit="$(printf 'f%.0s' $(seq 40))"
policy="$(printf 'c%.0s' $(seq 64))"
other_policy="$(printf '9%.0s' $(seq 64))"

# statement <digest> <commit> <ref> <pipeline-id> <policy-version> <recorded-at>
# -- one in-toto statement of the birdcage-validation predicate type, as
# JSON on stdout.
statement() {
  python3 - "$1" "$2" "$3" "$4" "$5" "$6" <<'PY'
import json, sys
digest, commit, ref, pipeline_id, policy_version, recorded_at = sys.argv[1:7]
print(json.dumps({
    "_type": "https://in-toto.io/Statement/v0.1",
    "predicateType": "https://tomlawson.io/attestations/birdcage-validation/v1",
    "subject": [{"name": "registry.gitlab.tomlawson.io/ai/birdcage/birdcage", "digest": {"sha256": digest.split(":", 1)[1]}}],
    "predicate": {
        "commit": commit, "ref": ref, "pipelineId": int(pipeline_id),
        "pipelineUrl": "https://gitlab.tomlawson.io/ai/birdcage/-/pipelines/%s" % pipeline_id,
        "imageDigest": digest, "policyVersion": policy_version, "recordedAt": recorded_at,
    },
}))
PY
}

# wrong_predicate_type <digest> <commit> <ref> <pipeline-id> <policy-version> <recorded-at>
# -- same shape, but a predicate type this verifier must ignore, to prove
# type filtering actually filters.
wrong_predicate_type() {
  python3 - "$1" "$2" "$3" "$4" "$5" "$6" <<'PY'
import json, sys
digest, commit, ref, pipeline_id, policy_version, recorded_at = sys.argv[1:7]
print(json.dumps({
    "_type": "https://in-toto.io/Statement/v0.1",
    "predicateType": "https://tomlawson.io/attestations/some-other-check/v1",
    "subject": [{"name": "registry.gitlab.tomlawson.io/ai/birdcage/birdcage", "digest": {"sha256": digest.split(":", 1)[1]}}],
    "predicate": {
        "commit": commit, "ref": ref, "pipelineId": int(pipeline_id),
        "pipelineUrl": "https://gitlab.tomlawson.io/ai/birdcage/-/pipelines/%s" % pipeline_id,
        "imageDigest": digest, "policyVersion": policy_version, "recordedAt": recorded_at,
    },
}))
PY
}

# forged_predicate <subject-digest> <predicate-digest> <commit> <ref>
#                  <pipeline-id> <policy-version> <recorded-at>
# -- a statement whose in-toto subject names one digest but whose predicate
# claims a different imageDigest: the shape a forged or misattached
# predicate would have if it were stapled onto someone else's subject. This
# isolates the predicate.imageDigest check from the subject-digest check
# above it (statement() always keeps both equal, so it cannot tell the two
# checks apart).
forged_predicate() {
  python3 - "$1" "$2" "$3" "$4" "$5" "$6" "$7" <<'PY'
import json, sys
subject_digest, predicate_digest, commit, ref, pipeline_id, policy_version, recorded_at = sys.argv[1:8]
print(json.dumps({
    "_type": "https://in-toto.io/Statement/v0.1",
    "predicateType": "https://tomlawson.io/attestations/birdcage-validation/v1",
    "subject": [{"name": "registry.gitlab.tomlawson.io/ai/birdcage/birdcage", "digest": {"sha256": subject_digest.split(":", 1)[1]}}],
    "predicate": {
        "commit": commit, "ref": ref, "pipelineId": int(pipeline_id),
        "pipelineUrl": "https://gitlab.tomlawson.io/ai/birdcage/-/pipelines/%s" % pipeline_id,
        "imageDigest": predicate_digest, "policyVersion": policy_version, "recordedAt": recorded_at,
    },
}))
PY
}

# envelope <statement-json> -- wraps a statement as the DSSE-ish JSONL line
# cosign verify-attestation prints once it has already verified the
# signature: {"payloadType", "payload": base64(statement), "signatures"}.
envelope() {
  python3 - <<PY
import base64, json
stmt = '''$1'''
print(json.dumps({
    "payloadType": "application/vnd.in-toto+json",
    "payload": base64.b64encode(stmt.encode()).decode(),
    "signatures": [{"keyid": "", "sig": "deadbeef"}],
}))
PY
}

# fixture <name> <statement-json>... -- writes one JSONL file under $work
# with one envelope line per statement given, and prints its path.
fixture() {
  local name="$1" f="$work/$1.jsonl"
  shift
  : > "$f"
  for stmt in "$@"; do
    envelope "$stmt" >> "$f"
  done
  printf '%s' "$f"
}

now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }
minus() { # minus <seconds> -- an RFC3339 UTC timestamp that many seconds in the past
  python3 - "$1" <<'PY'
import datetime, sys
print((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=float(sys.argv[1]))).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
}
plus() { # plus <seconds> -- an RFC3339 UTC timestamp that many seconds in the future
  python3 - "$1" <<'PY'
import datetime, sys
print((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=float(sys.argv[1]))).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
}

# expect <want-exit> <name> <fixture-file> [ref] -- runs judge_evidence
# against the fixture and checks the exit code judge_evidence's own exit
# call produces (it always exits, on success or refusal alike, so this must
# run in a subshell to observe the code without killing the test runner).
expect() {
  local want="$1" name="$2" f="$3" ref="${4:-main}" got=0 out
  out="$(judge_evidence "$f" "$digest" "$commit" "$ref" "$policy" 7 2>&1)" || got=$?
  if [ "$got" = "$want" ]; then
    ok "$name"
  else
    bad "$name" "exit $got, want $want" "$out"
  fi
}

recent="$(minus 3600)"

# --- accept: a single agreeing item of evidence ------------------------
f="$(fixture good "$(statement "$digest" "$commit" main 1 "$policy" "$recent")")"
expect 0 "a single matching item of evidence is accepted" "$f"

# --- mismatch (10): each field in turn --------------------------------
f="$(fixture mismatch_digest "$(statement "$other_digest" "$commit" main 1 "$policy" "$recent")")"
expect 10 "evidence for a different digest is a mismatch" "$f"

f="$(fixture forged_digest "$(forged_predicate "$digest" "$other_digest" "$commit" main 1 "$policy" "$recent")")"
expect 10 "a predicate claiming a different imageDigest than its own subject is a mismatch" "$f"

f="$(fixture mismatch_commit "$(statement "$digest" "$other_commit" main 1 "$policy" "$recent")")"
expect 10 "evidence for a different commit is a mismatch" "$f"

f="$(fixture mismatch_ref "$(statement "$digest" "$commit" other-branch 1 "$policy" "$recent")")"
expect 10 "evidence for a different ref is a mismatch" "$f" main

f="$(fixture mismatch_policy "$(statement "$digest" "$commit" main 1 "$other_policy" "$recent")")"
expect 10 "evidence under a stale policy version is a mismatch" "$f"

# --- missing (11): no evidence, empty file, wrong predicate type -------
f="$work/absent.jsonl"; : > "$f"
expect 11 "an empty evidence file is missing" "$f"

f="$(fixture wrong_type "$(wrong_predicate_type "$digest" "$commit" main 1 "$policy" "$recent")")"
expect 11 "evidence of another predicate type is missing, not accepted" "$f"

# --- ambiguous (12): two verified items disagreeing on the claim -------
f="$(fixture ambiguous \
  "$(statement "$digest" "$commit" main 1 "$policy" "$recent")" \
  "$(statement "$digest" "$commit" main 2 "$policy" "$(minus 1800)")")"
expect 12 "two items of evidence disagreeing on pipelineId are ambiguous" "$f"

f="$(fixture ambiguous_digest \
  "$(statement "$digest" "$commit" main 1 "$policy" "$recent")" \
  "$(statement "$other_digest" "$commit" main 1 "$policy" "$recent")")"
expect 12 "two items of evidence disagreeing on imageDigest are ambiguous" "$f"

# --- the retried-job case: identical claim, different recordedAt only --
f="$(fixture retried \
  "$(statement "$digest" "$commit" main 1 "$policy" "$(minus 7200)")" \
  "$(statement "$digest" "$commit" main 1 "$policy" "$recent")")"
expect 0 "two items differing only in recordedAt are one item of evidence, not ambiguous" "$f"
out="$(judge_evidence "$f" "$digest" "$commit" main "$policy" 7)" || true
case "$out" in
  *"recorded $recent"*) ok "the retried-job case is governed by the newest recordedAt" ;;
  *) bad "the retried-job case is governed by the newest recordedAt" "$out" ;;
esac

# --- expired/future (13): boundary either side of seven days, and future
just_under_7d="$(minus "$(( 7 * 24 * 3600 - 300 ))")"
f="$(fixture just_under "$(statement "$digest" "$commit" main 1 "$policy" "$just_under_7d")")"
expect 0 "evidence just under seven days old still passes" "$f"

just_over_7d="$(minus "$(( 7 * 24 * 3600 + 300 ))")"
f="$(fixture just_over "$(statement "$digest" "$commit" main 1 "$policy" "$just_over_7d")")"
expect 13 "evidence just over seven days old is expired" "$f"

future="$(plus 600)"
f="$(fixture future "$(statement "$digest" "$commit" main 1 "$policy" "$future")")"
expect 13 "evidence dated in the future is refused" "$f"

# --- fetch_verified_attestations wiring: main() treats a failed fetch as
# missing evidence, without ever reaching judge_evidence. Overriding it here
# is exactly the replacement scripts/attest-tested-image.test.sh and CI
# never need a registry to make.
fetch_verified_attestations() { return 1; }
: > "$work/unused.pub"
got=0
out="$(BIRDCAGE_IMAGE=registry.gitlab.tomlawson.io/ai/birdcage/birdcage BIRDCAGE_DIGEST="$digest" \
  BIRDCAGE_COMMIT="$commit" BIRDCAGE_POLICY_VERSION="$policy" \
  COSIGN_PUBLIC_KEY="$work/unused.pub" BIRDCAGE_COSIGN=/bin/true \
  main 2>&1)" || got=$?
if [ "$got" = 11 ]; then
  ok "main() treats a failed fetch_verified_attestations as missing evidence (exit 11)"
else
  bad "main() treats a failed fetch_verified_attestations as missing evidence (exit 11)" "exit $got: $out"
fi

# --- predicate type constant matches the attester's ---------------------
attester_type="$(sed -n 's/^readonly PREDICATE_TYPE="\(.*\)"$/\1/p' "$here/attest-tested-image.sh")"
if [ "$attester_type" = "$PREDICATE_TYPE" ]; then
  ok "PREDICATE_TYPE matches scripts/attest-tested-image.sh"
else
  bad "PREDICATE_TYPE matches scripts/attest-tested-image.sh" "verifier=$PREDICATE_TYPE attester=$attester_type"
fi

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
