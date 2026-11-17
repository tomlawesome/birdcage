#!/usr/bin/env bash
# The one shared verifier (issue #90, following orbit's ADR-0020): every job
# that gives a validated digest a consumer-visible name -- a preview tag, a
# promotion to a version tag, a copy to another registry -- runs this first,
# and refuses, with a DISTINCT message and exit code per ground, when the
# digest's validation evidence does not check out. The evidence is the
# cosign key-based attestation minted by scripts/attest-tested-image.sh at
# the moment the digest first existed; this script verifies it with the
# committed public key and then judges what it says.
#
# NO CALLER RE-IMPLEMENTS ANY OF THIS. If a publishing job finds itself
# writing its own digest/commit/ref/policy comparison, or its own evidence
# age check, that is drift from this file, not a shortcut -- call this
# script instead.
#
# The four grounds, their exit codes, and what each names:
#
#   mismatch  (exit 10)  The evidence is verifiable but describes something
#                        other than what is being published: another
#                        digest, another commit, another ref, or a policy
#                        version that is no longer current (a digest
#                        validated under older rules must not ship under
#                        newer ones).
#   missing   (exit 11)  No attestation of the expected type verifies with
#                        the committed public key over this digest -- or
#                        cosign could not resolve the digest at all.
#   ambiguous (exit 12)  Verified attestations disagree about what was
#                        validated. Two records identical except
#                        recordedAt are one item of evidence (a retried
#                        attesting job), newest governing expiry; any
#                        disagreement on (imageDigest, commit, ref,
#                        pipelineId, policyVersion) is a conflict this
#                        script refuses to pick a winner from.
#   expired   (exit 13)  The newest evidence is older than seven days, or
#                        is stamped in the future beyond plausible clock
#                        skew (five minutes).
#
# Exit 0 only when evidence is present, singular-or-agreeing, current, and
# matches. Anything else non-zero and not one of the four codes above (1/2)
# is misconfiguration -- missing inputs, missing public key -- named
# plainly, never silently treated as a pass: this gate fails closed.
#
# Inputs (environment):
#   BIRDCAGE_IMAGE          Image repository without tag or digest, e.g.
#                           ${CI_REGISTRY_IMAGE}/birdcage.
#   BIRDCAGE_DIGEST         The digest about to be given a name,
#                           "sha256:<64 hex>".
#   BIRDCAGE_COMMIT         The commit the publisher is acting for (40 hex).
#   BIRDCAGE_REF            Optional; when set, evidence for another ref is
#                           a mismatch.
#   BIRDCAGE_POLICY_VERSION Optional; the policy version this checkout
#                           carries. Computed by scripts/policy-version.sh
#                           when unset -- callers normally leave it unset
#                           so the recomputation is from their own checkout.
#   COSIGN_PUBLIC_KEY       Optional; path to the committed public key,
#                           default cosign.pub at the repository root.
#   BIRDCAGE_MAX_EVIDENCE_AGE_DAYS  Optional; default 7.
#   LEGACY_PREDICATE_TYPES_FILE  Optional; default
#                           scripts/legacy-predicate-types.sha256. Earlier
#                           predicate types still accepted for evidence
#                           already published, listed as the sha256 of each
#                           type string (one hex per line, # comments). A
#                           listed type is never written to output.
#   BIRDCAGE_COSIGN         Optional; the cosign command to run, overridable
#                           only so tests can stub it. Real use resolves the
#                           pinned binary via scripts/ensure-cosign.sh.
#
# Registry credentials are ambient: cosign reads the same Docker config the
# caller's `docker login` wrote. This script needs read access only.
#
# fetch_verified_attestations, below, is the one function that touches the
# registry; scripts/verify-validation-evidence.test.sh replaces it with a
# fixture writer, so every refusal ground is proved against fixture JSON,
# never a real registry.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"

# Must match scripts/attest-tested-image.sh; scripts/verify-validation-evidence.test.sh
# asserts the two agree.
readonly PREDICATE_TYPE="https://github.com/tomlawesome/birdcage/attestations/birdcage-validation/v1"

legacy_types_file() { printf '%s' "${LEGACY_PREDICATE_TYPES_FILE:-${here}/legacy-predicate-types.sha256}"; }

# Cleaned up on any exit, including a refuse()-triggered one; declared here
# (not `local` inside a function) so the trap can always find it.
verified_file=""
trap 'rm -f "${verified_file}"' EXIT

fail() { printf 'verify-validation-evidence: %s\n' "$1" >&2; exit 2; }
refuse() { # $1 ground, $2 exit code, $3 message
  printf 'verify-validation-evidence: refused (%s): %s\n' "$1" "$3" >&2
  exit "$2"
}

# fetch_verified_attestations <subject> <outfile> -- the one call that needs
# a reachable registry: asks cosign to verify every attestation of
# PREDICATE_TYPE attached to <subject> against the committed public key,
# and write the verified DSSE envelopes (one JSON object per line) to
# <outfile>. A non-zero return means cosign found nothing it could verify --
# an unresolvable digest, no attestation at all, or one under another key --
# and the caller treats all of those the same way: missing evidence.
#
# --insecure-ignore-tlog because these attestations are minted without a
# transparency log: key-based trust, no Rekor to consult.
#
# Legacy types (LEGACY_PREDICATE_TYPES_FILE) are known only by hash, so they
# are found by downloading the attestations unverified, hashing each
# predicate type, and verifying, by --type, only those that are listed. The
# download is a discovery step only: nothing it returns is trusted, and
# legacy type strings are never echoed.
fetch_verified_attestations() {
  local subject="$1" outfile="$2" found=1 t
  if "$cosign_cmd" verify-attestation \
    --key "$public_key" \
    --type "$PREDICATE_TYPE" \
    --insecure-ignore-tlog=true \
    "$subject" > "$outfile" 2>"${outfile}.err"; then
    found=0
  fi
  local hashes
  hashes="$(sed 's/#.*//' "$(legacy_types_file)" 2>/dev/null | tr -d ' \t' | grep -x '[0-9a-f]\{64\}' || true)"
  [ -n "$hashes" ] || return "$found"
  # The unverified download is bounded in time and size: at most
  # ATTESTATION_DOWNLOAD_TIMEOUT seconds, and anything over
  # ATTESTATION_DOWNLOAD_MAX_BYTES is refused rather than parsed. A refused
  # download ends legacy discovery only; the current type's result stands.
  local dl="${outfile}.download" max="${ATTESTATION_DOWNLOAD_MAX_BYTES:-10485760}"
  local limit="${ATTESTATION_DOWNLOAD_TIMEOUT:-300}"
  # 0 would mean no limit to timeout(1); only a positive whole number counts.
  case "$limit" in ''|*[!0-9]*) limit=300 ;; esac
  [ "$((10#$limit))" -ge 1 ] || limit=300
  timeout "$limit" \
    "$cosign_cmd" download attestation "$subject" 2>/dev/null \
    | head -c "$((max + 1))" > "$dl" || true
  if [ "$(wc -c < "$dl")" -gt "$max" ]; then
    rm -f "$dl"
    echo "attestation download for $subject is too large (over $((max / 1048576)) MB); legacy types not checked" >&2
    return "$found"
  fi
  local listed
  listed="$(python3 -c '
import base64, hashlib, json, sys
wanted = set(sys.argv[1].split())
seen = set()
for line in sys.stdin:
    try:
        t = json.loads(base64.b64decode(json.loads(line)["payload"]))["predicateType"]
    except Exception:
        continue
    if isinstance(t, str) and "\n" not in t and t not in seen \
            and hashlib.sha256(t.encode()).hexdigest() in wanted:
        seen.add(t)
        print(t)
' "$hashes" < "$dl" || true)"
  rm -f "$dl"
  while IFS= read -r t; do
    [ -n "$t" ] || continue
    if "$cosign_cmd" verify-attestation \
      --key "$public_key" \
      --type "$t" \
      --insecure-ignore-tlog=true \
      "$subject" >> "$outfile" 2>/dev/null; then
      found=0
    fi
  done <<< "$listed"
  return "$found"
}

# judge_evidence <verified-file> <expected-digest> <expected-commit>
#                <expected-ref-or-empty> <expected-policy-version>
#                <max-age-days>
# Pure decision logic over already-verified DSSE envelopes: no registry, no
# signing key, no network. This is what
# scripts/verify-validation-evidence.test.sh drives directly with fixture
# files to prove each of the four refusal grounds, the retried-job case, and
# the boundary either side of seven days.
judge_evidence() {
  local verified_file="$1" expected_digest="$2" expected_commit="$3" \
    expected_ref="$4" expected_policy_version="$5" max_age_days="$6"
  python3 - "$verified_file" "$expected_digest" "$expected_commit" \
    "$expected_ref" "$expected_policy_version" "$max_age_days" "$PREDICATE_TYPE" \
    "$(legacy_types_file)" <<'PY'
import base64
import datetime
import hashlib
import json
import re
import sys

(verified_file, expected_digest, expected_commit, expected_ref,
 expected_policy_version, max_age_days_s, predicate_type,
 legacy_file) = sys.argv[1:9]
max_age_days = float(max_age_days_s)
expected_ref = expected_ref or None

# Earlier types, by sha256 of the exact string. A missing or unreadable list
# accepts nothing extra: the safe direction for this gate.
legacy_hashes = set()
try:
    with open(legacy_file, "r", encoding="utf-8") as fh:
        for raw in fh:
            entry = raw.split("#", 1)[0].strip()
            if re.fullmatch(r"[0-9a-f]{64}", entry):
                legacy_hashes.add(entry)
except OSError:
    pass


def accepted_type(t):
    if t == predicate_type:
        return True
    return isinstance(t, str) and hashlib.sha256(t.encode("utf-8")).hexdigest() in legacy_hashes


def refuse(ground, code, message):
    sys.stderr.write(
        "verify-validation-evidence: refused (%s): %s\n" % (ground, message))
    sys.exit(code)


try:
    with open(verified_file, "r", encoding="utf-8") as fh:
        lines = [line for line in fh.read().split("\n") if line.strip()]
except OSError as exc:
    refuse("missing", 11, "verified evidence file could not be read: %s" % exc)

statements = []
for line in lines:
    try:
        envelope = json.loads(line)
        payload = base64.b64decode(envelope["payload"])
        statement = json.loads(payload)
    except Exception:
        refuse("missing", 11,
               "a verified attestation payload is not decodable in-toto JSON; unusable as evidence")
    if not accepted_type(statement.get("predicateType")):
        continue
    statements.append(statement)

if not statements:
    refuse("missing", 11,
           "cosign verified %d attestation(s) for the digest, but none carries predicate type %s"
           % (len(lines), predicate_type))

field_patterns = {
    "commit": r"^[0-9a-f]{40}$",
    "ref": r"^[A-Za-z0-9._/-]+$",
    "imageDigest": r"^sha256:[0-9a-f]{64}$",
    "policyVersion": r"^[0-9a-f]{64}$",
    "recordedAt": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
}

items = []
for statement in statements:
    subjects = statement.get("subject") or []
    subject_digests = []
    for s in subjects:
        digest = (s or {}).get("digest") or {}
        sha = digest.get("sha256")
        if sha:
            subject_digests.append("sha256:%s" % sha)
    predicate = statement.get("predicate") or {}
    for field, pattern in field_patterns.items():
        value = predicate.get(field)
        if not isinstance(value, str) or not re.match(pattern, value):
            refuse("missing", 11,
                   "a verified attestation predicate has no well-formed %s; unusable as evidence" % field)
    pipeline_id = predicate.get("pipelineId")
    if not isinstance(pipeline_id, int) or isinstance(pipeline_id, bool):
        refuse("missing", 11,
               "a verified attestation predicate has no well-formed pipelineId; unusable as evidence")
    if not isinstance(predicate.get("pipelineUrl"), str) or not predicate.get("pipelineUrl"):
        refuse("missing", 11,
               "a verified attestation predicate has no well-formed pipelineUrl; unusable as evidence")
    items.append({"subjectDigests": subject_digests, "predicate": predicate})

# Identical claims differing only in recordedAt are one item of evidence (a
# retried attesting job); the newest stamp governs expiry. Any disagreement
# on the claim itself is a conflict nobody here may resolve.
claims = {}
for item in items:
    p = item["predicate"]
    key = (p["imageDigest"], p["commit"], p["ref"], p["pipelineId"], p["policyVersion"])
    claims.setdefault(key, []).append(p)

if len(claims) > 1:
    refuse("ambiguous", 12,
           "%d verified attestations make %d conflicting claims about what was validated "
           "(imageDigest, commit, ref, pipelineId or policyVersion differ); refusing to choose between them"
           % (len(items), len(claims)))

records = next(iter(claims.values()))
claim = records[0]

for item in items:
    if expected_digest not in item["subjectDigests"]:
        refuse("mismatch", 10,
               "a verified attestation is attached to subject %s, not the digest being published (%s)"
               % (", ".join(item["subjectDigests"]) or "<none>", expected_digest))

if claim["imageDigest"] != expected_digest:
    refuse("mismatch", 10,
           "evidence names digest %s, not the digest being published (%s)"
           % (claim["imageDigest"], expected_digest))
if claim["commit"] != expected_commit:
    refuse("mismatch", 10,
           "evidence is for commit %s, not the commit being published (%s)"
           % (claim["commit"], expected_commit))
if expected_ref is not None and claim["ref"] != expected_ref:
    refuse("mismatch", 10,
           "evidence is for ref %s, not the ref being published (%s)"
           % (claim["ref"], expected_ref))
if claim["policyVersion"] != expected_policy_version:
    refuse("mismatch", 10,
           "the policy changed since validation: evidence was judged under policy %s, "
           "this checkout carries %s; re-validate the digest"
           % (claim["policyVersion"], expected_policy_version))

newest = max(r["recordedAt"] for r in records)
newest_dt = datetime.datetime.strptime(newest, "%Y-%m-%dT%H:%M:%SZ").replace(
    tzinfo=datetime.timezone.utc)
now = datetime.datetime.now(datetime.timezone.utc)
age = now - newest_dt

if age.total_seconds() > max_age_days * 24 * 3600:
    refuse("expired", 13,
           "evidence recorded at %s is older than %s days; re-validate the digest before publishing"
           % (newest, max_age_days_s))
if age.total_seconds() < -300:
    refuse("expired", 13,
           "evidence recorded at %s is in the future; refusing evidence from a skewed clock" % newest)

summary = next(r for r in records if r["recordedAt"] == newest)
sys.stdout.write(
    "verify-validation-evidence: accepted %s: validated at commit %s on %s by pipeline %s "
    "under policy %s, recorded %s\n"
    % (expected_digest, summary["commit"], summary["ref"], summary["pipelineId"],
       summary["policyVersion"], newest))
PY
}

main() {
  : "${BIRDCAGE_IMAGE:?BIRDCAGE_IMAGE is required: the image repository the digest lives in}"
  : "${BIRDCAGE_DIGEST:?BIRDCAGE_DIGEST is required: the digest about to be published}"
  : "${BIRDCAGE_COMMIT:?BIRDCAGE_COMMIT is required: the commit being published}"

  [[ "$BIRDCAGE_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    fail "BIRDCAGE_DIGEST is not an immutable manifest digest: ${BIRDCAGE_DIGEST}"
  [[ "$BIRDCAGE_COMMIT" =~ ^[0-9a-f]{40}$ ]] ||
    fail "BIRDCAGE_COMMIT is not an exact commit SHA: ${BIRDCAGE_COMMIT}"
  [[ "$BIRDCAGE_IMAGE" =~ ^[A-Za-z0-9._-]+(:[0-9]+)?(/[A-Za-z0-9._-]+)+$ ]] ||
    fail "BIRDCAGE_IMAGE is not a plain image repository reference: ${BIRDCAGE_IMAGE}"
  [[ -z "${BIRDCAGE_REF:-}" || "$BIRDCAGE_REF" =~ ^[A-Za-z0-9._/-]+$ ]] ||
    fail "BIRDCAGE_REF is not a plain ref name: ${BIRDCAGE_REF}"

  local max_age_days="${BIRDCAGE_MAX_EVIDENCE_AGE_DAYS:-7}"
  [[ "$max_age_days" =~ ^[0-9]+$ ]] || fail "BIRDCAGE_MAX_EVIDENCE_AGE_DAYS is not a whole number: ${max_age_days}"

  public_key="${COSIGN_PUBLIC_KEY:-${repo_root}/cosign.pub}"
  [ -f "$public_key" ] ||
    fail "the validation public key is not at ${public_key}; the owner commits cosign.pub at the repository root, and without it nothing can be verified"

  local policy_version="${BIRDCAGE_POLICY_VERSION:-}"
  if [ -z "$policy_version" ]; then
    policy_version="$("$here/policy-version.sh")"
  fi
  [[ "$policy_version" =~ ^[0-9a-f]{64}$ ]] || fail "policy version is not a sha256 hex value: ${policy_version}"

  cosign_cmd="${BIRDCAGE_COSIGN:-}"
  if [ -z "$cosign_cmd" ]; then
    cosign_cmd="$("$here/ensure-cosign.sh")"
  fi

  local subject="${BIRDCAGE_IMAGE}@${BIRDCAGE_DIGEST}"
  verified_file="$(mktemp)"

  if ! fetch_verified_attestations "$subject" "$verified_file"; then
    if [ -f "${verified_file}.err" ]; then
      sed 's/^/verify-validation-evidence: cosign: /' "${verified_file}.err" >&2
      rm -f "${verified_file}.err"
    fi
    refuse missing 11 "no verifiable validation attestation of type ${PREDICATE_TYPE} for ${subject}; validation has not attested this digest under the committed key"
  fi
  rm -f "${verified_file}.err"

  judge_evidence "$verified_file" "$BIRDCAGE_DIGEST" "$BIRDCAGE_COMMIT" \
    "${BIRDCAGE_REF:-}" "$policy_version" "$max_age_days"
}

# Guard so scripts/verify-validation-evidence.test.sh can source this file --
# to call judge_evidence directly against fixture JSON, and to override
# fetch_verified_attestations -- without main running on import.
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  main "$@"
fi
