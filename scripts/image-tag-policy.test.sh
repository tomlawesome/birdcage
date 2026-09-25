#!/usr/bin/env bash
# Tests for image-tag-policy.sh -- the one allow-list of image tag names the
# release path may create, move or mirror. Runs the real script as a
# program; the per-script suites (publish-image, publish-channel,
# promote-release, mirror-image) prove each caller actually consults it.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/image-tag-policy.sh"
pass=0; fail=0

ok() { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; shift; [ $# -gt 0 ] && printf '%s\n' "$*" | sed 's/^/       /'; fail=$((fail + 1)); }

run() { out="$("$script" "$@" 2>&1)" && got=0 || got=$?; }

assert_allowed() { # assert_allowed <name> <args...>
  local name="$1"; shift
  run "$@"
  if [ "$got" = 0 ]; then ok "$name"; else bad "$name" "exit $got, want 0; output=[$out]"; fi
}

assert_refused() { # assert_refused <name> <args...>
  local name="$1"; shift
  run "$@"
  if [ "$got" = 1 ] && [[ "$out" == *refused* || "$out" == *usage* || "$out" == *unknown* ]]; then
    ok "$name"
  else
    bad "$name" "exit $got, want 1 with a reason; output=[$out]"
  fi
}

gitlab="registry.gitlab.tomlawson.io/ai/birdcage/birdcage"
ghcr="ghcr.io/tomlawesome/birdcage"
sha40="$(printf 'a%.0s' $(seq 40))"
hex64="$(printf 'b%.0s' $(seq 64))"

# --- every allowed shape passes on both registries --------------------------
for repo in "$gitlab" "$ghcr"; do
  for tag in v0.1.0 v10.20.30 preview latest "sha-${sha40}"; do
    assert_allowed "$tag is allowed on ${repo%%/*}" "$repo" "$tag"
  done
done

# --- ci- transport tags: GitLab registry only -------------------------------
assert_allowed "ci-1234 is allowed on the GitLab registry" "$gitlab" ci-1234
assert_allowed "ci-x is allowed on the GitLab registry" "$gitlab" ci-x
assert_refused "ci-x is refused on GHCR" "$ghcr" ci-x
assert_refused "ci-1234 is refused on any other registry" "registry.example.com/a/b" ci-1234
assert_refused "a bare ci- with nothing after it is refused" "$gitlab" ci-

# --- cosign attestation objects: only when the caller opts in ---------------
assert_allowed "sha256-<hex>.att is allowed with --cosign-attestation" "$ghcr" "sha256-${hex64}.att" --cosign-attestation
assert_refused "sha256-<hex>.att is refused without --cosign-attestation" "$ghcr" "sha256-${hex64}.att"
assert_refused "sha256-<hex>.sig is refused even with --cosign-attestation" "$ghcr" "sha256-${hex64}.sig" --cosign-attestation
assert_refused "sha256-<short hex>.att is refused" "$ghcr" "sha256-abc.att" --cosign-attestation

# --- representative bad names are refused -----------------------------------
for tag in v0.1.0-beta v0.1.0-rc.1 v1.2 V1.2.3 0.1.0 v0.1.0+abc v1.2.3.4 \
           sha-abc123 "sha-$(printf 'A%.0s' $(seq 40))" "sha-${sha40}0" \
           preview2 latest-foo Preview dev main ""; do
  assert_refused "'$tag' is refused" "$gitlab" "$tag"
done

# --- usage -------------------------------------------------------------------
assert_refused "an unknown third argument is refused" "$gitlab" preview --nope
assert_refused "one argument is a usage error" "$gitlab"

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
