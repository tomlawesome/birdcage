#!/usr/bin/env bash
# Tests for publish-channel.sh. No Docker daemon and no registry are
# available in this environment, so these tests never call docker or the
# real verifier: they source the script (its sourcing guard keeps main()
# from running on import), override run_verifier/create_channel_tag/
# resolve_tag_digest -- the only three functions that touch anything
# external -- with recording stubs, and drive main() for real over
# everything else: argument validation, BIRDCAGE_COMMIT handling, wiring
# into the verifier, and the create-then-reresolve sequence.
#
# The most important behaviour here is that each of the verifier's four
# refusal codes (10/11/12/13) comes back out of this script unchanged, and
# that a refusal stops before the tag is ever touched -- so those get their
# own named assertions rather than being folded into one loop.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/publish-channel.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

ok() { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; shift; [ $# -gt 0 ] && printf '%s\n' "$*" | sed 's/^/       /'; fail=$((fail + 1)); }

# shellcheck source=/dev/null
source "$script"

repo="registry.gitlab.tomlawson.io/ai/birdcage/birdcage"
digest="sha256:$(printf 'a%.0s' $(seq 64))"
other_digest="sha256:$(printf 'e%.0s' $(seq 64))"
commit="$(printf 'b%.0s' $(seq 40))"
tag="preview"

# Stub configuration, read by the stubs below each time main() calls them.
STUB_VERIFIER_RC=0
STUB_CREATE_RC=0
STUB_RESOLVE_RC=0
STUB_RESOLVE_DIGEST="$digest"

# Each stub drops a marker file (a "was this called" fact that survives the
# command-substitution subshell main() runs in below) and records the
# arguments it was called with, so tests can assert both call/no-call and
# correct wiring.
run_verifier() {
  : > "$work/run_verifier.called"
  printf '%s\x1f%s\x1f%s\x1f%s' "$1" "$2" "$3" "$4" > "$work/run_verifier.args"
  return "$STUB_VERIFIER_RC"
}
create_channel_tag() {
  : > "$work/create_channel_tag.called"
  printf '%s\x1f%s\x1f%s' "$1" "$2" "$3" > "$work/create_channel_tag.args"
  return "$STUB_CREATE_RC"
}
resolve_tag_digest() {
  printf '%s\x1f%s' "$1" "$2" > "$work/resolve_tag_digest.args"
  [ "$STUB_RESOLVE_RC" = 0 ] || return "$STUB_RESOLVE_RC"
  printf '%s' "$STUB_RESOLVE_DIGEST"
}

reset_stubs() {
  STUB_VERIFIER_RC=0
  STUB_CREATE_RC=0
  STUB_RESOLVE_RC=0
  STUB_RESOLVE_DIGEST="$digest"
  rm -f "$work"/*.called "$work"/*.args
}

# run <args...> -- invokes main() with a valid BIRDCAGE_COMMIT and, unless
# RUN_REF is set, an empty BIRDCAGE_REF (which main() treats the same as
# unset). Always setting it, rather than conditionally including the
# assignment word, sidesteps a real bash trap: an assignment word is only
# recognised as such when it is literally "name=value" in the source, not
# when a parameter expansion happens to produce that text -- the expanded
# form is instead run as a command. Runs in a subshell (command
# substitution) so main()'s `exit`, taken on every path, never kills the
# test runner.
run() {
  local got=0 out
  out="$(BIRDCAGE_COMMIT="${RUN_COMMIT-$commit}" BIRDCAGE_REF="${RUN_REF-}" main "$@" 2>&1)" || got=$?
  printf '%s\x1f%s' "$got" "$out"
}

result() { result_got="${1%%$'\x1f'*}"; result_out="${1#*$'\x1f'}"; }

# --- happy path -----------------------------------------------------------
reset_stubs
result "$(run "$repo" "$digest" "$tag")"
if [ "$result_got" = 0 ] && [ -f "$work/create_channel_tag.called" ]; then
  ok "a valid publish with an accepting verifier succeeds"
else
  bad "a valid publish with an accepting verifier succeeds" "exit $result_got: $result_out"
fi

# --- verifier wiring: called with image, digest, commit, ref --------------
reset_stubs
RUN_REF="some-branch"
result "$(run "$repo" "$digest" "$tag")"
unset RUN_REF
if [ "$(cat "$work/run_verifier.args")" = "${repo}"$'\x1f'"${digest}"$'\x1f'"${commit}"$'\x1f'"some-branch" ]; then
  ok "the verifier is called with the repository, digest, commit and ref"
else
  bad "the verifier is called with the repository, digest, commit and ref" "$(cat "$work/run_verifier.args" 2>/dev/null)"
fi

# --- verifier refusal codes propagate unchanged ---------------------------
for code in 10 11 12 13; do
  reset_stubs
  STUB_VERIFIER_RC="$code"
  result "$(run "$repo" "$digest" "$tag")"
  if [ "$result_got" = "$code" ]; then
    ok "verifier exit $code is propagated unchanged"
  else
    bad "verifier exit $code is propagated unchanged" "exit $result_got: $result_out"
  fi
done

# --- a refusal stops before the tag is ever touched -----------------------
reset_stubs
STUB_VERIFIER_RC=11
result "$(run "$repo" "$digest" "$tag")"
if [ ! -f "$work/create_channel_tag.called" ]; then
  ok "the channel tag is not created when the verifier refuses"
else
  bad "the channel tag is not created when the verifier refuses" "create_channel_tag was called"
fi

# --- argument count -------------------------------------------------------
reset_stubs
result "$(run "$repo" "$digest")"
[ "$result_got" != 0 ] && ok "too few arguments is refused" || bad "too few arguments is refused" "exit $result_got: $result_out"

reset_stubs
result "$(run "$repo" "$digest" "$tag" "extra")"
[ "$result_got" != 0 ] && ok "too many arguments is refused" || bad "too many arguments is refused" "exit $result_got: $result_out"

# --- repository shape ------------------------------------------------------
reset_stubs
result "$(run "${repo}:othertag" "$digest" "$tag")"
[ "$result_got" != 0 ] && ok "a repository carrying a tag is refused" || bad "a repository carrying a tag is refused" "exit $result_got: $result_out"

reset_stubs
result "$(run "${repo}@${digest}" "$digest" "$tag")"
[ "$result_got" != 0 ] && ok "a repository carrying a digest is refused" || bad "a repository carrying a digest is refused" "exit $result_got: $result_out"

# --- malformed digest -------------------------------------------------------
reset_stubs
result "$(run "$repo" "sha256:not-hex" "$tag")"
[ "$result_got" != 0 ] && ok "a malformed digest is refused" || bad "a malformed digest is refused" "exit $result_got: $result_out"

# --- malformed channel tag --------------------------------------------------
reset_stubs
result "$(run "$repo" "$digest" ".starts-with-dot")"
[ "$result_got" != 0 ] && ok "a channel tag starting with '.' is refused" || bad "a channel tag starting with '.' is refused" "exit $result_got: $result_out"

reset_stubs
too_long="$(printf 'a%.0s' $(seq 129))"
result "$(run "$repo" "$digest" "$too_long")"
[ "$result_got" != 0 ] && ok "a channel tag over 128 characters is refused" || bad "a channel tag over 128 characters is refused" "exit $result_got: $result_out"

# --- BIRDCAGE_COMMIT ---------------------------------------------------------
reset_stubs
got=0
out="$(main "$repo" "$digest" "$tag" 2>&1)" || got=$?
[ "$got" != 0 ] && ok "a missing BIRDCAGE_COMMIT is refused" || bad "a missing BIRDCAGE_COMMIT is refused" "exit $got: $out"

reset_stubs
RUN_COMMIT="not-hex"
result "$(run "$repo" "$digest" "$tag")"
unset RUN_COMMIT
[ "$result_got" != 0 ] && ok "a malformed BIRDCAGE_COMMIT is refused" || bad "a malformed BIRDCAGE_COMMIT is refused" "exit $result_got: $result_out"

# --- tag creation fails ------------------------------------------------------
reset_stubs
STUB_CREATE_RC=1
result "$(run "$repo" "$digest" "$tag")"
if [ "$result_got" = 2 ]; then
  ok "a failing tag creation call exits 2"
else
  bad "a failing tag creation call exits 2" "exit $result_got: $result_out"
fi

# --- tag resolves to a different digest -------------------------------------
reset_stubs
STUB_RESOLVE_DIGEST="$other_digest"
result "$(run "$repo" "$digest" "$tag")"
if [ "$result_got" = 2 ]; then
  ok "a tag that resolves to a different digest afterwards exits 2"
else
  bad "a tag that resolves to a different digest afterwards exits 2" "exit $result_got: $result_out"
fi

# --- tag fails to resolve at all --------------------------------------------
reset_stubs
STUB_RESOLVE_RC=1
result "$(run "$repo" "$digest" "$tag")"
if [ "$result_got" = 2 ]; then
  ok "a tag that fails to resolve at all afterwards exits 2"
else
  bad "a tag that fails to resolve at all afterwards exits 2" "exit $result_got: $result_out"
fi

# --- tag allow-list (scripts/image-tag-policy.sh) ---------------------------
# Every allowed shape reaches the verifier; every refused one stops before
# the verifier or the registry is touched.
sha40="$(printf 'c%.0s' $(seq 40))"
for allowed in v0.1.0 preview latest "sha-${sha40}" ci-1234; do
  reset_stubs
  result "$(run "$repo" "$digest" "$allowed")"
  if [ "$result_got" = 0 ] && [ -f "$work/create_channel_tag.called" ]; then
    ok "allowed tag '$allowed' is published"
  else
    bad "allowed tag '$allowed' is published" "exit $result_got: $result_out"
  fi
done

refuse_tag() { # refuse_tag <name> <repo> <tag>
  reset_stubs
  result "$(run "$2" "$digest" "$3")"
  if [ "$result_got" = 1 ] && [ ! -f "$work/run_verifier.called" ] && [ ! -f "$work/create_channel_tag.called" ]; then
    ok "$1"
  else
    bad "$1" "exit $result_got (want 1, nothing touched): $result_out"
  fi
}
for refused in v0.1.0-beta v1.2 V1.2.3 0.1.0 sha-abc123 "sha-$(printf 'C%.0s' $(seq 40))" \
               preview2 latest-foo "sha256-$(printf 'd%.0s' $(seq 64)).att" ""; do
  refuse_tag "tag '$refused' is refused before anything is touched" "$repo" "$refused"
done
refuse_tag "a ci- tag is refused on GHCR" "ghcr.io/tomlawesome/birdcage" ci-x

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
