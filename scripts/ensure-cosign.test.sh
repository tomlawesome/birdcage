#!/usr/bin/env bash
# Tests for ensure-cosign.sh. This script exists so exactly one cosign
# binary, checksum-verified, is what the signer and every verifier run --
# a check that never fails proves nothing about the checksum gate actually
# gating, so every rule ensure-cosign.sh enforces has a case here that
# proves it fires.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/ensure-cosign.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

# Deterministic, tiny fixtures standing in for the real ~140MB linux-amd64
# release binary. COSIGN_LINUX_AMD64_SHA256 below is overridden per-run to
# match one of these (the same "${VAR:-default}" pin ensure-cosign.sh
# itself uses), so the checksum logic under test is the real thing, just
# run against bytes small enough to keep this suite fast and network-free.
mkdir -p "$work/fixtures"
good_fixture="$work/fixtures/good-cosign"
bad_fixture="$work/fixtures/bad-cosign"
printf 'fixture cosign binary -- good copy\n' > "$good_fixture"
printf 'fixture cosign binary -- corrupted copy\n' > "$bad_fixture"
good_sha="$(sha256sum "$good_fixture" | awk '{print $1}')"
bad_sha="$(sha256sum "$bad_fixture" | awk '{print $1}')"

# run <install_dir> <url> -- invokes the real script exactly as a caller
# would (as a subprocess, over its real argv surface), pinned against
# $good_sha and pointed at a fixture with --url instead of the network.
# Flags, not environment variables: the pin is deliberately not settable
# from the environment, so a test that reached for one would be testing a
# door the script no longer has. Captures stdout/stderr/exit into $work.
run() {
  local install_dir="$1" url="$2" got=0
  COSIGN_INSTALL_DIR="$install_dir" \
    "$script" --sha256 "$good_sha" --url "$url" >"$work/stdout" 2>"$work/stderr" || got=$?
  return "$got"
}

ok() { echo "ok   $1"; pass=$((pass + 1)); }
fail_() {
  echo "FAIL $1"
  echo "       stdout: $(cat "$work/stdout" 2>/dev/null)"
  echo "       stderr:"; sed 's/^/         /' "$work/stderr" 2>/dev/null
  fail=$((fail + 1))
}

# --- 1: a good fixture whose checksum matches is installed and made
# executable, and the printed path resolves to it.
t1="$work/t1"
got=0; run "$t1" "file://$good_fixture" || got=$?
target="$t1/cosign"
if [ "$got" = 0 ] && [ -x "$target" ] && [ "$(sha256sum "$target" | awk '{print $1}')" = "$good_sha" ] \
   && [ "$(cat "$work/stdout")" = "$target" ]; then
  ok "a good fixture is installed, executable, and its path is printed"
else
  fail_ "a good fixture is installed, executable, and its path is printed"
fi

# --- 2: a fixture whose checksum does NOT match is rejected non-zero,
# with expected and actual in the message, and nothing left at the target.
t2="$work/t2"
got=0; run "$t2" "file://$bad_fixture" || got=$?
target="$t2/cosign"
if [ "$got" != 0 ] && [ ! -e "$target" ] \
   && grep -qF "$good_sha" "$work/stderr" && grep -qF "$bad_sha" "$work/stderr"; then
  ok "a checksum mismatch is rejected non-zero, with both hashes reported, no file left behind"
else
  fail_ "a checksum mismatch is rejected non-zero, with both hashes reported, no file left behind"
fi

# --- 3: an already-installed correct binary is not re-downloaded. Proven
# by pointing COSIGN_URL at a path that does not exist: any attempt to
# actually fetch would fail, so success here is only possible if the
# script took the skip branch.
t3="$work/t3"
mkdir -p "$t3"
cp "$good_fixture" "$t3/cosign"
chmod +x "$t3/cosign"
got=0; run "$t3" "file://$work/fixtures/does-not-exist" || got=$?
if [ "$got" = 0 ] && grep -qi "skipping download" "$work/stderr"; then
  ok "an already-installed correct binary is not re-downloaded"
else
  fail_ "an already-installed correct binary is not re-downloaded"
fi

# --- 4: an already-installed binary with the WRONG checksum is not
# silently trusted. It starts out wrong (the bad fixture, placed directly
# at the target path, bypassing the script); a good fixture is offered via
# COSIGN_URL. If the script silently trusted what was already there, it
# would never touch COSIGN_URL and the target would stay wrong. Instead it
# must replace it with the verified good copy.
t4="$work/t4"
mkdir -p "$t4"
cp "$bad_fixture" "$t4/cosign"
chmod +x "$t4/cosign"
got=0; run "$t4" "file://$good_fixture" || got=$?
target="$t4/cosign"
if [ "$got" = 0 ] && [ "$(sha256sum "$target" | awk '{print $1}')" = "$good_sha" ] \
   && ! grep -qi "skipping download" "$work/stderr"; then
  ok "an already-installed binary with the wrong checksum is not silently trusted"
else
  fail_ "an already-installed binary with the wrong checksum is not silently trusted"
fi

# --- 5: the pin cannot be weakened from the environment. This is the whole
# point of the script: on this GitLab (CE) a protected CI/CD variable is
# readable and settable outside the repository, so an environment override
# would let anyone who can set one install any cosign they liked -- into the
# binary that decides whether anything gets published. Here the environment
# offers a matching checksum for the good fixture and the script is given
# only --url, so if it honoured the environment it would install happily.
# It must ignore it and refuse against the real pin instead. No network is
# touched: --url is a local file either way.
t5="$work/t5"
mkdir -p "$t5"
got=0
COSIGN_LINUX_AMD64_SHA256="$good_sha" COSIGN_VERSION="v0.0.0-fake" COSIGN_INSTALL_DIR="$t5" \
  "$script" --url "file://$good_fixture" >"$work/stdout" 2>"$work/stderr" || got=$?
if [ "$got" != 0 ] && [ ! -e "$t5/cosign" ] && grep -q "checksum mismatch" "$work/stderr"; then
  ok "the pinned checksum cannot be overridden from the environment"
else
  fail_ "the pinned checksum cannot be overridden from the environment"
fi

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
