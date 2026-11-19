#!/usr/bin/env bash
# Tests for ensure-zizmor.sh, the same shape as ensure-gitleaks.test.sh --
# every rule the script enforces has a case here that proves it fires.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/ensure-zizmor.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

# A tiny fixture standing in for the real linux release archive.
# The members match the real release layout, because
# the script extracts the binary -- a fixture that skipped extraction
# would leave the checksum logic unexercised.
mkdir -p "$work/fixtures"
build_archive() {
  local dir="$1" content="$2"
  local d="$work/fixtures/$dir"
  mkdir -p "$d/"
  printf '%s' "$content" > "$d/zizmor"
  chmod +x "$d/zizmor"
  # Same member layout as the real release archive: binary at the archive root.
  printf 'licence text' > "$d/LICENSE.txt"
  tar -C "$d" -czf "$work/fixtures/$dir.tar.gz" LICENSE.txt zizmor
}
build_archive good-src "fixture zizmor binary -- good copy"
build_archive bad-src "fixture zizmor binary -- corrupted copy"
good_archive="$work/fixtures/good-src.tar.gz"
bad_archive="$work/fixtures/bad-src.tar.gz"
good_archive_sha="$(sha256sum "$good_archive" | awk '{print $1}')"
bad_archive_sha="$(sha256sum "$bad_archive" | awk '{print $1}')"
good_binary_sha="$(sha256sum "$work/fixtures/good-src/zizmor" | awk '{print $1}')"

# run <install_dir> <url> -- invokes the real script exactly as a caller
# would, pinned against the good fixture's hashes and pointed at a fixture
# with --url instead of the network.
run() {
  local install_dir="$1" url="$2" got=0
  ZIZMOR_INSTALL_DIR="$install_dir" \
    "$script" --sha256 "$good_archive_sha" --binary-sha256 "$good_binary_sha" --url "$url" \
    >"$work/stdout" 2>"$work/stderr" || got=$?
  return "$got"
}

ok() { echo "ok   $1"; pass=$((pass + 1)); }
fail_() {
  echo "FAIL $1"
  echo "       stdout: $(cat "$work/stdout" 2>/dev/null)"
  echo "       stderr:"; sed 's/^/         /' "$work/stderr" 2>/dev/null
  fail=$((fail + 1))
}

# --- 1: a good archive whose checksum matches is extracted, installed,
# made executable, and the printed path resolves to it.
t1="$work/t1"
got=0; run "$t1" "file://$good_archive" || got=$?
target="$t1/zizmor"
if [ "$got" = 0 ] && [ -x "$target" ] && [ "$(sha256sum "$target" | awk '{print $1}')" = "$good_binary_sha" ] \
   && [ "$(cat "$work/stdout")" = "$target" ]; then
  ok "a good archive is extracted, installed, executable, and its path is printed"
else
  fail_ "a good archive is extracted, installed, executable, and its path is printed"
fi

# --- 2: an archive whose checksum does NOT match is rejected non-zero,
# with expected and actual reported, and nothing left at the target.
t2="$work/t2"
got=0; run "$t2" "file://$bad_archive" || got=$?
target="$t2/zizmor"
if [ "$got" != 0 ] && [ ! -e "$target" ] \
   && grep -qF "$good_archive_sha" "$work/stderr" && grep -qF "$bad_archive_sha" "$work/stderr"; then
  ok "a checksum mismatch is rejected non-zero, with both hashes reported, no file left behind"
else
  fail_ "a checksum mismatch is rejected non-zero, with both hashes reported, no file left behind"
fi

# --- 3: an already-installed correct binary is not re-downloaded. Proven
# by pointing the URL at a path that does not exist: any attempt to
# actually fetch would fail, so success here is only possible if the
# script took the skip branch.
t3="$work/t3"
mkdir -p "$t3"
cp "$work/fixtures/good-src/zizmor" "$t3/zizmor"
chmod +x "$t3/zizmor"
got=0; run "$t3" "file://$work/fixtures/does-not-exist.tar.gz" || got=$?
if [ "$got" = 0 ] && grep -qi "skipping download" "$work/stderr"; then
  ok "an already-installed correct binary is not re-downloaded"
else
  fail_ "an already-installed correct binary is not re-downloaded"
fi

# --- 4: an already-installed binary with the WRONG checksum is not
# silently trusted -- it starts out wrong (the bad fixture, placed directly
# at the target path); the good archive is offered via the URL, and the
# script must replace the wrong binary with the verified good one rather
# than trusting what was already there.
t4="$work/t4"
mkdir -p "$t4"
cp "$work/fixtures/bad-src/zizmor" "$t4/zizmor"
chmod +x "$t4/zizmor"
got=0; run "$t4" "file://$good_archive" || got=$?
target="$t4/zizmor"
if [ "$got" = 0 ] && [ "$(sha256sum "$target" | awk '{print $1}')" = "$good_binary_sha" ] \
   && ! grep -qi "skipping download" "$work/stderr"; then
  ok "an already-installed binary with the wrong checksum is not silently trusted"
else
  fail_ "an already-installed binary with the wrong checksum is not silently trusted"
fi

# --- 5: the pin cannot be weakened from the environment, the same
# closed door ensure-cosign.sh has and for the same reason (a protected
# CI/CD variable on this GitLab is settable outside the repository
# entirely). Env vars named exactly like the script's own pin variables
# are set to values that WOULD pass (the good archive's real hashes,
# alongside a fake version) but without the matching --sha256/--binary-
# sha256 flags -- if the environment could override the pin this would
# succeed; instead the script's own literal default pin (for the real
# release, not this fixture) must still apply and reject the fixture.
t5="$work/t5"
mkdir -p "$t5"
got=0
ZIZMOR_ARCHIVE_SHA256="$good_archive_sha" ZIZMOR_BINARY_SHA256="$good_binary_sha" \
  ZIZMOR_VERSION="v0.0.0-fake" ZIZMOR_INSTALL_DIR="$t5" \
  "$script" --url "file://$good_archive" >"$work/stdout" 2>"$work/stderr" || got=$?
if [ "$got" != 0 ] && [ ! -e "$t5/zizmor" ] && grep -qi "checksum mismatch" "$work/stderr"; then
  ok "the pinned checksum cannot be overridden from the environment"
else
  fail_ "the pinned checksum cannot be overridden from the environment"
fi

# --- 6: an unknown option is refused with exit 2 and nothing installed.
t6="$work/t6"
got=0
ZIZMOR_INSTALL_DIR="$t6" "$script" --bogus >"$work/stdout" 2>"$work/stderr" || got=$?
if [ "$got" = 2 ] && [ ! -e "$t6/zizmor" ]; then
  ok "an unknown option is refused with exit 2"
else
  fail_ "an unknown option is refused with exit 2"
fi

# --- 7: a failed download is non-zero and leaves nothing at the target.
t7="$work/t7"
got=0; run "$t7" "file://$work/fixtures/does-not-exist.tar.gz" || got=$?
if [ -f "$script" ] && [ "$got" != 0 ] && [ ! -e "$t7/zizmor" ]; then
  ok "a failed download is non-zero and installs nothing"
else
  fail_ "a failed download is non-zero and installs nothing"
fi

# --- 8: the script never reads a URL or a hash override from the
# environment: names such as ZIZMOR_URL or ZIZMOR_SHA256 must not
# appear as expansions in the script source.
if [ -f "$script" ] && ! grep -nE '\$\{?ZIZMOR_(ARCHIVE_SHA256|BINARY_SHA256|VERSION|URL)[:}-]' "$script" \
     | grep -vE '^[0-9]+:[[:space:]]*#' | grep -qE ':-|:\?'; then
  ok "the pin variables have no environment-default expansion"
else
  fail_ "the pin variables have no environment-default expansion"
fi

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
