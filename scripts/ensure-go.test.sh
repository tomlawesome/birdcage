#!/usr/bin/env bash
# Tests for ensure-go.sh, the same shape as ensure-gitleaks.test.sh -- every
# rule the script enforces has a case here that proves it fires. Never
# touches the network: every case points --url at a local file:// fixture.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/ensure-go.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

# A tiny fixture standing in for the real ~70MB linux-amd64 release
# archive. It must actually be a tar.gz containing go/VERSION (whose first
# line is the version string the script checks) and go/bin/go, because the
# script extracts the whole "go" tree -- a fixture that skipped either
# member would leave that logic unexercised.
mkdir -p "$work/fixtures"
build_archive() {
  local dir="$1" version="$2"
  local d="$work/fixtures/$dir/go"
  mkdir -p "$d/bin"
  printf '%s\n' "$version" > "$d/VERSION"
  printf '%s\n' "fixture go binary for $dir" > "$d/bin/go"
  chmod +x "$d/bin/go"
  tar -C "$work/fixtures/$dir" -czf "$work/fixtures/$dir.tar.gz" go
}
build_archive good-src "go1.27.1"
build_archive other-src "go1.27.1"
good_archive="$work/fixtures/good-src.tar.gz"
good_archive_sha="$(sha256sum "$good_archive" | awk '{print $1}')"
# A second archive with the *same pinned checksum flag value on purpose is
# not needed -- "bad" here just means "does not match the good archive's
# real hash", proven by re-using the good hash against a different archive.
bad_archive="$work/fixtures/other-src.tar.gz"

ok() { echo "ok   $1"; pass=$((pass + 1)); }
fail_() {
  echo "FAIL $1"
  echo "       stdout: $(cat "$work/stdout" 2>/dev/null)"
  echo "       stderr:"; sed 's/^/         /' "$work/stderr" 2>/dev/null
  fail=$((fail + 1))
}

# run <install_parent_dir> <url> [extra args...] -- invokes the real script
# exactly as a caller would, pinned against the good fixture's version and
# checksum unless overridden, and pointed at a fixture with --url instead
# of the network.
run() {
  local install_dir="$1" url="$2" got=0
  shift 2
  "$script" --version "go1.27.1" --sha256 "$good_archive_sha" --url "$url" "$@" "$install_dir" \
    >"$work/stdout" 2>"$work/stderr" || got=$?
  return "$got"
}

# --- 1: a good archive whose checksum matches is extracted, installed,
# and the printed path resolves to the go binary inside it.
t1="$work/t1"
got=0; run "$t1" "file://$good_archive" || got=$?
target="$t1/go"
if [ "$got" = 0 ] && [ -x "$target/bin/go" ] && [ "$(cat "$target/VERSION")" = "go1.27.1" ] \
   && [ "$(cat "$work/stdout")" = "$target/bin/go" ]; then
  ok "a good archive is extracted, installed, and its go binary path is printed"
else
  fail_ "a good archive is extracted, installed, and its go binary path is printed"
fi

# --- 2: an archive whose checksum does NOT match the pinned value is
# rejected non-zero, with expected and actual reported, and nothing left
# at the target.
t2="$work/t2"
got=0; run "$t2" "file://$bad_archive" || got=$?
target="$t2/go"
bad_archive_sha="$(sha256sum "$bad_archive" | awk '{print $1}')"
if [ "$got" != 0 ] && [ ! -e "$target" ] \
   && grep -qF "$good_archive_sha" "$work/stderr" && grep -qF "$bad_archive_sha" "$work/stderr"; then
  ok "a checksum mismatch is rejected non-zero, with both hashes reported, no directory left behind"
else
  fail_ "a checksum mismatch is rejected non-zero, with both hashes reported, no directory left behind"
fi

# --- 3: an already-installed matching version is not re-downloaded.
# Proven by pointing the URL at a path that does not exist: any attempt to
# actually fetch would fail, so success here is only possible if the
# script took the skip branch.
t3="$work/t3"
mkdir -p "$t3/go/bin"
printf '%s\n' "go1.27.1" > "$t3/go/VERSION"
printf '%s\n' "pre-existing go binary" > "$t3/go/bin/go"
chmod +x "$t3/go/bin/go"
got=0; run "$t3" "file://$work/fixtures/does-not-exist.tar.gz" || got=$?
if [ "$got" = 0 ] && grep -qi "skipping download" "$work/stderr" \
   && [ "$(cat "$work/stdout")" = "$t3/go/bin/go" ]; then
  ok "an already-installed matching version is not re-downloaded"
else
  fail_ "an already-installed matching version is not re-downloaded"
fi

# --- 4: an already-installed directory with a DIFFERENT version is not
# silently trusted and not overwritten -- it starts out at a different
# version (pre-existing go/VERSION says go1.26.0); the script must refuse
# rather than delete or replace what is there.
t4="$work/t4"
mkdir -p "$t4/go/bin"
printf '%s\n' "go1.26.0" > "$t4/go/VERSION"
printf '%s\n' "pre-existing go binary" > "$t4/go/bin/go"
chmod +x "$t4/go/bin/go"
got=0; run "$t4" "file://$good_archive" || got=$?
if [ "$got" != 0 ] && [ "$(cat "$t4/go/VERSION")" = "go1.26.0" ] \
   && grep -qi "go1.27.1" "$work/stderr" && grep -qi "go1.26.0" "$work/stderr"; then
  ok "an already-installed different version is refused, not overwritten"
else
  fail_ "an already-installed different version is refused, not overwritten"
fi

# --- 5: an unknown flag is a usage error (exit 2), not a silent no-op.
t5="$work/t5"
got=0
"$script" --bogus-flag "$t5" >"$work/stdout" 2>"$work/stderr" || got=$?
if [ "$got" = 2 ]; then
  ok "an unknown flag exits 2"
else
  fail_ "an unknown flag exits 2"
fi

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
