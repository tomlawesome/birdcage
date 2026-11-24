#!/usr/bin/env bash
# Tests for ensure-trivy.sh (#199 items 1-3, owner decision 66a), written from
# the specification before the script exists. Same shape as
# ensure-gitleaks.test.sh, plus the signature step: the script verifies the
# release's checksums file with cosign (obtained only through
# scripts/ensure-cosign.sh) and the tarball's line in it must equal the pin.
#
# Interface under test:
#   ensure-trivy.sh [--sha256 H] [--base-url URL] <install_dir>
# --base-url is a directory URL holding the three release files, named as the
# release names them (trivy_0.76.2_Linux-64bit.tar.gz,
# trivy_0.76.2_checksums.txt, trivy_0.76.2_checksums.txt.sigstore.json); the
# tests serve them with file://. --sha256 replaces the pinned tarball hash so
# a tiny fixture can stand in for the real archive. Prints the installed path.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
real_script="$here/ensure-trivy.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0
: > "$work/stdout"; : > "$work/stderr"

ver=0.76.2
asset="trivy_${ver}_Linux-64bit.tar.gz"
sums="trivy_${ver}_checksums.txt"
bundle="${sums}.sigstore.json"
pin_sha=bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf
identity="https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v${ver}"
issuer="https://token.actions.githubusercontent.com"

ok() { echo "ok   $1"; pass=$((pass + 1)); }
fail_() {
  echo "FAIL $1"
  echo "       stdout: $(cat "$work/stdout" 2>/dev/null)"
  echo "       stderr:"; sed 's/^/         /' "$work/stderr" 2>/dev/null
  fail=$((fail + 1))
}
check() { # name, rc (0 = pass)
  if [ "$2" -eq 0 ]; then ok "$1"; else fail_ "$1"; fi
}

# The script under test is copied next to a fake ensure-cosign.sh, so the only
# way it can reach cosign is by calling its sibling script. The fake logs that
# it was called and prints the path of a fake cosign that records its
# arguments and exits with the code in $work/cosign.rc.
sandbox="$work/scripts"
mkdir -p "$sandbox" "$work/decoy"
if [ -f "$real_script" ]; then cp "$real_script" "$sandbox/ensure-trivy.sh"; fi
cat > "$sandbox/ensure-cosign.sh" <<FAKE
#!/usr/bin/env bash
echo called >> "$work/ensure-cosign.calls"
echo "$work/fake-cosign"
FAKE
cat > "$work/fake-cosign" <<FAKE
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$work/cosign.args"
exit "\$(cat "$work/cosign.rc")"
FAKE
# A cosign on PATH that must never be used.
cat > "$work/decoy/cosign" <<FAKE
#!/usr/bin/env bash
echo used >> "$work/decoy.calls"
exit 0
FAKE
chmod +x "$sandbox"/*.sh "$work/fake-cosign" "$work/decoy/cosign"

# Release fixtures: a real tar.gz holding a file named trivy, a checksums file
# listing it, and a bundle file (content irrelevant: cosign is faked).
mk_release() { # dir, binary content, checksum-file line hash (or "-" to omit the line)
  local d="$work/rel/$1"
  mkdir -p "$d/src"
  printf '%s' "$2" > "$d/src/trivy"; chmod +x "$d/src/trivy"
  tar -C "$d/src" -czf "$d/$asset" trivy
  local h; h="$(sha256sum "$d/$asset" | awk '{print $1}')"
  { echo "0000000000000000000000000000000000000000000000000000000000000000  other_asset.tar.gz"
    [ "$3" = "-" ] || echo "${3/@/$h}  $asset"; } > "$d/$sums"
  echo '{"fixture":"bundle"}' > "$d/$bundle"
  echo "$h" > "$d/tarball.sha"
}
mk_release good "fixture trivy binary -- good" "@"
mk_release linebad "fixture trivy binary -- good" "1111111111111111111111111111111111111111111111111111111111111111"
mk_release noline "fixture trivy binary -- good" "-"
mk_release tampered "fixture trivy binary -- tampered" "@"
good_sha="$(cat "$work/rel/good/tarball.sha")"

# refused <name> <exit>: prints 0 when the script ran, failed with its own
# "ensure-trivy:" message and left nothing installed (a missing script does
# not count as a refusal).
refused() {
  if [ "$2" != 0 ] && [ ! -e "$work/$1/trivy" ] && grep -q 'ensure-trivy:' "$work/stderr"; then echo 0; else echo 1; fi
}

# run <name> <release-dir> <sha-pin> [cosign-rc] -- install into $work/<name>.
run() {
  local name="$1" rel="$2" sha="$3" rc="${4:-0}" got=0
  echo "$rc" > "$work/cosign.rc"
  : > "$work/cosign.args"; rm -f "$work/ensure-cosign.calls" "$work/decoy.calls"
  PATH="$work/decoy:$PATH" "$sandbox/ensure-trivy.sh" --sha256 "$sha" \
    --base-url "file://$work/rel/$rel" "$work/$name" >"$work/stdout" 2>"$work/stderr" || got=$?
  return "$got"
}

# --- 0: the script exists and carries the pin from the specification.
if [ -x "$real_script" ] \
   && grep -qF "$pin_sha" "$real_script" && grep -qF "$asset" "$real_script" \
   && grep -qE 'TRIVY_VERSION="v?0\.76\.2"' "$real_script" \
   && grep -qF "reusable-release.yaml@refs/tags/v" "$real_script" \
   && grep -qF "$issuer" "$real_script"; then
  ok "scripts/ensure-trivy.sh exists, is executable and carries the version, asset, hash, identity and issuer pins"
else
  fail_ "scripts/ensure-trivy.sh exists, is executable and carries the version, asset, hash, identity and issuer pins"
fi

# --- 1: a good release is verified, extracted, installed, executable, and
# its path is printed.
got=0; run t1 good "$good_sha" || got=$?
if [ "$got" = 0 ] && [ -x "$work/t1/trivy" ] && [ "$(cat "$work/stdout")" = "$work/t1/trivy" ] \
   && cmp -s "$work/t1/trivy" "$work/rel/good/src/trivy"; then
  ok "a good release is installed, executable, and its path is printed"
else
  fail_ "a good release is installed, executable, and its path is printed"
fi

# --- 2: cosign verify-blob is called on the checksums file with the bundle,
# the exact identity (not a regexp) and the GitHub issuer.
args="$(cat "$work/cosign.args" 2>/dev/null || true)"
rcx=0
{ grep -q 'verify-blob' <<<"$args" \
  && grep -qE -- "--bundle[ =][^ ]*${sums}\.sigstore\.json" <<<"$args" \
  && grep -qE -- "--certificate-identity[ =]${identity}( |\$)" <<<"$args" \
  && grep -qE -- "--certificate-oidc-issuer[ =]${issuer}( |\$)" <<<"$args" \
  && ! grep -q -- '-regexp' <<<"$args" \
  && grep -qE "${sums}\$" <<<"$args"; } || rcx=$?
check "cosign verify-blob checks the checksums file with --bundle, the exact identity and the GitHub issuer, no regexp" "$rcx"

# --- 3: cosign is obtained only through scripts/ensure-cosign.sh.
rcx=0
{ [ -s "$work/ensure-cosign.calls" ] && [ ! -e "$work/decoy.calls" ] \
  && ! grep -qE 'command -v cosign|which cosign|^\s*cosign ' "$real_script"; } || rcx=$?
check "cosign comes only from scripts/ensure-cosign.sh (a cosign on PATH is never used)" "$rcx"

# --- 4: tarball hash mismatch -> non-zero, nothing installed.
got=0; run t4 tampered "$good_sha" || got=$?
check "a tarball whose hash differs from the pin is rejected, nothing installed" \
  "$(refused t4 "$got")"

# --- 5: the checksums-file line differs from the pin -> non-zero, nothing
# installed (the tarball itself matches the pin here, so only the line
# comparison can catch it).
got=0; run t5 linebad "$(cat "$work/rel/linebad/tarball.sha")" || got=$?
check "a checksums-file line that differs from the pin is rejected, nothing installed" \
  "$(refused t5 "$got")"

# --- 6: no line for the tarball in the checksums file -> rejected.
got=0; run t6 noline "$(cat "$work/rel/noline/tarball.sha")" || got=$?
check "a checksums file without the tarball's line is rejected, nothing installed" \
  "$(refused t6 "$got")"

# --- 7: signature verification fails -> rejected, nothing installed, even
# though both hashes match.
got=0; run t7 good "$good_sha" 1 || got=$?
check "a failed cosign verification is rejected, nothing installed" \
  "$(refused t7 "$got")"

# --- 8: the pin cannot be weakened from the environment: variables named
# like the script's pins are set to passing values, but without --sha256 the
# script's own real pin applies and rejects the fixture.
echo 0 > "$work/cosign.rc"; got=0
TRIVY_VERSION="v0.0.0-fake" TRIVY_ARCHIVE_SHA256="$good_sha" TRIVY_SHA256="$good_sha" \
  TRIVY_INSTALL_DIR="$work/t8" PATH="$work/decoy:$PATH" \
  "$sandbox/ensure-trivy.sh" --base-url "file://$work/rel/good" "$work/t8" >"$work/stdout" 2>"$work/stderr" || got=$?
check "the pinned hash cannot be overridden from the environment" \
  "$(refused t8 "$got")"

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
