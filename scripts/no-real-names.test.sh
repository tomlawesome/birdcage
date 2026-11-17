#!/usr/bin/env bash
# Tests for no-real-names.py (#192), then the real run over this tree.
# Fixtures use an invented word; the real words are only ever hashes.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
guard="$here/no-real-names.py"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

salt=fixture-salt
h="$(printf '%s' "${salt}zanzibar" | sha256sum | cut -d' ' -f1)"
printf 'salt: %s\n%s\n' "$salt" "$h" > "$work/hashes"
printf '^ALLOWED\\.txt$\n' > "$work/allow"
repo="$work/repo"; mkdir "$repo"
git -C "$repo" init -q
git -C "$repo" config user.email t@example.invalid; git -C "$repo" config user.name t

expect() { # want name
  local want="$1" name="$2" got=0 out
  out="$(python3 "$guard" --root "$repo" --hashes "$work/hashes" --allow "$work/allow" 2>&1)" || got=$?
  if [ "$got" = "$want" ]; then echo "ok   $name"; pass=$((pass+1))
  else echo "FAIL $name: exit $got, want $want"; echo "$out" | sed 's/^/       /'; fail=$((fail+1)); fi
}
track() { git -C "$repo" add -A; }

echo 'nothing personal here' > "$repo/clean.txt"; track
expect 0 "clean file passes"

echo 'written by Zanzibar, 2026' > "$repo/hit.txt"; track
expect 1 "file with a hashed word fails (case-insensitive)"
out="$(python3 "$guard" --root "$repo" --hashes "$work/hashes" --allow "$work/allow" 2>&1 || true)"
if echo "$out" | grep -qi zanzibar; then echo "FAIL output leaks the word"; fail=$((fail+1)); else echo "ok   output omits the word"; pass=$((pass+1)); fi
echo "$out" | grep -q 'hit.txt' && { echo "ok   output names the path"; pass=$((pass+1)); } || { echo "FAIL output lacks path"; fail=$((fail+1)); }
git -C "$repo" rm -qf hit.txt

echo 'contact zanzibar@example.test' > "$repo/mail.txt"; track
expect 1 "word inside an email fails"
git -C "$repo" rm -qf mail.txt

echo 'x' > "$repo/zanzibar-notes.txt"; track
expect 1 "word in a path fails"
git -C "$repo" rm -qf zanzibar-notes.txt

echo 'Copyright zanzibar' > "$repo/ALLOWED.txt"; track
expect 0 "allowlisted path passes"

echo 'Copyright zanzibar' > "$repo/NOTALLOWED.txt"; track
expect 1 "near-miss path is not allowlisted"
git -C "$repo" rm -qf NOTALLOWED.txt

printf 'zanzibar\0\1\2' > "$repo/blob.bin"; track
expect 0 "binary file is skipped"
printf 'zanzibar v1\n' > "$repo/go.sum"; track
expect 0 "lockfile is skipped"

echo "fixtures: $pass passed, $fail failed"
[ "$fail" = 0 ] || exit 1

echo "--- real tree ---"
python3 "$guard"
