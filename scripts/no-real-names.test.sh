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

# --- history mode: every blob reachable from any ref, not just the tree ---
run() { # run <want> <name> <args...>; sets $out
  local want="$1" name="$2" got=0; shift 2
  out="$(python3 "$guard" --hashes "$work/hashes" --allow "$work/allow" "$@" 2>&1)" || got=$?
  if [ "$got" = "$want" ]; then echo "ok   $name"; pass=$((pass+1))
  else echo "FAIL $name: exit $got, want $want"; echo "$out" | sed 's/^/       /'; fail=$((fail+1)); fi
}
hrepo="$work/hist"; mkdir "$hrepo"
git -C "$hrepo" init -q
git -C "$hrepo" config user.email t@example.invalid; git -C "$hrepo" config user.name t
echo 'nothing personal' > "$hrepo/a.txt"; git -C "$hrepo" add -A; git -C "$hrepo" commit -qm one
run 0 "history mode: clean history passes" --root "$hrepo" --history
echo 'written by zanzibar' > "$hrepo/old.txt"; git -C "$hrepo" add -A; git -C "$hrepo" commit -qm two
git -C "$hrepo" branch side
git -C "$hrepo" rm -qf old.txt; git -C "$hrepo" commit -qm three
run 0 "tree mode ignores a word already removed from the tree" --root "$hrepo"
run 1 "history mode finds a word removed in a later commit" --root "$hrepo" --history
if echo "$out" | grep -qi zanzibar; then echo "FAIL history output leaks the word"; fail=$((fail+1)); else echo "ok   history output omits the word"; pass=$((pass+1)); fi
if echo "$out" | grep -q 'old.txt'; then echo "ok   history output names the path"; pass=$((pass+1)); else echo "FAIL history output lacks path"; fail=$((fail+1)); fi

# a blob first committed at an allowlisted path, then the same content at an
# ordinary path: the blob is one object, but the second path must be reported
arepo="$work/histallow"; mkdir "$arepo"
git -C "$arepo" init -q
git -C "$arepo" config user.email t@example.invalid; git -C "$arepo" config user.name t
echo 'Copyright zanzibar' > "$arepo/ALLOWED.txt"; git -C "$arepo" add -A; git -C "$arepo" commit -qm one
run 0 "history mode: a word only at an allowlisted path passes" --root "$arepo" --history
echo 'Copyright zanzibar' > "$arepo/ordinary.txt"; git -C "$arepo" add -A; git -C "$arepo" commit -qm two
run 1 "history mode: same content later added at an ordinary path is reported" --root "$arepo" --history
if echo "$out" | grep -q 'ordinary.txt'; then echo "ok   history output names the ordinary path"; pass=$((pass+1)); else echo "FAIL history output lacks the ordinary path"; fail=$((fail+1)); fi

# a submodule entry is not a file and must not count as an oversize skip
srepo="$work/sub"; mkdir "$srepo"
git -C "$srepo" init -q
git -C "$srepo" config user.email t@example.invalid; git -C "$srepo" config user.name t
echo 'nothing personal' > "$srepo/a.txt"; git -C "$srepo" add -A; git -C "$srepo" commit -qm one
git -C "$srepo" update-index --add --cacheinfo 160000,1111111111111111111111111111111111111111,vendor/mod
git -C "$srepo" commit -qm sub
run 0 "tree mode: a submodule entry passes" --root "$srepo"
if echo "$out" | grep -q skipped; then echo "FAIL tree mode counts a submodule as an oversize skip"; fail=$((fail+1)); else echo "ok   tree mode: submodule is not an oversize skip"; pass=$((pass+1)); fi
run 0 "history mode: a submodule entry passes" --root "$srepo" --history
if echo "$out" | grep -q skipped; then echo "FAIL history mode counts a submodule as an oversize skip"; fail=$((fail+1)); else echo "ok   history mode: submodule is not an oversize skip"; pass=$((pass+1)); fi

# --- config errors exit 2 ---
printf '%s\n' "$h" > "$work/nosalt"
run 2 "missing salt line exits 2" --root "$repo" --hashes "$work/nosalt"
run 2 "missing hashes file exits 2" --root "$repo" --hashes "$work/absent"
if echo "$out" | grep -q Traceback; then echo "FAIL missing hashes file prints a traceback"; fail=$((fail+1)); else echo "ok   missing hashes file prints no traceback"; pass=$((pass+1)); fi
if [ -n "$out" ]; then echo "ok   missing hashes file gives a message"; pass=$((pass+1)); else echo "FAIL missing hashes file gives no message"; fail=$((fail+1)); fi

echo "fixtures: $pass passed, $fail failed"
[ "$fail" = 0 ] || exit 1

echo "--- real tree ---"
python3 "$guard"
