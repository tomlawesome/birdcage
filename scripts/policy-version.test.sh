#!/usr/bin/env bash
# Tests for policy-version.sh. A digest that cannot be shown to move when
# policy moves, or to hold still when it does not, proves nothing -- every
# claim in the script's header comment has a case here that proves it.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

# The script derives repo_root from its own location (not the caller's
# cwd), so the only way to sandbox a run -- including the "changing a byte
# changes the digest" and "missing file fails" cases -- is to give it its
# own tree to call home: a copy of the real script under a fixture
# scripts/, alongside fixture files and a fixture policy list.
fresh_fixture() {
  rm -rf "$work/repo"
  mkdir -p "$work/repo/scripts" "$work/repo/supply-chain"
  cp "$repo_root/scripts/policy-version.sh" "$work/repo/scripts/policy-version.sh"
  chmod +x "$work/repo/scripts/policy-version.sh"
  printf 'file A\n' > "$work/repo/fileA.txt"
  printf 'file B\n' > "$work/repo/fileB.txt"
  printf 'not on the list\n' > "$work/repo/unlisted.txt"
  printf '# fixture policy list\nfileA.txt\nfileB.txt\n' > "$work/repo/supply-chain/policy-files.txt"
}

sut() { "$work/repo/scripts/policy-version.sh" "$@"; }

ok() { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; shift; [ $# -gt 0 ] && echo "$*" | sed 's/^/       /'; fail=$((fail + 1)); }

is_bare_digest() {
  # $(...) already strips one trailing newline, so a clean single-line
  # digest arrives here with none left; a second, embedded newline (extra
  # output below the digest) means this was never a single line to begin
  # with.
  case "$1" in
    *$'\n'*) return 1 ;;
  esac
  printf '%s' "$1" | grep -qE '^[0-9a-f]{64}$'
}

# --- same tree twice gives the same digest -----------------------------
fresh_fixture
d1="$(sut)"; d2="$(sut)"
if [ "$d1" = "$d2" ] && is_bare_digest "$d1"; then
  ok "same tree twice gives the same digest"
else
  bad "same tree twice gives the same digest" "d1=$d1 d2=$d2"
fi

# --- output is a bare 64-char lowercase hex string, no extra output ----
fresh_fixture
out="$(sut)"
if is_bare_digest "$out"; then
  ok "output is a bare 64-character lowercase hex digest"
else
  bad "output is a bare 64-character lowercase hex digest" "got: $out"
fi

# --- changing one byte in a listed file changes the digest -------------
fresh_fixture
before="$(sut)"
printf 'file A, changed\n' > "$work/repo/fileA.txt"
after="$(sut)"
if [ "$before" != "$after" ]; then
  ok "changing one byte in a listed file changes the digest"
else
  bad "changing one byte in a listed file changes the digest" "digest unchanged: $before"
fi

# --- changing a file NOT on the list does not change the digest --------
fresh_fixture
before="$(sut)"
printf 'still not on the list, but different\n' > "$work/repo/unlisted.txt"
after="$(sut)"
if [ "$before" = "$after" ]; then
  ok "changing a file not on the list does not change the digest"
else
  bad "changing a file not on the list does not change the digest" "before=$before after=$after"
fi

# --- a missing listed file fails, non-zero, naming the file ------------
fresh_fixture
rm "$work/repo/fileA.txt"
got=0; err="$(sut 2>&1 1>/dev/null)" || got=$?
if [ "$got" != 0 ] && echo "$err" | grep -q 'fileA.txt'; then
  ok "a missing listed file fails non-zero, naming the file"
else
  bad "a missing listed file fails non-zero, naming the file" "exit=$got err=$err"
fi

# --- a listed path that is a directory, not a regular file, also fails -
fresh_fixture
rm "$work/repo/fileB.txt"
mkdir "$work/repo/fileB.txt"
got=0; err="$(sut 2>&1 1>/dev/null)" || got=$?
if [ "$got" != 0 ] && echo "$err" | grep -q 'fileB.txt'; then
  ok "a listed path that is a directory fails non-zero, naming it"
else
  bad "a listed path that is a directory fails non-zero, naming it" "exit=$got err=$err"
fi

# --- an empty or comment-only list fails non-zero ------------------------
fresh_fixture
printf '# nothing but comments\n\n   \n' > "$work/repo/alt-list.txt"
got=0; err="$(sut --list "$work/repo/alt-list.txt" 2>&1 1>/dev/null)" || got=$?
if [ "$got" != 0 ]; then
  ok "a comment-only list fails non-zero"
else
  bad "a comment-only list fails non-zero" "exit=$got"
fi

fresh_fixture
: > "$work/repo/alt-list.txt"
got=0; err="$(sut --list "$work/repo/alt-list.txt" 2>&1 1>/dev/null)" || got=$?
if [ "$got" != 0 ]; then
  ok "a fully empty list fails non-zero"
else
  bad "a fully empty list fails non-zero" "exit=$got"
fi

# --- a missing list file fails non-zero -----------------------------------
fresh_fixture
got=0; err="$(sut --list "$work/repo/does-not-exist.txt" 2>&1 1>/dev/null)" || got=$?
if [ "$got" != 0 ] && echo "$err" | grep -q 'does-not-exist.txt'; then
  ok "a missing list file fails non-zero, naming it"
else
  bad "a missing list file fails non-zero, naming it" "exit=$got err=$err"
fi

# --- reordering the lines in the list does not change the digest --------
fresh_fixture
before="$(sut)"
printf '# reordered\nfileB.txt\nfileA.txt\n' > "$work/repo/alt-list.txt"
after="$(sut --list "$work/repo/alt-list.txt")"
if [ "$before" = "$after" ]; then
  ok "reordering the lines in the list does not change the digest"
else
  bad "reordering the lines in the list does not change the digest" "before=$before after=$after"
fi

# --- the real thing must pass: this repository's own policy list -------
if out="$(cd /tmp && "$repo_root/scripts/policy-version.sh")"; then
  if is_bare_digest "$out"; then
    ok "this repository's own policy list produces a bare digest"
  else
    bad "this repository's own policy list produces a bare digest" "got: $out"
  fi
else
  bad "this repository's own policy list produces a bare digest" "script exited non-zero"
fi

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
