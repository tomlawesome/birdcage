#!/usr/bin/env bash
# Tests for no-real-names.py (#192, SEC-5), then the real run over this tree.
# Fixtures use an invented word and a throwaway key; the real words are only
# ever keyed hashes (HMAC-SHA256) and the real key is never read by a fixture.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
guard="$here/no-real-names.py"
work="$(mktemp -d /tmp/no-real-names-test.XXXXXX)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

# Fixture key: 32 random bytes in a scratch file, never the real key.
key="$work/key"
head -c 32 /dev/urandom > "$key"
# Remember the caller's real key setting for the final real-tree run, then point
# every fixture run at the fixture key through the environment (the CI route).
orig_key_file="${NO_REAL_NAMES_KEY_FILE-}"
export NO_REAL_NAMES_KEY_FILE="$key"
hmac() { # hmac <keyfile> <word>: keyed hash of the lowercase word, as the guard computes it
  python3 -I -c 'import hmac,hashlib,sys; print(hmac.new(open(sys.argv[1],"rb").read(), sys.argv[2].encode(), hashlib.sha256).hexdigest())' "$1" "$2"
}
h="$(hmac "$key" zanzibar)"
printf 'hmac-sha256\n%s\n' "$h" > "$work/hashes"
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
# a hashes file with no format header is a config error
printf '%s\n' "$h" > "$work/nohdr"
run 2 "hashes file without the hmac-sha256 header exits 2" --root "$repo" --hashes "$work/nohdr"
run 2 "missing hashes file exits 2" --root "$repo" --hashes "$work/absent"
if echo "$out" | grep -q Traceback; then echo "FAIL missing hashes file prints a traceback"; fail=$((fail+1)); else echo "ok   missing hashes file prints no traceback"; pass=$((pass+1)); fi
if [ -n "$out" ]; then echo "ok   missing hashes file gives a message"; pass=$((pass+1)); else echo "FAIL missing hashes file gives no message"; fail=$((fail+1)); fi

# --- SEC-5: keyed hashing (HMAC-SHA256), key from a file, never argv ---
# The clean repo must not report clean for a config error, so use the repo
# that holds a hit: if the guard wrongly ignored the error it would exit 1.
cleanrepo="$work/cleanrepo"; mkdir "$cleanrepo"
git -C "$cleanrepo" init -q
echo 'nothing personal here' > "$cleanrepo/clean.txt"; git -C "$cleanrepo" add -A

no_tb() { # no_tb <name>: $out holds no traceback, no argparse usage error, and some message
  if echo "$out" | grep -q '^usage:'; then echo "FAIL $1 is an argument-parsing error, not a config error"; fail=$((fail+1)); else echo "ok   $1 is not an argument-parsing error"; pass=$((pass+1)); fi
  if echo "$out" | grep -q Traceback; then echo "FAIL $1 prints a traceback"; fail=$((fail+1)); else echo "ok   $1 prints no traceback"; pass=$((pass+1)); fi
  if [ -n "$out" ]; then echo "ok   $1 gives a message"; pass=$((pass+1)); else echo "FAIL $1 gives no message"; fail=$((fail+1)); fi
}
key_msg() { # key_msg <name>: the message says the key is the problem
  if echo "$out" | grep -qi 'key'; then echo "ok   $1 message mentions the key"; pass=$((pass+1)); else echo "FAIL $1 message does not mention the key"; echo "$out" | sed 's/^/       /'; fail=$((fail+1)); fi
}
not_clean() { # not_clean <name>: $out does not claim the tree is clean
  if echo "$out" | grep -qi 'clean'; then echo "FAIL $1 reports clean"; echo "$out" | sed 's/^/       /'; fail=$((fail+1)); else echo "ok   $1 does not report clean"; pass=$((pass+1)); fi
}

# the old salted format is refused as a config error, not read as an empty list
salt=fixture-salt
oldh="$(printf '%s' "${salt}zanzibar" | sha256sum | cut -d' ' -f1)"
printf 'salt: %s\n%s\n' "$salt" "$oldh" > "$work/oldhashes"
run 2 "old salted hashes file exits 2" --root "$cleanrepo" --hashes "$work/oldhashes"
no_tb "old salted hashes file"; not_clean "old salted hashes file"
# ... even over a tree that holds the word, which must not pass silently either
run 2 "old salted hashes file exits 2 over a tree holding the word" --root "$hrepo" --hashes "$work/oldhashes"
not_clean "old salted hashes file over a tree holding the word"

# a missing key is a config error that fails closed (env unset, default absent)
nokey() { # nokey <want> <name> <args...>: no key from the env or the default path
  local want="$1" name="$2" got=0; shift 2
  out="$(env -u NO_REAL_NAMES_KEY_FILE HOME="$work/emptyhome" python3 "$guard" --hashes "$work/hashes" --allow "$work/allow" "$@" 2>&1)" || got=$?
  if [ "$got" = "$want" ]; then echo "ok   $name"; pass=$((pass+1))
  else echo "FAIL $name: exit $got, want $want"; echo "$out" | sed 's/^/       /'; fail=$((fail+1)); fi
}
mkdir "$work/emptyhome"
nokey 2 "no key anywhere (env unset, default absent) exits 2" --root "$cleanrepo"
no_tb "missing default key"; not_clean "missing default key"
key_msg "missing default key"
run 2 "--key-file naming an absent file exits 2" --key-file "$work/absent-key" --root "$cleanrepo"
no_tb "absent --key-file"; not_clean "absent --key-file"; key_msg "absent --key-file"
out="$(env NO_REAL_NAMES_KEY_FILE="$work/absent-key" HOME="$work/emptyhome" python3 "$guard" --hashes "$work/hashes" --allow "$work/allow" --root "$cleanrepo" 2>&1)" && got=0 || got=$?
if [ "$got" = 2 ]; then echo "ok   NO_REAL_NAMES_KEY_FILE naming an absent file exits 2"; pass=$((pass+1)); else echo "FAIL NO_REAL_NAMES_KEY_FILE naming an absent file: exit $got, want 2"; fail=$((fail+1)); fi
no_tb "absent NO_REAL_NAMES_KEY_FILE"; not_clean "absent NO_REAL_NAMES_KEY_FILE"; key_msg "absent NO_REAL_NAMES_KEY_FILE"

# the key is found through the environment variable too, and --key-file wins
printf 'written by zanzibar\n' > "$repo/envhit.txt"; track
out="$(env HOME="$work/emptyhome" python3 "$guard" --hashes "$work/hashes" --allow "$work/allow" --root "$repo" 2>&1)" && got=0 || got=$?
if [ "$got" = 1 ]; then echo "ok   key read from NO_REAL_NAMES_KEY_FILE"; pass=$((pass+1)); else echo "FAIL key read from NO_REAL_NAMES_KEY_FILE: exit $got, want 1"; fail=$((fail+1)); fi
out="$(env NO_REAL_NAMES_KEY_FILE="$work/absent-key" HOME="$work/emptyhome" python3 "$guard" --key-file "$key" --hashes "$work/hashes" --allow "$work/allow" --root "$repo" 2>&1)" && got=0 || got=$?
if [ "$got" = 1 ]; then echo "ok   --key-file takes precedence over the environment"; pass=$((pass+1)); else echo "FAIL --key-file takes precedence over the environment: exit $got, want 1"; fail=$((fail+1)); fi
git -C "$repo" rm -qf envhit.txt

# key dependence: a hash made under a different key does not match
key2="$work/key2"; head -c 32 /dev/urandom > "$key2"
h2="$(hmac "$key2" zanzibar)"
printf 'hmac-sha256\n%s\n' "$h2" > "$work/hashes-key2"
printf 'written by zanzibar\n' > "$repo/keydep.txt"; track
run 0 "a hash made under another key does not match" --root "$repo" --hashes "$work/hashes-key2"
run 1 "the same file matches under the right key" --root "$repo" --hashes "$work/hashes"
run 1 "a hash made under key 2 matches when key 2 is supplied" --key-file "$key2" --root "$repo" --hashes "$work/hashes-key2"
git -C "$repo" rm -qf keydep.txt

# a plain or salted digest of the word, put under the new header, does not match
plain="$(printf '%s' zanzibar | sha256sum | cut -d' ' -f1)"
printf 'hmac-sha256\n%s\n' "$plain" > "$work/hashes-plain"
printf 'written by zanzibar\n' > "$repo/plain.txt"; track
run 0 "a plain sha256 of the word does not match under the hmac header" --root "$repo" --hashes "$work/hashes-plain"
git -C "$repo" rm -qf plain.txt

# the key is never echoed: use a printable key so a leak is greppable
pkey="$work/pkey"; printf '%s' 'zebrafjordkey0123456789abcdefXY' > "$pkey"
ph="$(hmac "$pkey" zanzibar)"
printf 'hmac-sha256\n%s\n' "$ph" > "$work/hashes-p"
printf 'written by zanzibar\n' > "$repo/leak.txt"; track
leaked=0
leak_check() { # leak_check <label>: $out holds neither the key text nor its hex
  if echo "$out" | grep -q 'zebrafjordkey' || echo "$out" | grep -qi "$(printf '%s' 'zebrafjordkey0123456789abcdefXY' | od -An -tx1 | tr -d ' \n')"; then
    echo "FAIL $1 output echoes the key"; fail=$((fail+1)); leaked=1; fi
}
run 1 "hit run with a printable key" --key-file "$pkey" --root "$repo" --hashes "$work/hashes-p"; leak_check "hit run"
run 0 "clean run with a printable key" --key-file "$pkey" --root "$cleanrepo" --hashes "$work/hashes-p"; leak_check "clean run"
run 2 "old-format file with a printable key" --key-file "$pkey" --root "$cleanrepo" --hashes "$work/oldhashes"; no_tb "old-format run with --key-file"; leak_check "old-format run"
run 1 "history run with a printable key" --key-file "$pkey" --root "$hrepo" --hashes "$work/hashes-p" --history; leak_check "history run"
[ "$leaked" = 0 ] && { echo "ok   the key is never echoed in output"; pass=$((pass+1)); }
git -C "$repo" rm -qf leak.txt

# --- --add: reads the word from stdin, prints only a keyed hash, never argv ---
add_out="$(printf 'zanzibar\n' | python3 "$guard" --key-file "$key" --add 2>&1)" && got=0 || got=$?
if [ "$got" = 0 ]; then echo "ok   --add reads a word from stdin and exits 0"; pass=$((pass+1)); else echo "FAIL --add from stdin: exit $got, want 0"; echo "$add_out" | sed 's/^/       /'; fail=$((fail+1)); fi
if printf '%s\n' "$add_out" | grep -Eq '^[0-9a-f]{64}$' && [ "$(printf '%s\n' "$add_out" | wc -l)" = 1 ]; then
  echo "ok   --add emits exactly one 64-hex line"; pass=$((pass+1))
else echo "FAIL --add output is not exactly one 64-hex line"; echo "$add_out" | sed 's/^/       /'; fail=$((fail+1)); fi
if [ "$add_out" = "$h" ]; then echo "ok   --add output is the keyed hash of the word"; pass=$((pass+1)); else echo "FAIL --add output differs from the keyed hash of the word"; fail=$((fail+1)); fi
if echo "$add_out" | grep -qi zanzibar; then echo "FAIL --add output echoes the word"; fail=$((fail+1)); else echo "ok   --add output omits the word"; pass=$((pass+1)); fi
# a word on argv is refused: non-zero, no hash printed, no traceback
for argv_form in "--add zanzibar" "--add=zanzibar"; do
  got=0
  # shellcheck disable=SC2086
  add_out="$(printf 'other\n' | python3 "$guard" --key-file "$key" $argv_form 2>&1)" || got=$?
  if [ "$got" != 0 ]; then echo "ok   '$argv_form' is rejected (exit $got)"; pass=$((pass+1)); else echo "FAIL '$argv_form' was accepted"; fail=$((fail+1)); fi
  if echo "$add_out" | grep -Eq '[0-9a-f]{64}'; then echo "FAIL '$argv_form' printed a hash"; fail=$((fail+1)); else echo "ok   '$argv_form' prints no hash"; pass=$((pass+1)); fi
  if echo "$add_out" | grep -q Traceback; then echo "FAIL '$argv_form' prints a traceback"; fail=$((fail+1)); else echo "ok   '$argv_form' prints no traceback"; pass=$((pass+1)); fi
done
# --add with no key is a config error, not a hash under an empty key
add_out="$(printf 'zanzibar\n' | env -u NO_REAL_NAMES_KEY_FILE HOME="$work/emptyhome" python3 "$guard" --add 2>&1)" && got=0 || got=$?
if [ "$got" = 2 ] && ! echo "$add_out" | grep -Eq '[0-9a-f]{64}' && ! echo "$add_out" | grep -q Traceback \
   && ! echo "$add_out" | grep -q '^usage:' && echo "$add_out" | grep -qi key; then
  echo "ok   --add with no key exits 2 and prints no hash"; pass=$((pass+1))
else echo "FAIL --add with no key: exit $got"; echo "$add_out" | sed 's/^/       /'; fail=$((fail+1)); fi

echo "fixtures: $pass passed, $fail failed"
[ "$fail" = 0 ] || exit 1

# --- real tree: needs the real key (CI supplies it as NO_REAL_NAMES_KEY_FILE) ---
echo "--- real tree ---"
if [ -n "$orig_key_file" ]; then export NO_REAL_NAMES_KEY_FILE="$orig_key_file"; else unset NO_REAL_NAMES_KEY_FILE; fi
real_key="${NO_REAL_NAMES_KEY_FILE:-$HOME/.config/birdcage/no-real-names.key}"
if [ ! -f "$real_key" ]; then
  echo "FAIL real tree: no key. Set NO_REAL_NAMES_KEY_FILE to the key file" >&2
  echo "     (CI: the masked file variable) or create ~/.config/birdcage/no-real-names.key." >&2
  echo "     Failing closed: the real list cannot be checked without the key." >&2
  exit 1
fi
python3 "$guard"
