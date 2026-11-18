#!/usr/bin/env bash
# Tests for scripts/release-note.sh (#230): renders the GitLab release note
# from release:promote's dotenv report. Pure text in, text out: no docker,
# no registry, no network.
#
# Interface under test:
#   scripts/release-note.sh PROMOTION_ENV
#     PROMOTION_ENV is the dotenv file release:promote reports (promotion.env).
#     It holds RELEASE_TAG plus one RELEASE_<NAME>_REPO per image, NAME in
#     BIRDCAGE MOCKINGBIRD NIGHTJAR SMB_LURE HOLDER OPENCANARY (the repository
#     promoted, without tag). Prints the note to stdout and exits 0; if the
#     file is missing/unreadable, RELEASE_TAG or any *_REPO is missing or
#     empty, prints nothing on stdout, a reason on stderr, and exits non-zero.
#     Each image appears as a line "- `<repo>:<tag>`". The note contains the
#     word `preview` in backticks, never "either of them".
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/release-note.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

ok() { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; shift; [ $# -gt 0 ] && printf '%s\n' "$*" | sed 's/^/       /'; fail=$((fail + 1)); }

names="BIRDCAGE MOCKINGBIRD NIGHTJAR SMB_LURE HOLDER OPENCANARY"
tag="v0.1.0"
base="registry.example.com/ai/birdcage"

# mkenv FILE [EMPTY_NAME]: a promotion.env; EMPTY_NAME's repo is left empty,
# "TAG" empties RELEASE_TAG, "-NAME" omits that line.
mkenv() {
  local f="$1" skip="${2:-}" n lower
  {
    if [ "$skip" = TAG ]; then echo "RELEASE_TAG="; else echo "RELEASE_TAG=$tag"; fi
    echo "RELEASE_COMMIT=$(printf 'b%.0s' $(seq 40))"
    for n in $names; do
      lower="$(echo "$n" | tr 'A-Z_' 'a-z-')"
      if [ "$skip" = "-$n" ]; then continue; fi
      if [ "$skip" = "$n" ]; then echo "RELEASE_${n}_REPO="; else echo "RELEASE_${n}_REPO=$base/$lower"; fi
    done
  } > "$f"
}

run() {
  set +e
  bash "$script" "$1" > "$work/out" 2> "$work/err"
  status=$?
  set -e
}

# Missing script is itself a failure, not a skip.
if [ ! -f "$script" ]; then
  bad "scripts/release-note.sh exists"
fi

mkenv "$work/good.env"
run "$work/good.env"
if [ "$status" -eq 0 ]; then ok "good input: exit 0"; else bad "good input: exit 0" "status $status: $(cat "$work/err")"; fi

for n in $names; do
  lower="$(echo "$n" | tr 'A-Z_' 'a-z-')"
  want="- \`$base/$lower:$tag\`"
  if grep -qxF -- "$want" "$work/out"; then ok "names $lower with repo and tag"; else bad "names $lower with repo and tag" "wanted line: $want"; fi
done

lines="$(grep -c '^- `' "$work/out" || true)"
if [ "$lines" -eq 6 ]; then ok "exactly six image lines"; else bad "exactly six image lines" "got $lines"; fi

if grep -q '^- `[^`]*[^`/]/[^`]*:[^`]*`$' "$work/out" && ! grep -qE '^- `:|^- `[^`]*:`|^- `\$|^- ``' "$work/out"; then ok "no empty or unexpanded image line"; else bad "no empty or unexpanded image line" "$(cat "$work/out")"; fi

if grep -qF '`preview`' "$work/out"; then ok "preview appears with its backticks"; else bad "preview appears with its backticks" "$(cat "$work/out")"; fi
if grep -qF 'promoted from the build `preview` tested' "$work/out"; then ok "wording: promoted from the build \`preview\` tested"; else bad "wording: promoted from the build \`preview\` tested"; fi

if grep -qi 'either of them' "$work/out"; then bad 'no "either of them"'; else ok 'no "either of them"'; fi
if grep -qiE 'both carry|both of them|\bboth\b' "$work/out"; then bad 'wording fits six images (no "both")'; else ok 'wording fits six images (no "both")'; fi
if grep -qiE 'all six|each|every|all of them|all images' "$work/out"; then ok "wording refers to all the images"; else bad "wording refers to all the images" "$(cat "$work/out")"; fi

# Any one empty (or absent) image fails, with no note at all.
for n in $names; do
  for mode in "$n" "-$n"; do
    mkenv "$work/bad.env" "$mode"
    run "$work/bad.env"
    if [ "$status" -ne 0 ] && [ "$status" -ne 127 ] && [ ! -s "$work/out" ] && [ -s "$work/err" ]; then ok "refused, no note: $mode"; else bad "refused, no note: $mode" "status $status out: $(cat "$work/out")"; fi
  done
done

mkenv "$work/notag.env" TAG
run "$work/notag.env"
if [ "$status" -ne 0 ] && [ "$status" -ne 127 ] && [ ! -s "$work/out" ]; then ok "empty RELEASE_TAG refused, no note"; else bad "empty RELEASE_TAG refused, no note" "status $status"; fi

run "$work/does-not-exist.env"
if [ "$status" -ne 0 ] && [ "$status" -ne 127 ] && [ ! -s "$work/out" ]; then ok "missing file refused, no note"; else bad "missing file refused, no note" "status $status"; fi

set +e
bash "$script" > /dev/null 2>&1
status=$?
set -e
if [ "$status" -ne 0 ] && [ "$status" -ne 127 ]; then ok "no argument: refused"; else bad "no argument: refused"; fi

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
