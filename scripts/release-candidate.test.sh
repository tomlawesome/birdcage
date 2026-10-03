#!/usr/bin/env bash
# Tests for release-candidate.sh. No registry here: a fake `docker` on
# PATH answers "a build exists" for the shas listed in $work/built, and a
# scratch repository supplies the merge shapes `main` can have.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/release-candidate.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

ok() { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; shift; [ $# -gt 0 ] && printf '%s\n' "$*" | sed 's/^/       /'; fail=$((fail + 1)); }

mkdir -p "$work/bin"
cat > "$work/bin/docker" <<'EOF'
#!/bin/sh
# docker buildx imagetools inspect <repo>:sha-<commit>
sha="${4##*:sha-}"
grep -qx "$sha" "$BUILT"
EOF
chmod +x "$work/bin/docker"
export BUILT="$work/built"
export PATH="$work/bin:$PATH"

repo="$work/repo"
git init -q "$repo"
g() { git -C "$repo" -c user.email=t@example.invalid -c user.name=t "$@"; }
g commit -q --allow-empty -m p1
p1="$(g rev-parse HEAD)"
g checkout -q -b preview
g commit -q --allow-empty -m p2
p2="$(g rev-parse HEAD)"
g checkout -q -b side "$p1"
g commit -q --allow-empty -m p3
p3="$(g rev-parse HEAD)"

# run <built shas...> -- prints the script's stdout; status in $status.
run() {
  : > "$BUILT"
  for s in "$@"; do echo "$s" >> "$BUILT"; done
  set +e
  out="$(cd "$repo" && sh "$script" registry.example/birdcage 2>"$work/err")"
  status=$?
  set -e
}

g checkout -q -B main "$p2"
run "$p1" "$p2"
if [ "$status" -eq 0 ] && [ "$out" = "$p2" ]; then ok "fast-forward: HEAD itself"; else bad "fast-forward: HEAD itself" "status $status out $out"; fi

g checkout -q -B main "$p1"
g merge -q --no-ff -m merge preview
m="$(g rev-parse HEAD)"
run "$p1" "$p2"
if [ "$status" -eq 0 ] && [ "$out" = "$p2" ]; then ok "merge: the merged-in parent, not main's previous tip"; else bad "merge: the merged-in parent, not main's previous tip" "status $status out $out (p1 $p1, p2 $p2)"; fi

run "$p1"
if [ "$status" -ne 0 ] && grep -q "no validated build" "$work/err" && grep -q "$m $p2" "$work/err"; then ok "merge: main's previous tip alone is refused"; else bad "merge: main's previous tip alone is refused" "status $status out $out err $(cat "$work/err")"; fi

g checkout -q -B main "$p1"
g merge -q --no-ff -m octopus preview side 2>/dev/null
run "$p2"
if [ "$status" -eq 0 ] && [ "$out" = "$p2" ]; then ok "octopus: the one parent with a build"; else bad "octopus: the one parent with a build" "status $status out $out"; fi

run "$p2" "$p3"
if [ "$status" -ne 0 ] && grep -q "more than one" "$work/err"; then ok "octopus: two with a build is refused"; else bad "octopus: two with a build is refused" "status $status out $out"; fi

set +e
sh "$script" >/dev/null 2>&1
status=$?
set -e
if [ "$status" -eq 2 ]; then ok "no repository: usage"; else bad "no repository: usage" "status $status"; fi

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
