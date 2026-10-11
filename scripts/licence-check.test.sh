#!/usr/bin/env bash
# Tests for licence-check.sh, the Go licence gate. A guard that cannot fail
# guards nothing, so every rule it enforces has a case here that proves it
# fires.
#
# Hermetic: `go` and `go-licenses` are stubs on PATH that replay fixture
# files, so nothing is installed, fetched or compiled. The stub go-licenses
# also answers `check` the way the real one does, so this suite can be run
# against an older licence-check.sh to show which cases it got wrong.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
checker="$here/licence-check.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

stubs="$work/bin"
mkdir -p "$stubs"

# go: `install` does nothing, `env GOROOT` names a fake root, `list` replays
# $FAKE_MODULES (one "<module> <version>" per line). Every call's arguments
# are appended to $FAKE_ARGS_LOG.
cat > "$stubs/go" <<'EOF'
#!/usr/bin/env bash
echo "go $*" >> "$FAKE_ARGS_LOG"
case "${1:-}" in
  install) exit 0 ;;
  env) echo /fake/goroot ;;
  list) cat "$FAKE_MODULES"; exit "${FAKE_LIST_EXIT:-0}" ;;
  *) echo "stub go: unexpected: $*" >&2; exit 2 ;;
esac
EOF

# go-licenses: `report` replays $FAKE_REPORT (go-licenses' CSV:
# library,url,licence). `check` applies --allowed_licenses to the same
# rows, as the real tool does.
cat > "$stubs/go-licenses" <<'EOF'
#!/usr/bin/env bash
echo "go-licenses $*" >> "$FAKE_ARGS_LOG"
case "${1:-}" in
  report) cat "$FAKE_REPORT"; exit "${FAKE_REPORT_EXIT:-0}" ;;
  check)
    allowed=""
    for a in "$@"; do
      case "$a" in --allowed_licenses=*) allowed=",${a#*=}," ;; esac
    done
    bad=0
    while IFS=, read -r lib _url lic; do
      [ -n "$lib" ] || continue
      case "$allowed" in
        *",$lic,"*) ;;
        *) echo "Not allowed license '$lic' found for library '$lib'." >&2; bad=1 ;;
      esac
    done < "$FAKE_REPORT"
    exit "$bad" ;;
  *) echo "stub go-licenses: unexpected: $*" >&2; exit 2 ;;
esac
EOF
chmod +x "$stubs/go" "$stubs/go-licenses"

# run <policy> <report> <modules> -> sets $got and $out
run() {
  got=0
  out="$(PATH="$stubs:$PATH" POLICY_FILE="$1" FAKE_REPORT="$2" \
    FAKE_MODULES="$3" FAKE_ARGS_LOG="$work/args.log" "$checker" 2>&1)" || got=$?
}

# expect <want-exit> <name> <policy> <report> <modules> [must-contain]
expect() {
  local want="$1" name="$2" needle="${6:-}"
  : > "$work/args.log"
  run "$3" "$4" "$5"
  if [ "$got" = "$want" ] && { [ -z "$needle" ] || printf '%s' "$out" | grep -qF -- "$needle"; }; then
    echo "ok   $name"; pass=$((pass + 1))
  else
    echo "FAIL $name: exit $got, want $want${needle:+, or missing '$needle'}"
    echo "$out" | sed 's/^/       /'
    fail=$((fail + 1))
  fi
}

# policy <file> <exception-lines...>: allow-licenses BSD-3-Clause and MIT,
# plus the given allow-go-module-licenses entries.
policy() {
  local f="$1"; shift
  {
    echo 'allow-licenses:'
    echo '  - BSD-3-Clause'
    echo '  - MIT'
    echo
    if [ "$#" -gt 0 ]; then
      echo 'allow-go-module-licenses:'
      for e in "$@"; do
        echo "  - $e"
        echo '  # reason for the entry'
      done
    fi
  } > "$f"
}

modules="$work/modules.txt"
printf '%s\n' \
  'github.com/example/mit v1.0.0' \
  'github.com/example/bsd v2.3.4' \
  'github.com/example/apache v0.9.8' \
  'github.com/example/x v0.3.1' > "$modules"

clean_report="$work/clean.csv"
printf '%s\n' \
  'github.com/example/mit,https://example.test/LICENSE,MIT' \
  'github.com/example/bsd/sub,https://example.test/LICENSE,BSD-3-Clause' > "$clean_report"

apache_report="$work/apache.csv"
cat "$clean_report" > "$apache_report"
echo 'github.com/example/apache,https://example.test/LICENSE,Apache-2.0' >> "$apache_report"

# A library below its module's root, with a licence of its own.
sub_report="$work/sub.csv"
cat "$clean_report" > "$sub_report"
echo 'github.com/example/x/revoke,https://example.test/revoke/LICENSE,BSD-2-Clause' >> "$sub_report"

p="$work/plain.yml"; policy "$p"
expect 0 "only allowed licences passes" "$p" "$clean_report" "$modules"
grep -qF -- "--ignore github.com/tomlawesome/birdcage" "$work/args.log" \
  && { echo "ok   birdcage's own module is still ignored"; pass=$((pass + 1)); } \
  || { echo "FAIL birdcage's own module is no longer ignored"; cat "$work/args.log"; fail=$((fail + 1)); }

expect 1 "a licence outside allow-licenses with no entry fails" \
  "$p" "$apache_report" "$modules" "github.com/example/apache"

p="$work/exc.yml"; policy "$p" 'github.com/example/apache@v0.9.8 Apache-2.0'
expect 0 "an exact library@version licence entry lets it through" \
  "$p" "$apache_report" "$modules" "github.com/example/apache@v0.9.8"

p="$work/exc-sub.yml"; policy "$p" 'github.com/example/x/revoke@v0.3.1 BSD-2-Clause'
expect 0 "an entry for a library below its module root takes the module's version" \
  "$p" "$sub_report" "$modules"

p="$work/exc-oldver.yml"; policy "$p" 'github.com/example/apache@v0.9.7 Apache-2.0'
expect 1 "the same library at a different version fails" \
  "$p" "$apache_report" "$modules" "github.com/example/apache"

p="$work/exc-otherlic.yml"; policy "$p" 'github.com/example/apache@v0.9.8 ISC'
expect 1 "an entry whose licence differs from the report fails" \
  "$p" "$apache_report" "$modules" "github.com/example/apache"

p="$work/exc-module.yml"; policy "$p" 'github.com/example/x@v0.3.1 BSD-2-Clause'
expect 1 "an entry naming the module, not the library, does not cover the library" \
  "$p" "$sub_report" "$modules" "github.com/example/x/revoke"

p="$work/exc-stale.yml"; policy "$p" \
  'github.com/example/apache@v0.9.8 Apache-2.0' \
  'github.com/example/gone@v1.0.0 ISC'
expect 1 "an entry matching no library is stale and fails" \
  "$p" "$apache_report" "$modules" "github.com/example/gone@v1.0.0"

p="$work/exc-redundant.yml"; policy "$p" 'github.com/example/mit@v1.0.0 MIT'
expect 1 "an entry for a library allow-licenses already passes is stale and fails" \
  "$p" "$clean_report" "$modules" "github.com/example/mit@v1.0.0"

p="$work/exc-bad.yml"; policy "$p" 'github.com/example/apache Apache-2.0'
expect 1 "an entry without @version fails" "$p" "$apache_report" "$modules"

p="$work/plain.yml"
empty="$work/empty.csv"; : > "$empty"
expect 1 "an empty go-licenses report fails" "$p" "$empty" "$modules"

expect 1 "an empty module list fails" "$p" "$clean_report" "$empty"

nomod="$work/nomod.csv"
cat "$clean_report" > "$nomod"
echo 'github.com/elsewhere/thing,https://example.test/LICENSE,MIT' >> "$nomod"
expect 1 "a library with no module in the build list fails" \
  "$p" "$nomod" "$modules" "github.com/elsewhere/thing"

short="$work/short.csv"
cat "$clean_report" > "$short"
echo 'github.com/example/mit' >> "$short"
expect 1 "a malformed report row fails" "$p" "$short" "$modules"

: > "$work/args.log"
got=0
out="$(PATH="$stubs:$PATH" POLICY_FILE="$p" FAKE_REPORT="$clean_report" \
  FAKE_REPORT_EXIT=1 FAKE_MODULES="$modules" FAKE_ARGS_LOG="$work/args.log" \
  "$checker" 2>&1)" || got=$?
if [ "$got" != 0 ]; then echo "ok   go-licenses report failing fails the gate"; pass=$((pass + 1))
else echo "FAIL go-licenses report failing passed the gate"; echo "$out" | sed 's/^/       /'; fail=$((fail + 1)); fi

np="$work/no-allow.yml"
printf '%s\n' 'allow-licenses: []' > "$np"
expect 1 "an empty allow-licenses list refuses to run" "$np" "$clean_report" "$modules"

# The real policy's entries must all be well formed and the general list
# must stay exactly BSD-3-Clause and MIT (owner, #8 answer 7a).
real="$here/../supply-chain/licence-policy.yml"
general="$(awk '/^allow-licenses:/{f=1;next} /^[^[:space:]]/{f=0} f&&/^[[:space:]]*-/{sub(/^[[:space:]]*-[[:space:]]*/,"");print}' "$real" | paste -sd, -)"
if [ "$general" = "BSD-3-Clause,MIT" ]; then echo "ok   the real allow-licenses is exactly BSD-3-Clause, MIT"; pass=$((pass + 1))
else echo "FAIL the real allow-licenses is '$general'"; fail=$((fail + 1)); fi

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
