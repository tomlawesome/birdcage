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

# go: `install` does nothing, `env GOROOT` names a fake root, `list` renders
# $FAKE_MODULES, one module per line: "<module> <version>", "<module>
# <version> => <path> [<version>]" for a replaced one, or "main <module>"
# for the main module. It renders them as the -f template the script
# passes would: the main module only if the template lacks `if not
# .Main` (and then with no version, as go prints it), the replacement
# only if it reads .Replace. Every call's arguments are appended to
# $FAKE_ARGS_LOG.
cat > "$stubs/go" <<'EOF'
#!/usr/bin/env bash
echo "go $*" >> "$FAKE_ARGS_LOG"
case "${1:-}" in
  install) exit 0 ;;
  env) echo /fake/goroot ;;
  list)
    tmpl=""; prev=""
    for a in "$@"; do [ "$prev" = -f ] && tmpl="$a"; prev="$a"; done
    while read -r m v arrow rp rv; do
      if [ "$m" = main ]; then
        case "$tmpl" in *"if not .Main"*) ;; *) echo "$v " ;; esac
        continue
      fi
      line="$m $v"
      if [ "$arrow" = "=>" ]; then
        case "$tmpl" in *.Replace*) line="$line => $rp $rv" ;; esac
      fi
      echo "$line"
    done < "$FAKE_MODULES"
    exit "${FAKE_LIST_EXIT:-0}" ;;
  *) echo "stub go: unexpected: $*" >&2; exit 2 ;;
esac
EOF

# go-licenses: `report` replays $FAKE_REPORT (go-licenses' CSV:
# library,url,licence), leaving out rows whose library starts with an
# --ignore value, a plain string prefix as in the real tool. `check`
# applies --allowed_licenses to the same rows, as the real tool does.
cat > "$stubs/go-licenses" <<'EOF'
#!/usr/bin/env bash
echo "go-licenses $*" >> "$FAKE_ARGS_LOG"
case "${1:-}" in
  report)
    ignores=(); prev=""
    for a in "$@"; do
      [ "$prev" = --ignore ] && ignores+=("$a")
      case "$a" in --ignore=*) ignores+=("${a#*=}") ;; esac
      prev="$a"
    done
    while IFS= read -r row; do
      for i in "${ignores[@]}"; do
        case "$row" in "$i"*) continue 2 ;; esac
      done
      printf '%s\n' "$row"
    done < "$FAKE_REPORT"
    exit "${FAKE_REPORT_EXIT:-0}" ;;
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

# run <policy> <report> <modules> -> sets $got and $out. Extra stub
# settings (FAKE_LIST_EXIT, FAKE_REPORT_EXIT) pass through the
# environment.
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

# Birdcage's own packages, which go-licenses reports as Unknown, are left
# out of the decision; so is the main module from the go list output.
self_report="$work/self.csv"
cat "$clean_report" > "$self_report"
printf '%s\n' \
  'github.com/tomlawesome/birdcage,Unknown,Unknown' \
  'github.com/tomlawesome/birdcage/cmd/birdcage,Unknown,Unknown' >> "$self_report"
self_modules="$work/self-modules.txt"
cat "$modules" > "$self_modules"
echo 'main github.com/tomlawesome/birdcage' >> "$self_modules"
expect 0 "birdcage's own module and packages are left out" "$p" "$self_report" "$self_modules"

# Only exactly Birdcage's module and the packages under it: a dependency
# whose path merely starts with the same string is checked like any other.
sdk_report="$work/sdk.csv"
cat "$self_report" > "$sdk_report"
echo 'github.com/tomlawesome/birdcage-sdk,https://example.test/LICENSE,Apache-2.0' >> "$sdk_report"
sdk_modules="$work/sdk-modules.txt"
cat "$self_modules" > "$sdk_modules"
echo 'github.com/tomlawesome/birdcage-sdk v1.0.0' >> "$sdk_modules"
expect 1 "a dependency sharing birdcage's path prefix is not left out" \
  "$p" "$sdk_report" "$sdk_modules" "Not allowed licence 'Apache-2.0' found for library 'github.com/tomlawesome/birdcage-sdk'"

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
expect 1 "an entry without @version fails" "$p" "$apache_report" "$modules" \
  "malformed allow-go-module-licenses entry"

# A go.mod replace swaps the code built while go list still reports the
# required version, so a replaced dependency fails even when its entry
# matches -- whether replaced by a local directory or another version.
p="$work/exc.yml"
for target in '../fork' 'github.com/example/apache v0.9.9'; do
  repl="$work/replaced.txt"
  grep -v '^github.com/example/apache ' "$modules" > "$repl"
  echo "github.com/example/apache v0.9.8 => $target" >> "$repl"
  expect 1 "a dependency replaced by $target fails despite its entry" \
    "$p" "$apache_report" "$repl" "module github.com/example/apache v0.9.8 is replaced by $target"
done

p="$work/plain.yml"
empty="$work/empty.csv"; : > "$empty"
expect 1 "an empty go-licenses report fails" "$p" "$empty" "$modules" \
  "go-licenses report produced no libraries"

grep tomlawesome/birdcage "$self_report" > "$work/self-only.csv"
expect 1 "a report holding only birdcage's own packages counts as empty" \
  "$p" "$work/self-only.csv" "$modules" "go-licenses report produced no libraries"

expect 1 "an empty module list fails" "$p" "$clean_report" "$empty" \
  "go list produced no modules"

FAKE_LIST_EXIT=1 expect 1 "go list failing fails the gate" \
  "$p" "$clean_report" "$modules" "go list failed"

nomod="$work/nomod.csv"
cat "$clean_report" > "$nomod"
echo 'github.com/elsewhere/thing,https://example.test/LICENSE,MIT' >> "$nomod"
expect 1 "a library with no module in the build list fails" \
  "$p" "$nomod" "$modules" "github.com/elsewhere/thing"

short="$work/short.csv"
cat "$clean_report" > "$short"
echo 'github.com/example/mit' >> "$short"
expect 1 "a malformed report row fails" "$p" "$short" "$modules" \
  "unreadable go-licenses report line: github.com/example/mit"

FAKE_REPORT_EXIT=1 expect 1 "go-licenses report failing fails the gate" \
  "$p" "$clean_report" "$modules" "go-licenses report failed"

np="$work/no-allow.yml"
printf '%s\n' 'allow-licenses: []' > "$np"
expect 1 "an empty allow-licenses list refuses to run" "$np" "$clean_report" "$modules" \
  "no allow-licenses entries found"

# The real policy: the general list must stay exactly BSD-3-Clause and MIT
# (owner, #8 answer 7a), and every allow-go-module-licenses entry must be
# one exact "<library>@v<version> <licence>", listed once, for a licence
# the general list does not already allow.
real="$here/../supply-chain/licence-policy.yml"
entries() {
  awk -v key="$1:" '$0 == key || index($0, key " ") == 1 {f=1;next} /^[^[:space:]]/{f=0} f&&/^[[:space:]]*-/{sub(/^[[:space:]]*-[[:space:]]*/,"");print}' "$real"
}
general="$(entries allow-licenses | paste -sd, -)"
if [ "$general" = "BSD-3-Clause,MIT" ]; then echo "ok   the real allow-licenses is exactly BSD-3-Clause, MIT"; pass=$((pass + 1))
else echo "FAIL the real allow-licenses is '$general'"; fail=$((fail + 1)); fi

bad_entries="$(entries allow-go-module-licenses | awk '
  !/^[^[:space:]@]+@v[0-9][^[:space:]@]* [^[:space:]]+$/ { print "malformed: " $0; next }
  { split($0, f, " ") }
  f[2] == "BSD-3-Clause" || f[2] == "MIT" { print "already allowed: " $0 }
  seen[f[1]]++ { print "duplicate: " $0 }
')"
if [ -z "$bad_entries" ]; then echo "ok   the real allow-go-module-licenses entries are well formed"; pass=$((pass + 1))
else echo "FAIL the real allow-go-module-licenses entries:"; echo "$bad_entries" | sed 's/^/       /'; fail=$((fail + 1)); fi

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
