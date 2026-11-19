#!/usr/bin/env bash
# Tests for `static-scan.sh gosec|dupl [--report-only]` (#199, #200). golangci-lint is
# stubbed on PATH, so no real scanner is needed. The script is run from a temp
# copy of the files it needs, so static-scan-reports/ never lands in the repo.
#
# Spec: --report-only tolerates a gosec-high count above or below its ceiling,
# but never a failed self-test or a real run with no report. Without
# --report-only, both fail.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

ceiling="$(awk '/^  gosec-high:/{print $2; exit}' "$repo_root/supply-chain/scan-ceilings.yml")"
dupl_ceiling="$(awk '/^  go-dupl:/{print $2; exit}' "$repo_root/supply-chain/scan-ceilings.yml")"

# A copy of just what the gosec mode touches.
copy="$work/repo"
mkdir -p "$copy/scripts" "$copy/supply-chain" "$copy/scripts/scan-fixtures/gosec" "$copy/scripts/scan-fixtures/dupl" "$work/bin"
cp "$here/static-scan.sh" "$here/scan-ceiling.py" "$copy/scripts/"
cp "$repo_root/supply-chain/scan-ceilings.yml" "$copy/supply-chain/"
: > "$copy/.golangci.yml"

# The stub. STUB_MODE gosec|dupl picks the linter it reports as.
# STUB_SELFTEST: caught (exit 1 + G401, or "(dupl)"), clean (exit 0, no output),
# wrongid (exit 1, no expected id). STUB_COUNT: high issues in the real run's report.
# STUB_NOREPORT=1: the real run writes no report.
cat > "$work/bin/golangci-lint" <<'STUB'
#!/usr/bin/env bash
out=""
for a in "$@"; do
  case "$a" in --output.json.path=*) out="${a#*=}" ;; esac
done
if [ -z "$out" ]; then  # the self-test invocation
  case "${STUB_SELFTEST:-caught}" in
    caught)
      if [ "${STUB_MODE:-gosec}" = dupl ]; then
        echo "fixture.go:5-20: 16 lines are duplicate of fixture.go:25-40 (dupl)"
      else
        echo "fixture.go:5: G401: weak hash md5"
      fi
      exit 1 ;;
    wrongid) echo "fixture.go:5: G999: something else (gosec)"; exit 1 ;;
    clean) exit 0 ;;
  esac
fi
[ "${STUB_NOREPORT:-0}" = 1 ] && exit 0
python3 - "$out" "${STUB_COUNT:-0}" "${STUB_MODE:-gosec}" <<'PY'
import json, sys
n = int(sys.argv[2])
if sys.argv[3] == "dupl":
    issues = [{"FromLinter": "dupl", "Severity": "", "Text": "lines are duplicate"} for _ in range(n)]
else:
    issues = [{"FromLinter": "gosec", "Severity": "high", "Text": "G401"} for _ in range(n)]
json.dump({"Issues": issues}, open(sys.argv[1], "w"))
PY
[ "${STUB_COUNT:-0}" -gt 0 ] && exit 1
exit 0
STUB
chmod +x "$work/bin/golangci-lint"

# expect <want-zero|nonzero> <name> <selftest> <count> <noreport 0|1> [script args...]
expect() {
  local want="$1" name="$2" st="$3" count="$4" noreport="$5" got=0 out
  shift 5
  rm -rf "$copy/static-scan-reports"
  out="$(cd "$copy" && PATH="$work/bin:$PATH" STUB_SELFTEST="$st" STUB_COUNT="$count" \
    STUB_NOREPORT="$noreport" STUB_MODE="${mode:-gosec}" bash scripts/static-scan.sh "${mode:-gosec}" "$@" 2>&1)" || got=$?
  if { [ "$want" = zero ] && [ "$got" = 0 ]; } || { [ "$want" = nonzero ] && [ "$got" != 0 ]; }; then
    echo "ok   $name"; pass=$((pass + 1))
  else
    echo "FAIL $name: exit $got, want $want"; echo "$out" | sed 's/^/       /'
    fail=$((fail + 1))
  fi
}

over=$((ceiling + 13))
under=$((ceiling - 6))

expect nonzero "report-only, self-test does not fail (exit 0): fails"        clean   "$ceiling" 0 --report-only
expect nonzero "report-only, self-test lacks G401: fails"                    wrongid "$ceiling" 0 --report-only
expect zero    "report-only, good self-test, count over ceiling: passes"     caught  "$over"    0 --report-only
expect zero    "report-only, good self-test, count far under ceiling: passes" caught "$under"   0 --report-only
expect zero    "report-only, good self-test, count at ceiling: passes"       caught  "$ceiling" 0 --report-only
expect nonzero "report-only, real run writes no report: fails"               caught  "$ceiling" 1 --report-only
expect nonzero "gate mode, count over ceiling: fails"                        caught  "$over"    0
expect nonzero "gate mode, self-test does not fail: fails"                   clean   "$ceiling" 0
expect zero    "gate mode, good self-test, count at ceiling: passes"         caught  "$ceiling" 0

# dupl (#200): the same cases, ceiling go-dupl, no severity. $mode is read by expect.
if [ -z "$dupl_ceiling" ]; then
  echo "FAIL go-dupl key missing from supply-chain/scan-ceilings.yml"; fail=$((fail + 1))
  dupl_ceiling=20
fi
mode=dupl
ceiling="$dupl_ceiling"
over=$((ceiling + 13))

expect nonzero "dupl, report-only, self-test does not fail (exit 0): fails"    clean   "$ceiling" 0 --report-only
expect nonzero "dupl, report-only, self-test lacks dupl: fails"                wrongid "$ceiling" 0 --report-only
expect zero    "dupl, report-only, good self-test, count over ceiling: passes" caught  "$over"    0 --report-only
expect zero    "dupl, report-only, good self-test, count at ceiling: passes"   caught  "$ceiling" 0 --report-only
expect nonzero "dupl, report-only, real run writes no report: fails"           caught  "$ceiling" 1 --report-only
expect nonzero "dupl, gate mode, count over ceiling: fails"                    caught  "$over"    0
# Far under: the real ceiling may be 0, so use a fake ceilings file with go-dupl: 10 and 4 issues.
cp "$copy/supply-chain/scan-ceilings.yml" "$work/ceilings.real"
sed -i 's/^  go-dupl:.*/  go-dupl: 10/' "$copy/supply-chain/scan-ceilings.yml"
expect nonzero "dupl, gate mode, count far under a ceiling of 10: fails"       caught  4          0
cp "$work/ceilings.real" "$copy/supply-chain/scan-ceilings.yml"
expect nonzero "dupl, gate mode, self-test does not fail: fails"               clean   "$ceiling" 0
expect zero    "dupl, gate mode, good self-test, count at ceiling: passes"     caught  "$ceiling" 0

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
