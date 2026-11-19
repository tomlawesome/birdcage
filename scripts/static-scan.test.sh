#!/usr/bin/env bash
# Tests for `static-scan.sh gosec [--report-only]` (#199). golangci-lint is
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

# A copy of just what the gosec mode touches.
copy="$work/repo"
mkdir -p "$copy/scripts" "$copy/supply-chain" "$copy/scripts/scan-fixtures/gosec" "$work/bin"
cp "$here/static-scan.sh" "$here/scan-ceiling.py" "$copy/scripts/"
cp "$repo_root/supply-chain/scan-ceilings.yml" "$copy/supply-chain/"
: > "$copy/.golangci.yml"

# The stub. STUB_SELFTEST: caught (exit 1 + G401), clean (exit 0, no output),
# wrongid (exit 1, no G401). STUB_COUNT: high issues in the real run's report.
# STUB_NOREPORT=1: the real run writes no report.
cat > "$work/bin/golangci-lint" <<'STUB'
#!/usr/bin/env bash
out=""
for a in "$@"; do
  case "$a" in --output.json.path=*) out="${a#*=}" ;; esac
done
if [ -z "$out" ]; then  # the self-test invocation
  case "${STUB_SELFTEST:-caught}" in
    caught) echo "fixture.go:5: G401: weak hash md5"; exit 1 ;;
    wrongid) echo "fixture.go:5: G999: something else"; exit 1 ;;
    clean) exit 0 ;;
  esac
fi
[ "${STUB_NOREPORT:-0}" = 1 ] && exit 0
python3 - "$out" "${STUB_COUNT:-0}" <<'PY'
import json, sys
n = int(sys.argv[2])
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
    STUB_NOREPORT="$noreport" bash scripts/static-scan.sh gosec "$@" 2>&1)" || got=$?
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

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
