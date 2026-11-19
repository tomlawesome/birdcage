#!/usr/bin/env bash
# The one place the static scanners' command lines are written (#199, slice 1),
# so the CI jobs and anyone running them locally run identical invocations --
# the scripts/gitleaks-scan.sh pattern.
#
#   static-scan.sh [all]              actionlint, zizmor, ruff and shellcheck
#                                     (job lint:static-scan)
#   static-scan.sh gosec [--report-only]
#                                     gosec through golangci-lint (job lint:go)
#
# Each tool first runs against its planted defect under scripts/scan-fixtures/
# and must fail with the expected rule id: a scan that cannot fail proves
# nothing. Then the real scan writes its machine-readable report to
# static-scan-reports/, and scripts/scan-ceiling.py compares the finding count
# with the ceiling in supply-chain/scan-ceilings.yml (a count above it, or more
# than 5 below it, fails). The ceilings file itself may only go down: it is
# compared with the target branch (or the previous commit).
#
# Needs the tools on PATH (scripts/ensure-<tool>.sh installs them). Offline
# apart from that: no token, and zizmor runs with --offline.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
cd "$root" || exit 1
reports="static-scan-reports"
ceilings="supply-chain/scan-ceilings.yml"
fixtures="scripts/scan-fixtures"
ceiling() { python3 -I scripts/scan-ceiling.py "$@"; }
status=0
fail() { echo "static-scan: FAIL $*" >&2; status=1; }

# selftest <name> <expected rule ids, space separated> <command...>
# The command must exit non-zero and print every expected id.
selftest() {
  local name="$1" want="$2" out rc=0 id
  shift 2
  out="$("$@" 2>&1)" || rc=$?
  if [ "$rc" -eq 0 ]; then
    fail "$name self-test: the planted defect was NOT caught (exit 0)"
    return 1
  fi
  for id in $want; do
    if ! grep -q "$id" <<<"$out"; then
      fail "$name self-test: exit $rc but $id is not in the output"
      printf '%s\n' "$out" | sed 's/^/    /' >&2
      return 1
    fi
  done
  echo "static-scan: $name self-test ok (exit $rc, found: $want)"
}

# gate <key> <report> <format> [severity] -- the ceiling check for one key.
gate() {
  local key="$1" report="$2" format="$3" sev="${4:-}" args=()
  [ -z "$sev" ] || args=(--severity "$sev")
  ceiling check --key "$key" --report "$report" --format "$format" "${args[@]}" \
    --ceilings "$ceilings" || status=1
}

tracked() { # tracked <glob> -- tracked files, never the planted fixtures
  git ls-files -- "$1" | grep -v "^$fixtures/" || true
}

# --- the ceilings file only goes down ---------------------------------------
compare_ceilings() {
  local ref=""
  if [ -n "${CI_MERGE_REQUEST_TARGET_BRANCH_NAME:-}" ]; then
    git fetch --quiet --depth=50 origin \
      "+refs/heads/${CI_MERGE_REQUEST_TARGET_BRANCH_NAME}:refs/remotes/origin/${CI_MERGE_REQUEST_TARGET_BRANCH_NAME}" \
      || { fail "could not fetch the target branch to compare ceilings"; return; }
    ref="origin/${CI_MERGE_REQUEST_TARGET_BRANCH_NAME}"
  elif git rev-parse --verify --quiet HEAD~1 >/dev/null; then
    ref="HEAD~1"
  fi
  if [ -z "$ref" ]; then
    echo "static-scan: no base to compare ceilings with (no target branch, no previous commit)"
    return
  fi
  if ! git cat-file -e "$ref:$ceilings" 2>/dev/null; then
    echo "static-scan: $ref has no $ceilings yet: nothing to compare (first introduction)"
    return
  fi
  ceiling compare --ceilings "$ceilings" --base-ref "$ref" || status=1
}

# --- gosec, inside golangci-lint (job lint:go) -------------------------------
run_gosec() {
  local report_only="$1" rc=0
  command -v golangci-lint >/dev/null || { echo "static-scan: golangci-lint not found" >&2; return 127; }
  mkdir -p "$reports"
  # Self-test: the planted module has its own go.mod, so ./... of the main
  # module never sees it. The same repo config runs inside it. G401 (md5) is
  # the required id: gosec follows the constant in the fixture's exec.Command
  # call and does not raise G204 for it.
  selftest gosec "G401" \
    bash -c 'cd "$1/gosec" && golangci-lint run --config "$2/.golangci.yml" --enable-only gosec ./...' \
    _ "$root/$fixtures" "$root"
  golangci-lint run --enable-only gosec --output.json.path="$reports/gosec.json" ./... || rc=$?
  if [ "$rc" -gt 1 ] || [ ! -s "$reports/gosec.json" ]; then
    fail "gosec run failed (exit $rc, no report)"
    return
  fi
  echo "static-scan: gosec findings: high $(ceiling count --report "$reports/gosec.json" --format golangci-json --severity high)," \
    "medium $(ceiling count --report "$reports/gosec.json" --format golangci-json --severity medium)," \
    "low $(ceiling count --report "$reports/gosec.json" --format golangci-json --severity low)"
  # Blocks at high. Medium and low are printed above, and gosec-medium in the
  # ceilings file is there for visibility only: never checked.
  # Report-only (for a new scanner's first run) forgives the ceiling check alone: a broken self-test or a
  # failed run above has already set status and must still fail the job.
  local before="$status"
  gate gosec-high "$reports/gosec.json" golangci-json high
  if [ "$report_only" = 1 ] && [ "$status" -ne "$before" ]; then
    echo "static-scan: report-only: not failing the job on the ceiling (first run of a new scanner)" >&2
    status="$before"
  fi
}

# --- the four static binaries (job lint:static-scan) --------------------------
run_all() {
  local files
  mkdir -p "$reports"

  # actionlint. Its shellcheck and pyflakes integrations are off: shellcheck
  # runs on the tracked .sh files below and ruff covers the Python, so the
  # inline `run:` scripts would otherwise be counted twice.
  selftest actionlint "expression" \
    actionlint -shellcheck= -pyflakes= "$fixtures/actionlint/bad.yml"
  files="$(git ls-files '.github/workflows/*.yml' '.github/workflows/*.yaml')"
  # shellcheck disable=SC2086 # the list is newline separated paths without spaces
  actionlint -shellcheck= -pyflakes= -format '{{json .}}' $files >"$reports/actionlint.json" \
    2>"$reports/actionlint.err" || [ $? -eq 1 ] || fail "actionlint failed to run"
  [ -s "$reports/actionlint.json" ] || echo '[]' >"$reports/actionlint.json"
  gate actionlint "$reports/actionlint.json" actionlint-json

  # zizmor, offline, no token. Online-only audits are off (--offline); action
  # pins are checked by scripts/action-pins-check.py. High and above blocks.
  if [ -n "${GH_TOKEN:-}${GITHUB_TOKEN:-}" ]; then
    fail "zizmor must run without a GitHub token in the environment"
  fi
  selftest zizmor "template-injection" \
    zizmor --offline --no-online-audits "$fixtures/zizmor/bad.yml"
  zizmor --offline --no-online-audits --no-exit-codes --format json-v1 .github/workflows/ \
    >"$reports/zizmor.json" 2>"$reports/zizmor.err" || fail "zizmor failed to run"
  gate zizmor-high "$reports/zizmor.json" zizmor-json high

  # ruff, security rules only (ruff.toml). Tracked files only, passed as
  # arguments, so untracked files are not scanned.
  selftest ruff "S602 S324" \
    ruff check --no-cache --config ruff.toml "$fixtures/ruff/bad.py"
  files="$(tracked '*.py')"
  # shellcheck disable=SC2086 # newline separated paths without spaces
  ruff check --no-cache --config ruff.toml --output-format json $files \
    >"$reports/ruff.json" 2>"$reports/ruff.err" || [ $? -eq 1 ] || fail "ruff failed to run"
  gate ruff-S "$reports/ruff.json" ruff-json

  # The shellcheck run: errors and warnings block; info and style are not reported.
  # SC2086 is info level, so the self-test runs at the default severity.
  selftest shellcheck "SC2086 SC2164" \
    shellcheck "$fixtures/shellcheck/bad.sh"
  files="$(tracked '*.sh')"
  # shellcheck disable=SC2086 # newline separated paths without spaces
  shellcheck --severity=warning --format=json1 $files \
    >"$reports/shellcheck.json" 2>"$reports/shellcheck.err" || [ $? -eq 1 ] || fail "shellcheck failed to run"
  gate shellcheck "$reports/shellcheck.json" shellcheck-json1 "error,warning"

  # A suppression always carries a reason: `# shellcheck disable=SCxxxx # why`.
  # A project-wide disable in .shellcheckrc is not allowed.
  local bare
  bare="$(git grep -nE '^[[:space:]]*#[[:space:]]*shellcheck[[:space:]]+disable=' -- '*.sh' ':!'"$fixtures" \
    | grep -vE 'disable=[A-Za-z0-9,]+[[:space:]]+#[[:space:]]*[^[:space:]]' || true)"
  if [ -n "$bare" ]; then
    fail "shellcheck suppression without a reason (needs a second # and text):"
    printf '%s\n' "$bare" | sed 's/^/    /' >&2
  fi
  if git ls-files | grep -q '\.shellcheckrc$'; then
    fail "a .shellcheckrc is tracked: project-wide disables are not allowed"
  fi

  compare_ceilings
}

mode="${1:-all}"
case "$mode" in
  all) run_all ;;
  gosec) run_gosec "$([ "${2:-}" = "--report-only" ] && echo 1 || echo 0)" ;;
  *) echo "usage: static-scan.sh [all | gosec [--report-only]]" >&2; exit 2 ;;
esac
exit "$status"
