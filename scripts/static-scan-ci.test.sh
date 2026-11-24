#!/usr/bin/env bash
# Checks on .gitlab-ci.yml and .golangci.yml for slice 1 of #199 (code
# scanning), written from the specification before the build: the new
# lint:static-scan job exists and is shaped as specified, holds no secret,
# and lint:go runs gosec. Needs python3 with PyYAML, as ci-config.test.sh.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"
pass=0; fail=0

check() { # name, ok(0/1), detail
  if [ "$2" -eq 0 ]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: $3"; fi
}

report="$(python3 -I - "$repo_root/.gitlab-ci.yml" <<'PY'
import re, sys, yaml
class L(yaml.SafeLoader):
    pass
L.add_multi_constructor("!", lambda loader, suffix, node: None)  # !reference
doc = yaml.load(open(sys.argv[1]), Loader=L)

def text(v):
    if v is None: return ""
    if isinstance(v, str): return v
    if isinstance(v, list): return "\n".join(text(x) for x in v)
    if isinstance(v, dict): return "\n".join(text(x) for x in v.values())
    return str(v)

def line(k, v): print(f"{k}\t{v}")

job = doc.get("lint:static-scan")
line("exists", "1" if isinstance(job, dict) else "0")
if isinstance(job, dict):
    line("stage", job.get("stage", ""))
    line("image", job.get("image", ""))
    line("needs_release_readiness", "1" if "release_readiness" in text(job.get("needs")) else "0")
    line("variable_names", ",".join(sorted((job.get("variables") or {}).keys())))
    line("before", text(job.get("before_script")).replace("\n", ";"))
    line("script", text(job.get("script")).replace("\n", ";"))
    art = job.get("artifacts") or {}
    line("artifact_paths", text(art.get("paths")).replace("\n", ","))
    line("artifact_expire", str(art.get("expire_in", "")))
    line("artifact_when", str(art.get("when", "")))
    line("rules", text(job.get("rules")).replace("\n", ";"))
    line("allow_failure", str(job.get("allow_failure", "")))
    line("secrets_key", "1" if "secrets" in job else "0")
    line("id_tokens", "1" if "id_tokens" in job else "0")
    line("body", text(job))
go = doc.get("lint:go")
line("go_exists", "1" if isinstance(go, dict) else "0")
if isinstance(go, dict):
    line("go_script", text(go.get("script")).replace("\n", ";"))
# global/default variables the job would inherit
line("global_var_names", ",".join(sorted((doc.get("variables") or {}).keys())))
PY
)"
get() { printf '%s\n' "$report" | awk -F'\t' -v k="$1" '$1==k{sub(/^[^\t]*\t/,""); print; exit}'; }

# --- lint:static-scan exists and is shaped as specified
if [ "$(get exists)" = 1 ]; then check "lint:static-scan job exists" 0 ""; else
  check "lint:static-scan job exists" 1 "no lint:static-scan job in .gitlab-ci.yml"; fi
check "it is in the lint stage" "$([ "$(get stage)" = lint ]; echo $?)" "stage is '$(get stage)'"
check "it runs on \$GOLANG_IMAGE (Debian, glibc for zizmor)" \
  "$([ "$(get image)" = '$GOLANG_IMAGE' ]; echo $?)" "image is '$(get image)'"
check "it needs release_readiness (optional), like its neighbours" \
  "$([ "$(get needs_release_readiness)" = 1 ]; echo $?)" "needs does not name release_readiness"
for t in actionlint zizmor ruff shellcheck; do
  check "before_script installs $t with scripts/ensure-$t.sh" \
    "$(grep -q "scripts/ensure-$t.sh" <<<"$(get before)"; echo $?)" "scripts/ensure-$t.sh not in before_script"
done
check "script runs scripts/static-scan.sh (one place for the command lines)" \
  "$(grep -q 'scripts/static-scan.sh' <<<"$(get script)"; echo $?)" "static-scan.sh not in script"
check "reports are kept: static-scan-reports/ for 30 days, when always" \
  "$([ "$(get artifact_paths)" = 'static-scan-reports/' ] && [ "$(get artifact_expire)" = '30 days' ] && [ "$(get artifact_when)" = always ]; echo $?)" \
  "artifacts: paths='$(get artifact_paths)' expire_in='$(get artifact_expire)' when='$(get artifact_when)'"
check "it is gated like the other static checks (merge requests, dev, preview, main)" \
  "$(grep -q 'merge_request_event' <<<"$(get rules)"; echo $?)" "rules do not mention merge_request_event"

# --- no secrets: no secret-looking job variables, no secrets:/id_tokens:,
# no token references anywhere in the job body, none inherited globally.
secret_re='(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|API_KEY|COSIGN_KEY)'
check "no secret-looking variable is defined on the job" \
  "$(grep -qE "$secret_re" <<<"$(get variable_names)"; [ $? -ne 0 ]; echo $?)" "job variables: $(get variable_names)"
check "the job has no secrets: or id_tokens: key" \
  "$([ "$(get secrets_key)" = 0 ] && [ "$(get id_tokens)" = 0 ]; echo $?)" "secrets/id_tokens present"
check "the job body names no token or secret variable (zizmor runs with none)" \
  "$(grep -qE "(GH_TOKEN|GITHUB_TOKEN|CI_JOB_TOKEN|CI_REGISTRY_PASSWORD|$secret_re)" <<<"$(get body)"; [ $? -ne 0 ]; echo $?)" \
  "job body references a token or secret variable"
check "no global variable is secret-looking (inherited by the job)" \
  "$(grep -qE "$secret_re" <<<"$(get global_var_names)"; [ $? -ne 0 ]; echo $?)" "global variables: $(get global_var_names)"

# --- lint:go runs gosec, and .golangci.yml enables it
check "lint:go exists" "$([ "$(get go_exists)" = 1 ]; echo $?)" "no lint:go job"
check "lint:go script runs gosec (--enable-only gosec step)" \
  "$(grep -q 'gosec' <<<"$(get go_script)"; echo $?)" "gosec not in lint:go script"
cfg="$repo_root/.golangci.yml"
if [ -f "$cfg" ]; then
  check ".golangci.yml enables gosec" "$(grep -qE '^[[:space:]]*-[[:space:]]*gosec[[:space:]]*$' "$cfg"; echo $?)" "gosec not listed"
  check ".golangci.yml enables nolintlint" "$(grep -qE '^[[:space:]]*-[[:space:]]*nolintlint[[:space:]]*$' "$cfg"; echo $?)" "nolintlint not listed"
  check ".golangci.yml is version 2 and lists linters explicitly (default: none)" \
    "$(grep -qE '^version:[[:space:]]*"?2"?' "$cfg" && grep -qE 'default:[[:space:]]*none' "$cfg"; echo $?)" "version/default missing"
  check "nolintlint requires an explanation and a specific linter" \
    "$(grep -q 'require-explanation: true' "$cfg" && grep -q 'require-specific: true' "$cfg"; echo $?)" "require-explanation/require-specific missing"
else
  check ".golangci.yml exists" 1 "no .golangci.yml at the repository root"
fi

# --- the planted fixtures the self-tests feed the tools are committed
for f in gosec/bad.go gosec/go.mod actionlint/bad.yml zizmor/bad.yml ruff/bad.py shellcheck/bad.sh; do
  check "planted fixture scripts/scan-fixtures/$f is committed" \
    "$([ -s "$here/scan-fixtures/$f" ]; echo $?)" "missing"
done

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
