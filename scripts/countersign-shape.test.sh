#!/usr/bin/env bash
# Pins the shape of the countersign workflow (#169, item B). The second
# signature is worth something only if nothing but a human at GitHub can
# start it, so this fails if any of these stops being true:
#   1. countersign.yml triggers only on workflow_dispatch;
#   2. its job declares `environment: countersign` (the approval step);
#   3. no other .github/workflows file requests id-token: write or
#      packages: write;
#   4. .gitlab-ci.yml has no api.github.com, `gh ` or workflow_dispatch
#      reference outside the mirror jobs (sync:mirror*, release:mirror*).
# Each rule is then broken in a scratch copy to prove it fires.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

# check <root>: prints one line per broken rule ("rule1".."rule4"); exit 0.
check() {
  python3 -I - "$1" <<'PY'
import glob, os, re, sys
import yaml
root = sys.argv[1]
wf = os.path.join(root, ".github/workflows")
bad = []
def triggers(doc):
    on = doc.get("on", doc.get(True))  # YAML 1.1 reads a bare `on` as True
    if isinstance(on, str): return {on}
    if isinstance(on, list): return set(on)
    return set(on or {})
try:
    doc = yaml.safe_load(open(os.path.join(wf, "countersign.yml")))
except Exception:
    doc = None
if not doc or triggers(doc) != {"workflow_dispatch"}:
    bad.append("rule1")
jobs = (doc or {}).get("jobs") or {}
def env_name(job):
    e = job.get("environment")
    return e.get("name") if isinstance(e, dict) else e
if not jobs or not all(env_name(j) == "countersign" for j in jobs.values()):
    bad.append("rule2")
def writes(perms):
    return isinstance(perms, dict) and any(perms.get(k) == "write" for k in ("id-token", "packages"))
for path in sorted(glob.glob(os.path.join(wf, "*.y*ml"))):
    if os.path.basename(path) == "countersign.yml": continue
    d = yaml.safe_load(open(path)) or {}
    if writes(d.get("permissions")) or any(writes(j.get("permissions")) for j in (d.get("jobs") or {}).values()):
        bad.append("rule3"); break
ci = open(os.path.join(root, ".gitlab-ci.yml")).read()
blocks = re.split(r"(?m)^(?=[A-Za-z0-9_.:-]+:)", ci)
pat = re.compile(r"api\.github\.com|workflow_dispatch|(?<![\w-])gh\s")
for b in blocks:
    name = re.match(r"([A-Za-z0-9_.:-]+):", b)
    if name and re.match(r"(sync|release):mirror", name.group(1)): continue
    # comments are prose, not commands
    if any(pat.search(l) for l in b.splitlines() if not l.lstrip().startswith("#")):
        bad.append("rule4"); break
print("\n".join(bad))
PY
}

# scratch <name>: a copy of just the files the check reads, with the
# environment line the real file is meant to gain, so each mutation below
# breaks exactly one rule from an otherwise-good base.
scratch() {
  local d="$work/$1"; rm -rf "$d"; mkdir -p "$d/.github"
  cp -r "$repo/.github/workflows" "$d/.github/workflows"
  cp "$repo/.gitlab-ci.yml" "$d/.gitlab-ci.yml"
  grep -q '^    environment: countersign$' "$d/.github/workflows/countersign.yml" \
    || sed -i 's/^    runs-on: ubuntu-latest$/&\n    environment: countersign/' "$d/.github/workflows/countersign.yml"
  echo "$d"
}
# expect <name> <root> <want: "none" or the rule that must fire>
expect() {
  local got; got="$(check "$2")" || got="checker-error"
  if { [ "$3" = none ] && [ -z "$got" ]; } || { [ "$3" != none ] && grep -qx "$3" <<<"$got"; }; then
    echo "ok   $1"; pass=$((pass + 1))
  else
    echo "FAIL $1: got '${got//$'\n'/ }', want $3"; fail=$((fail + 1))
  fi
}

expect "the real tree satisfies all four rules" "$repo" none

d="$(scratch r1a)"; sed -i 's/^  workflow_dispatch:/  workflow_dispatch:\n  push:/' "$d/.github/workflows/countersign.yml"
expect "rule 1: an added push trigger is caught" "$d" rule1
d="$(scratch r1b)"; sed -i 's/^  workflow_dispatch:/  workflow_call:/' "$d/.github/workflows/countersign.yml"
expect "rule 1: workflow_dispatch replaced is caught" "$d" rule1
d="$(scratch r2a)"; sed -i '/^    environment: countersign$/d' "$d/.github/workflows/countersign.yml"
expect "rule 2: no environment is caught" "$d" rule2
d="$(scratch r2b)"; sed -i 's/^    environment: countersign$/    environment: other/' "$d/.github/workflows/countersign.yml"
expect "rule 2: a different environment is caught" "$d" rule2
d="$(scratch r3a)"
printf 'name: rogue\non: push\npermissions:\n  id-token: write\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n' > "$d/.github/workflows/rogue.yml"
expect "rule 3: id-token: write in another workflow is caught" "$d" rule3
d="$(scratch r3b)"
printf 'name: rogue\non: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    permissions:\n      packages: write\n    steps:\n      - run: echo hi\n' > "$d/.github/workflows/rogue.yml"
expect "rule 3: job-level packages: write in another workflow is caught" "$d" rule3
d="$(scratch r4a)"; printf 'rogue:\n  script:\n    - curl https://api.github.com/repos/x/y/dispatches\n' >> "$d/.gitlab-ci.yml"
expect "rule 4: api.github.com in a non-mirror job is caught" "$d" rule4
d="$(scratch r4b)"; printf 'rogue:\n  script:\n    - gh workflow run countersign.yml\n' >> "$d/.gitlab-ci.yml"
expect "rule 4: a gh command in a non-mirror job is caught" "$d" rule4
d="$(scratch r4c)"; printf 'rogue:\n  script:\n    - echo workflow_dispatch\n' >> "$d/.gitlab-ci.yml"
expect "rule 4: workflow_dispatch in a non-mirror job is caught" "$d" rule4
d="$(scratch good)"
expect "the scratch base itself satisfies all four rules" "$d" none
d="$(scratch r4d)"; printf 'sync:mirror-extra:\n  script:\n    - gh repo view\n' >> "$d/.gitlab-ci.yml"
expect "rule 4: a mirror job is exempt" "$d" none

echo "countersign-shape: $pass passed, $fail failed"
[ "$fail" = 0 ]
