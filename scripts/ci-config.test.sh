#!/usr/bin/env bash
# Checks on .gitlab-ci.yml and supply-chain/policy-files.txt that no job can
# make for itself (#207 audit, GP3-F1 and GP3-F2).
#
# 1. Every job that runs on the docker CLI image runs on the same tag and
#    digest as the release jobs' .dind image. test:release-scripts exists to
#    catch tool differences on the release image (#158); on a floating tag it
#    can pass while the release image differs.
# 2. The policy file list names the quarantine and flake gates and the
#    release-candidate script, so editing any of them moves the policy digest.
#
# Runs in lint:scripts (every scripts/*.test.sh); needs python3 with PyYAML.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"
ci="$repo_root/.gitlab-ci.yml"
policy="$repo_root/supply-chain/policy-files.txt"
pass=0; fail=0

check() { # name, ok(0/1), detail
  if [ "$2" -eq 0 ]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: $3"; fi
}

# Prints "<job>\t<tag>\t<digest or ->" for .dind and for each job on the
# docker CLI image, after expanding the file's own global variables.
report="$(python3 -I - "$ci" <<'PY'
import re, sys, yaml
class L(yaml.SafeLoader):
    pass
L.add_multi_constructor("!", lambda loader, suffix, node: None)  # !reference
doc = yaml.load(open(sys.argv[1]), Loader=L)
gvars = {k: str(v) for k, v in (doc.get("variables") or {}).items()}

def expand(s):
    for _ in range(5):
        s = re.sub(r"\$\{?(\w+)\}?", lambda m: gvars.get(m.group(1), m.group(0)), s)
    return s

def image_of(job):
    img = job.get("image")
    if isinstance(img, dict):
        img = img.get("name")
    return img

def split(ref):
    m = re.search(r"docker:([^@\s]+?)(?:@(sha256:[0-9a-f]{64}))?$", ref)
    return (m.group(1), m.group(2) or "-") if m else (ref, "-")

dind = expand(image_of(doc[".dind"]))
print("\t".join([".dind", *split(dind)]))
for name, job in doc.items():
    if not isinstance(job, dict) or name == ".dind":
        continue
    raw = image_of(job)
    if not isinstance(raw, str):
        continue
    if "DOCKER_CLI_IMAGE" in raw or re.search(r"docker:[^/\s]*-cli", expand(raw)):
        print("\t".join([name, *split(expand(raw))]))
PY
)" || { echo "FAIL could not read $ci"; exit 1; }

dind_tag=""; dind_digest=""; jobs=0
while IFS=$'\t' read -r name tag digest; do
  if [ "$name" = ".dind" ]; then dind_tag="$tag"; dind_digest="$digest"; continue; fi
  jobs=$((jobs + 1))
  if [ "$tag" = "$dind_tag" ] && [ "$digest" = "$dind_digest" ] && [ "$digest" != "-" ]; then
    check "$name runs on the .dind image" 0 ""
  else
    check "$name runs on the .dind image" 1 "has tag=$tag digest=$digest, .dind has tag=$dind_tag digest=$dind_digest"
  fi
done <<< "$report"

for want in test:release-scripts release:attest; do
  if grep -q "^$want"$'\t' <<< "$report"; then check "$want is checked" 0 ""
  else check "$want is checked" 1 "not found among docker CLI image jobs"; fi
done

for f in scripts/quarantine.txt scripts/ci/quarantine-pattern.sh \
         scripts/ci/flake-check.sh scripts/release-candidate.sh; do
  if grep -qxF "$f" "$policy"; then check "policy-files.txt lists $f" 0 ""
  else check "policy-files.txt lists $f" 1 "not listed"; fi
  [ -e "$repo_root/$f" ] || check "$f exists" 1 "listed file missing from tree"
done

# 3. The static scanners block (#199): lint:static-scan is not allow_failure,
#    and lint:go runs the gosec scan without --report-only.
scan="$(python3 -I - "$ci" <<'PY'
import sys, yaml
class L(yaml.SafeLoader):
    pass
L.add_multi_constructor("!", lambda loader, suffix, node: None)  # !reference
doc = yaml.load(open(sys.argv[1]), Loader=L)
print("allow_failure=%s" % doc["lint:static-scan"].get("allow_failure", False))
for line in doc["lint:go"].get("script") or []:
    if isinstance(line, str):
        for l in line.splitlines():
            if "static-scan.sh" in l:
                print("go-scan-line=" + l.strip())
            if "golangci-lint run" in l:
                print("go-lint-line=" + l.strip())
PY
)" || { echo "FAIL could not read lint jobs from $ci"; exit 1; }

if grep -qx 'allow_failure=\(False\|false\)' <<< "$scan"; then
  check "lint:static-scan is not allow_failure" 0 ""
else
  check "lint:static-scan is not allow_failure" 1 "$(grep '^allow_failure=' <<< "$scan")"
fi
if grep -q '^go-scan-line=.*gosec.*--report-only' <<< "$scan"; then
  check "lint:go does not pass --report-only to the gosec scan" 1 "$(grep -- '--report-only' <<< "$scan")"
else
  check "lint:go does not pass --report-only to the gosec scan" 0 ""
fi
if grep -qx 'go-scan-line=scripts/static-scan.sh gosec' <<< "$scan"; then
  check "lint:go runs scripts/static-scan.sh gosec" 0 ""
else
  check "lint:go runs scripts/static-scan.sh gosec" 1 "no such script line"
fi

# 4. dupl (#200) blocks: lint:go runs the dupl scan without --report-only
#    (pipeline 4781 measured 0 at a ceiling of 0), and its main
#    golangci-lint line disables dupl (as gosec).
if grep -qx 'go-scan-line=scripts/static-scan.sh dupl' <<< "$scan"; then
  check "lint:go runs scripts/static-scan.sh dupl, blocking" 0 ""
else
  check "lint:go runs scripts/static-scan.sh dupl, blocking" 1 "$(grep 'static-scan.sh dupl' <<< "$scan" || echo 'no such script line')"
fi
if grep '^go-lint-line=' <<< "$scan" | grep -v -- '--enable-only' | grep -q -- '--disable[ =][a-z,]*dupl'; then
  check "lint:go main golangci-lint line disables dupl" 0 ""
else
  check "lint:go main golangci-lint line disables dupl" 1 "$(grep '^go-lint-line=' <<< "$scan")"
fi

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
