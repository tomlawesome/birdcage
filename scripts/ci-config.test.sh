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

tf() { if "$@"; then echo 0; else echo 1; fi; }  # tf <test...>: prints 0 or 1 for check
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

# 5. knip runs sandboxed (#200, owner 57a): own package, locked install, no
#    secrets, no cache push, nothing downstream depends on it.
knip="$(python3 -I - "$ci" "$repo_root" <<'PY'
import json, os, re, sys, yaml
class L(yaml.SafeLoader):
    pass
L.add_multi_constructor("!", lambda loader, suffix, node: None)  # !reference
doc = yaml.load(open(sys.argv[1]), Loader=L)
root = sys.argv[2]
job = doc.get("lint:knip")
print("exists=%s" % (isinstance(job, dict)))
job = job if isinstance(job, dict) else {}
lines = []
for line in job.get("script") or []:
    if isinstance(line, str):
        lines += [l.strip() for l in line.splitlines()]
for l in lines:
    if re.search(r"\bnpm\s+ci\b", l):
        print("npm-ci=" + l)
    if re.search(r"\bnpm\s+audit\s+signatures\b", l):
        print("audit-sig=" + l)
cache = job.get("cache")
for c in (cache if isinstance(cache, list) else [cache] if cache else []):
    if isinstance(c, dict) and c.get("policy", "pull-push") != "pull":
        print("cache-push=%s" % c.get("policy", "pull-push"))
for name, other in doc.items():
    if name == "lint:knip" or not isinstance(other, dict):
        continue
    needs = other.get("needs") or []
    for n in needs if isinstance(needs, list) else [needs]:
        n = n.get("job") if isinstance(n, dict) else n
        if n == "lint:knip":
            print("needed-by=" + name)
for k, v in (job.get("variables") or {}).items():
    print("var=%s" % k)
    if re.search(r"TOKEN|SECRET|PASSWORD|PASSWD|KEY|CREDENTIAL|CERT", k, re.I) \
            or isinstance(v, dict):
        print("secret-var=%s" % k)

def load(path):
    try:
        return json.load(open(os.path.join(root, path)))
    except (OSError, ValueError):
        return None
kp = load("ci/knip/package.json")
if kp is None:
    print("knip-pkg=missing")
else:
    v = {**(kp.get("dependencies") or {}), **(kp.get("devDependencies") or {})}.get("knip")
    print("knip-version=%s" % v)
fp = load("frontend/package.json") or {}
for sec in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
    if "knip" in (fp.get(sec) or {}):
        print("knip-in-frontend=" + sec)
PY
)" || { echo "FAIL could not read lint:knip from $ci"; exit 1; }

if grep -qx 'exists=True' <<< "$knip"; then
  check "lint:knip exists" 0 ""
else
  check "lint:knip exists" 1 "no such job"
fi
if grep -q '^npm-ci=' <<< "$knip" && ! grep '^npm-ci=' <<< "$knip" | grep -qv -- '--ignore-scripts'; then
  check "every npm ci in lint:knip has --ignore-scripts" 0 ""
else
  check "every npm ci in lint:knip has --ignore-scripts" 1 "$(grep '^npm-ci=' <<< "$knip" | grep -v -- '--ignore-scripts' || echo 'no npm ci line')"
fi
if grep -q '^audit-sig=' <<< "$knip"; then
  check "lint:knip runs npm audit signatures" 0 ""
else
  check "lint:knip runs npm audit signatures" 1 "no such script line"
fi
if grep -q '^cache-push=' <<< "$knip"; then
  check "lint:knip has no cache with a push policy" 1 "$(grep '^cache-push=' <<< "$knip")"
else
  check "lint:knip has no cache with a push policy" 0 ""
fi
if grep -q '^needed-by=' <<< "$knip"; then
  check "no job needs lint:knip" 1 "$(grep '^needed-by=' <<< "$knip" | tr '\n' ' ')"
else
  check "no job needs lint:knip" 0 ""
fi
if grep -qx 'exists=True' <<< "$knip" && ! grep -q '^secret-var=' <<< "$knip"; then
  check "lint:knip defines no secret variables" 0 ""
else
  check "lint:knip defines no secret variables" 1 "$(grep '^secret-var=' <<< "$knip" | tr '\n' ' ')job missing or has secret-like variables"
fi
if grep -qE '^knip-version=[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$' <<< "$knip"; then
  check "ci/knip/package.json pins knip exactly" 0 ""
else
  check "ci/knip/package.json pins knip exactly" 1 "$(grep '^knip-' <<< "$knip" | head -1)"
fi
if grep -q '^knip-in-frontend=' <<< "$knip"; then
  check "knip is not in frontend/package.json" 1 "$(grep '^knip-in-frontend=' <<< "$knip")"
else
  check "knip is not in frontend/package.json" 0 ""
fi

# 5b. squawk (#199 item 5, owner decision 69a): same sandbox as knip, own
#     package, report-only, over the Postgres migrations. Written from the
#     specification before the job exists.
sq="$(python3 -I - "$ci" "$repo_root" <<'PY'
import json, os, re, sys, yaml
class L(yaml.SafeLoader):
    pass
L.add_multi_constructor("!", lambda loader, suffix, node: None)  # !reference
doc = yaml.load(open(sys.argv[1]), Loader=L)
root = sys.argv[2]
J = "lint:squawk"
job = doc.get(J)
print("exists=%s" % (isinstance(job, dict)))
job = job if isinstance(job, dict) else {}
print("allow-failure=%s" % job.get("allow_failure"))
lines = []
for line in job.get("script") or []:
    if isinstance(line, str):
        lines += [l.strip() for l in line.splitlines()]
for l in lines:
    if re.search(r"\bnpm\s+ci\b", l):
        print("npm-ci=" + l)
    if re.search(r"\bnpm\s+audit\s+signatures\b", l):
        print("audit-sig=" + l)
    if "squawk" in l and "internal/db/migrations/postgres/" in l and "sqlite" not in l:
        print("scans-postgres=" + l)
    if "licence-check-npm.sh" in l:
        print("licence-check=" + l)
art = job.get("artifacts") or {}
if any("squawk-report" in str(p) for p in (art.get("paths") or [])) \
        and art.get("when") == "always" and art.get("expire_in") == "30 days":
    print("artifact-ok=1")
cache = job.get("cache")
for c in (cache if isinstance(cache, list) else [cache] if cache else []):
    if isinstance(c, dict) and c.get("policy", "pull-push") != "pull":
        print("cache-push=%s" % c.get("policy", "pull-push"))
for name, other in doc.items():
    if name == J or not isinstance(other, dict):
        continue
    needs = other.get("needs") or []
    for n in needs if isinstance(needs, list) else [needs]:
        n = n.get("job") if isinstance(n, dict) else n
        if n == J:
            print("needed-by=" + name)
for k, v in (job.get("variables") or {}).items():
    if re.search(r"TOKEN|SECRET|PASSWORD|PASSWD|KEY|CREDENTIAL|CERT", k, re.I) \
            or isinstance(v, dict):
        print("secret-var=%s" % k)

def load(path):
    try:
        return json.load(open(os.path.join(root, path)))
    except (OSError, ValueError):
        return None
kp = load("ci/squawk/package.json")
if kp is None:
    print("squawk-pkg=missing")
else:
    v = {**(kp.get("dependencies") or {}), **(kp.get("devDependencies") or {})}.get("squawk-cli")
    print("squawk-version=%s" % v)
print("lock=%s" % os.path.exists(os.path.join(root, "ci/squawk/package-lock.json")))
fp = load("frontend/package.json") or {}
for sec in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
    if "squawk-cli" in (fp.get(sec) or {}):
        print("squawk-in-frontend=" + sec)
def txt(p):
    try:
        return open(os.path.join(root, p)).read()
    except OSError:
        return ""
inv = txt("supply-chain/dependency-inventory.md")
print("inventory-row=%s" % bool(re.search(r"^\|[^|]*\|\s*`squawk", inv, re.M)))
print("policy-listed=%s" % ("ci/squawk/package.json" in txt("supply-chain/policy-files.txt").split()))
print("hops-row=%s" % ("`lint:squawk`" in txt("docs/ci-hops.md")))
PY
)" || { echo "FAIL could not read lint:squawk from $ci"; exit 1; }

chk() { # name, grep-pattern (must match), detail
  if grep -qE "$2" <<< "$sq"; then check "$1" 0 ""; else check "$1" 1 "$3"; fi
}
chk "lint:squawk exists" '^exists=True$' "no such job"
chk "lint:squawk is allow_failure: true" '^allow-failure=True$' "$(grep '^allow-failure=' <<< "$sq")"
if grep -q '^npm-ci=' <<< "$sq" && ! grep '^npm-ci=' <<< "$sq" | grep -qv -- '--ignore-scripts'; then
  check "every npm ci in lint:squawk has --ignore-scripts" 0 ""
else
  check "every npm ci in lint:squawk has --ignore-scripts" 1 "$(grep '^npm-ci=' <<< "$sq" | grep -v -- '--ignore-scripts' || echo 'no npm ci line')"
fi
chk "lint:squawk runs npm audit signatures" '^audit-sig=' "no such script line"
chk "lint:squawk runs the npm licence check" '^licence-check=' "no such script line"
chk "lint:squawk scans internal/db/migrations/postgres/" '^scans-postgres=' "no squawk line over the postgres dir"
chk "lint:squawk keeps squawk-report/ for 30 days, when always" '^artifact-ok=1$' "artifact missing or wrong"
if grep -q '^cache-push=' <<< "$sq"; then
  check "lint:squawk has no cache with a push policy" 1 "$(grep '^cache-push=' <<< "$sq")"
else
  check "lint:squawk has no cache with a push policy" 0 ""
fi
if grep -q '^needed-by=' <<< "$sq"; then
  check "no job needs lint:squawk" 1 "$(grep '^needed-by=' <<< "$sq" | tr '\n' ' ')"
else
  check "no job needs lint:squawk" 0 ""
fi
if grep -qx 'exists=True' <<< "$sq" && ! grep -q '^secret-var=' <<< "$sq"; then
  check "lint:squawk defines no secret variables" 0 ""
else
  check "lint:squawk defines no secret variables" 1 "job missing or has secret-like variables"
fi
chk "ci/squawk/package.json pins squawk-cli exactly 2.73.0" '^squawk-version=2\.73\.0$' "$(grep '^squawk-' <<< "$sq" | head -1)"
chk "ci/squawk/package-lock.json exists" '^lock=True$' "missing"
if grep -q '^squawk-in-frontend=' <<< "$sq"; then
  check "squawk-cli is not in frontend/package.json" 1 "$(grep '^squawk-in-frontend=' <<< "$sq")"
else
  check "squawk-cli is not in frontend/package.json" 0 ""
fi
chk "dependency-inventory.md has a squawk row" '^inventory-row=True$' "no row"
chk "policy-files.txt lists ci/squawk/package.json" '^policy-listed=True$' "not listed"
chk "docs/ci-hops.md has a lint:squawk row" '^hops-row=True$' "no row"

# 6. Trivy (#199 items 1-3, owner decision 66a): report-first jobs, installed
#    only through scripts/ensure-trivy.sh. Written from the specification
#    before the jobs exist.
trivy="$(python3 -I - "$ci" <<'PY'
import re, sys, yaml
class L(yaml.SafeLoader):
    pass
L.add_multi_constructor("!", lambda loader, suffix, node: None)  # !reference
doc = yaml.load(open(sys.argv[1]), Loader=L)
raw = open(sys.argv[1]).read()

def text(v):
    if v is None: return ""
    if isinstance(v, str): return v
    if isinstance(v, list): return "\n".join(text(x) for x in v)
    if isinstance(v, dict): return "\n".join(text(x) for x in v.values())
    return str(v)

def line(k, v): print(f"{k}\t{v}")

line("aquasec_image", "1" if re.search(r"aquasec(security)?/trivy", raw) else "0")
line("trivy_action", "1" if "trivy-action" in raw else "0")
names = []
for name, job in doc.items():
    if not isinstance(job, dict) or name.startswith("."):
        continue
    scripts = text(job.get("before_script")) + "\n" + text(job.get("script"))
    if not re.search(r"\btrivy\b", scripts):
        continue
    names.append(name)
    j = "j:" + name
    line(j + ":scripts", scripts.replace("\n", ";"))
    line(j + ":allow_failure", str(job.get("allow_failure", "")))
    line(j + ":cache", "1" if job.get("cache") else "0")
    needs = job.get("needs") or []
    nn = [n.get("job") if isinstance(n, dict) else n for n in needs]
    line(j + ":needs", ",".join(str(n) for n in nn))
    art = job.get("artifacts") or {}
    line(j + ":artifact_paths", text(art.get("paths")).replace("\n", ","))
line("jobs", ",".join(names))
PY
)" || { echo "FAIL could not read trivy jobs from $ci"; exit 1; }
tget() { printf '%s\n' "$trivy" | awk -F'\t' -v k="$1" '$1==k{sub(/^[^\t]*\t/,""); print; exit}'; }

# Jobs by what they run. Several jobs may do the same kind of scan.
cfg_jobs=""; fs_jobs=""; img_jobs=""
for j in $(tr ',' ' ' <<< "$(tget jobs)"); do
  s="$(tget "j:$j:scripts")"
  grep -qE 'trivy +config\b' <<< "$s" && cfg_jobs="$cfg_jobs $j"
  grep -qE 'trivy +fs\b' <<< "$s" && fs_jobs="$fs_jobs $j"
  grep -qE 'trivy +image\b' <<< "$s" && img_jobs="$img_jobs $j"
done
all_jobs="$(tr ',' ' ' <<< "$(tget jobs)")"

[ -n "$cfg_jobs" ] && r=0 || r=1
check "a job runs trivy config (Dockerfile misconfiguration)" "$r" "no job runs 'trivy config'"
r=1
for j in $cfg_jobs; do grep -qE 'trivy +config\b.*(Dockerfile|build|\. *(;|$))' <<< "$(tget "j:$j:scripts")" && r=0; done
check "trivy config is pointed at the repo's Dockerfiles (build/ or the repo)" "$r" "trivy config names no Dockerfile path"

[ -n "$fs_jobs" ] && r=0 || r=1
check "a job runs trivy fs (npm lockfile and Go modules)" "$r" "no job runs 'trivy fs'"
r=1
for j in $fs_jobs; do grep -qE -- '--scanners[ =]vuln,license' <<< "$(tget "j:$j:scripts")" && r=0; done
check "trivy fs runs with --scanners vuln,license" "$r" "no trivy fs line names --scanners vuln,license"

[ -n "$img_jobs" ] && r=0 || r=1
check "a job runs trivy image (the images build:images builds)" "$r" "no job runs 'trivy image'"
r=1
for j in $img_jobs; do
  grep -qw 'build:images' <<< "$(tr ',' ' ' <<< "$(tget "j:$j:needs")")" && r=0
done
check "the trivy image job needs build:images" "$r" "needs: $(for j in $img_jobs; do tget "j:$j:needs"; done)"
r=1
for j in $img_jobs; do
  s="$(tget "j:$j:scripts")"; all=0
  for img in birdcage mockingbird nightjar smb-lure holder opencanary; do
    grep -qE "(^|[^A-Za-z0-9_-])$img([^A-Za-z0-9_-]|$)" <<< "$s" || all=1
  done
  [ "$all" = 0 ] && r=0
done
check "the trivy image job covers birdcage mockingbird nightjar smb-lure holder opencanary" "$r" "not all six image names appear in a trivy image job"

check "no job pulls an aquasec/trivy image" "$(tf [ "$(tget aquasec_image)" = 0 ])" "aquasec/trivy named in $ci"
check "no job uses trivy-action" "$(tf [ "$(tget trivy_action)" = 0 ])" "trivy-action named in $ci"

# Every Trivy job: installs only via ensure-trivy.sh, report-first, severity
# named, JSON report kept, database cached.
[ -n "$all_jobs" ] && r=0 || r=1
check "at least one Trivy job exists" "$r" "no job runs trivy"
for j in $all_jobs; do
  s="$(tget "j:$j:scripts")"
  check "$j installs trivy via scripts/ensure-trivy.sh" \
    "$(grep -q 'scripts/ensure-trivy.sh' <<< "$s"; echo $?)" "scripts/ensure-trivy.sh not in the job"
  check "$j is allow_failure: true (report first)" \
    "$(tf [ "$(tget "j:$j:allow_failure")" = True ])" "allow_failure is '$(tget "j:$j:allow_failure")'"
  check "$j keeps a JSON report as an artifact" \
    "$([ -n "$(tget "j:$j:artifact_paths")" ] && grep -qE -- '(--format|-f)[ =]json' <<< "$s"; echo $?)" \
    "artifact paths '$(tget "j:$j:artifact_paths")' / no --format json"
  check "$j names --severity HIGH,CRITICAL" \
    "$(grep -qE -- '--severity[ =]"?HIGH,CRITICAL' <<< "$s"; echo $?)" "no --severity HIGH,CRITICAL"
  check "$j caches the vulnerability database through cache:" \
    "$(tf [ "$(tget "j:$j:cache")" = 1 ])" "no cache: entry"
done

# The database is cached, never committed.
tracked="$(git -C "$repo_root" ls-files | grep -E '(^|/)(trivy-db|db\.tar\.gz)|\.db$' || true)"
check "no Trivy database path is tracked in git (trivy-db, db.tar.gz, *.db)" \
  "$(tf [ -z "$tracked" ])" "tracked: $tracked"

# Trivy's ignore list is .trivyignore.yaml only (#199 triage): the YAML form
# can scope an entry to paths, which the plain .trivyignore cannot, so a
# misconfiguration accepted for one Dockerfile does not hide it in another.
# Every entry has a statement (the reason) and an expired_at date; every
# misconfiguration entry names the files it covers; every trivy command
# passes it with --ignorefile.
check "there is no plain .trivyignore (the YAML file is the only ignore list)" \
  "$(tf [ ! -e "$repo_root/.trivyignore" ])" "found $repo_root/.trivyignore"
ignres="$(python3 -I - "$repo_root" "$ci" <<'PY'
import datetime, os, re, sys, yaml
root, ci = sys.argv[1], sys.argv[2]
path = os.path.join(root, ".trivyignore.yaml")
if not os.path.isfile(path):
    print("missing")
doc = (yaml.safe_load(open(path)) or {}) if os.path.isfile(path) else {}
for sec in ("vulnerabilities", "misconfigurations", "secrets", "licenses"):
    for i, e in enumerate(doc.get(sec) or []):
        tag = "%s[%d] %s" % (sec, i, e.get("id"))
        if not str(e.get("statement") or "").strip():
            print("bad=%s: no statement" % tag)
        exp = e.get("expired_at")
        if not isinstance(exp, (datetime.date, datetime.datetime)) and not re.match(r"^\d{4}-\d{2}-\d{2}$", str(exp or "")):
            print("bad=%s: no expired_at date" % tag)
        if sec == "misconfigurations":
            paths = e.get("paths") or []
            if not paths:
                print("bad=%s: no paths" % tag)
            for q in paths:
                if not os.path.isfile(os.path.join(root, "build", q)) and not os.path.isfile(os.path.join(root, q)):
                    print("bad=%s: path %s does not exist" % (tag, q))
                print("mis=%s %s" % (e.get("id"), os.path.normpath(q)))
        if sec == "vulnerabilities":
            print("vuln=%s" % e.get("id"))
class L(yaml.SafeLoader):
    pass
L.add_multi_constructor("!", lambda loader, suffix, node: None)
cfg = yaml.load(open(ci), Loader=L)
for name, job in cfg.items():
    if not isinstance(job, dict):
        continue
    for l in job.get("script") or []:
        if not isinstance(l, str):
            continue
        for line in l.splitlines():
            if re.search(r"\btrivy\s+(config|fs|image)\b", line) and "--ignorefile .trivyignore.yaml" not in line:
                print("noignore=%s" % name)
PY
)" || { echo "FAIL could not read .trivyignore.yaml"; exit 1; }
check ".trivyignore.yaml exists" "$(grep -qx missing <<< "$ignres" && echo 1 || echo 0)" "missing"
check ".trivyignore.yaml entries carry a statement, an expiry, and (misconfigurations) existing paths" \
  "$(tf [ -z "$(grep '^bad=' <<< "$ignres" || true)" ])" "$({ grep '^bad=' <<< "$ignres" || true; } | tr '\n' ' ')"
check "every trivy command passes --ignorefile .trivyignore.yaml" \
  "$(tf [ -z "$(grep '^noignore=' <<< "$ignres" || true)" ])" "$({ grep '^noignore=' <<< "$ignres" || true; } | sort -u | tr '\n' ' ')"
for id in CVE-2026-115775 CVE-2026-115776 CVE-2026-115778 GHSA-vpp8-g58w-m8mp; do
  check "twisted $id stays ignored until 26.10.0 (#236)" "$(grep -qx "vuln=$id" <<< "$ignres"; echo $?)" "not in vulnerabilities"
done
# DS-0002 (image user is root) is accepted for exactly these six files: the
# five test-only e2e images and smb-lure, whose Dockerfile documents why smbd
# must start as root and how root is contained. Never the birdcage image.
want="$(printf 'mis=DS-0002 %s/Dockerfile\n' e2e-dns e2e-mail e2e-samba e2e-smbclient e2e-snmp smb-lure | sort)"
got="$({ grep '^mis=DS-0002 ' <<< "$ignres" || true; } | sed 's#^mis=DS-0002 build/#mis=DS-0002 #' | sort)"
check "DS-0002 is ignored for exactly the five e2e images and smb-lure" "$(tf [ "$want" = "$got" ])" "got: $(tr '\n' ' ' <<< "$got")"

# 7. Inventory and staleness (#199 item 3): Trivy has a row like gitleaks, and
#    scripts/staleness-check.py reads the pin the way it reads the other ensure
#    scripts' (read_version_var on scripts/ensure-<tool>.sh, variable
#    <TOOL>_VERSION, a tool:<name> row from check_tools).
inv="$repo_root/supply-chain/dependency-inventory.md"
check "dependency-inventory.md has a Trivy row naming scripts/ensure-trivy.sh" \
  "$(grep -E "^\\| *[0-9]+ *\\| *\`trivy\`" "$inv" | grep -q 'scripts/ensure-trivy.sh'; echo $?)" "no table row for \`trivy\` naming scripts/ensure-trivy.sh"
pin="$(python3 -I - "$here/staleness-check.py" "$repo_root" <<'PY' 2>&1 || true
import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("sc", sys.argv[1])
sc = importlib.util.module_from_spec(spec); spec.loader.exec_module(sc)
root = sys.argv[2]
class F:
    def get(self, url, headers=None):
        return True, json.dumps({"tag_name": "v9.9.9"}).encode(), None
    def head_digest(self, url, headers=None):
        return False, None, "HTTP 404"
v = sc.read_version_var(os.path.join(root, "scripts", "ensure-trivy.sh"), "TRIVY_VERSION")
rows = [r for r in sc.check_tools(root, F()) if r.id == "tool:trivy"]
print("pin=%s rows=%d status=%s" % (v, len(rows), rows[0].status if rows else "-"))
PY
)"
check "staleness-check.py reads TRIVY_VERSION from scripts/ensure-trivy.sh (0.76.2) into a tool:trivy row" \
  "$(grep -qE '^pin=v?0\.76\.2 rows=1 status=behind$' <<< "$pin"; echo $?)" "$pin"

# 8. Registry credentials reach $CI_REGISTRY only (#199). Trivy v0.76.2 adds
#    TRIVY_USERNAME/TRIVY_PASSWORD (--username/--password) as basic auth on
#    every registry it contacts, including the vulnerability-DB registries
#    (pkg/remote/remote.go authOptions, used by pkg/db Download), so those
#    would carry the job token off this host. scan:trivy-images instead gets
#    a DOCKER_CONFIG whose auths name $CI_REGISTRY only, and no Trivy job
#    sets credentials in variables, before_script or flags.
creds="$(python3 -I - "$ci" <<'PY'
import re, sys, yaml
class L(yaml.SafeLoader):
    pass
L.add_multi_constructor("!", lambda loader, suffix, node: None)
doc = yaml.load(open(sys.argv[1]), Loader=L)
def lines(job, key):
    out = []
    for l in job.get(key) or []:
        if isinstance(l, str):
            out += l.splitlines()
    return out
for name, job in doc.items():
    if not isinstance(job, dict):
        continue
    text = "\n".join(lines(job, "script") + lines(job, "before_script"))
    if "trivy" not in text and name != "scan:trivy-images":
        continue
    for k in (job.get("variables") or {}):
        if re.match(r"TRIVY_(USERNAME|PASSWORD|REGISTRY_TOKEN)$", k):
            print("cred-var=%s:%s" % (name, k))
    for l in lines(job, "before_script"):
        if re.search(r"CI_REGISTRY_PASSWORD|CI_JOB_TOKEN|TRIVY_PASSWORD", l):
            print("cred-before=%s" % name)
    for l in lines(job, "script"):
        if re.search(r"\btrivy\b.*(--username|--password|--registry-token)", l):
            print("cred-flag=%s" % name)
        if re.search(r"\bTRIVY_(USERNAME|PASSWORD|REGISTRY_TOKEN)=", l):
            print("cred-inline=%s" % name)
    if name == "scan:trivy-images":
        s = "\n".join(lines(job, "script"))
        print("docker-config=%s" % bool(re.search(r"DOCKER_CONFIG=", s)))
        print("auths-ci-registry=%s" % bool(re.search(r"auths.*\$\{?CI_REGISTRY\}?", s, re.S)))
PY
)" || { echo "FAIL could not read Trivy jobs from $ci"; exit 1; }
if grep -q '^cred-' <<< "$creds"; then
  check "no Trivy job passes registry credentials by variable, before_script or flag" 1 "$(grep '^cred-' <<< "$creds" | tr '\n' ' ')"
else
  check "no Trivy job passes registry credentials by variable, before_script or flag" 0 ""
fi
check "scan:trivy-images sets DOCKER_CONFIG in its script" "$(grep -qx 'docker-config=True' <<< "$creds"; echo $?)" "$creds"
check "scan:trivy-images's docker config auths name \$CI_REGISTRY" "$(grep -qx 'auths-ci-registry=True' <<< "$creds"; echo $?)" "$creds"

# 9. Semgrep CE (#199, owner decision 70a): report-only job on the official
#    image pinned by digest, logged out, metrics off, rule sets fetched at run
#    time. Written from the specification before the job exists.
sg="$(python3 -I - "$ci" <<'PY'
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
print("var-image=%s" % gvars.get("SEMGREP_IMAGE", ""))
job = doc.get("lint:semgrep")
print("exists=%s" % isinstance(job, dict))
job = job if isinstance(job, dict) else {}
img = job.get("image")
if isinstance(img, dict):
    img = img.get("name")
print("image=%s" % expand(img) if isinstance(img, str) else "image=")
print("allow-failure=%s" % job.get("allow_failure"))
print("stage=%s" % job.get("stage"))
lines = []
for line in job.get("script") or []:
    if isinstance(line, str):
        lines += [l.strip() for l in line.splitlines()]
for l in lines:
    print("line=" + l)
    if re.search(r"\bsemgrep\s+(scan|ci)\b", l):
        print("scan=" + l)
for l in lines:
    if re.search(r"semgrep\s+login|SEMGREP_APP_TOKEN", l):
        print("login=" + l)
    if re.search(r";\s*rc=\$\?", l):
        print("semi-rc=" + l)
    if re.search(r"\|\|\s*rc=\$\?", l):
        print("or-rc=" + l)
    if re.search(r"exit\s+\$\{rc:-0\}", l):
        print("exit-rc=" + l)
for k, v in (job.get("variables") or {}).items():
    if re.search(r"TOKEN|SECRET|PASSWORD|PASSWD|KEY|CREDENTIAL|CERT", k, re.I) or isinstance(v, dict):
        print("secret-var=%s" % k)
if "cache" in job:
    print("cache=1")
for name, other in doc.items():
    if name == "lint:semgrep" or not isinstance(other, dict):
        continue
    needs = other.get("needs") or []
    for n in needs if isinstance(needs, list) else [needs]:
        n = n.get("job") if isinstance(n, dict) else n
        if n == "lint:semgrep":
            print("needed-by=" + name)
art = job.get("artifacts") or {}
print("art-paths=%s" % " ".join(art.get("paths") or []))
print("art-expire=%s" % art.get("expire_in"))
print("art-when=%s" % art.get("when"))
PY
)" || { echo "FAIL could not read lint:semgrep from $ci"; exit 1; }
sgl() { grep "^$1=" <<< "$sg" || true; }
check "lint:semgrep exists" "$(grep -qx 'exists=True' <<< "$sg"; echo $?)" "no such job"
check "lint:semgrep is allow_failure (report-only first)" "$(grep -qx 'allow-failure=True' <<< "$sg"; echo $?)" "$(sgl allow-failure)"
check "lint:semgrep is in the lint stage" "$(grep -qx 'stage=lint' <<< "$sg"; echo $?)" "$(sgl stage)"
check "SEMGREP_IMAGE pins semgrep/semgrep:1.185.0 by @sha256 digest" \
  "$(grep -qE '^var-image=semgrep/semgrep:1\.185\.0@sha256:[0-9a-f]{64}$' <<< "$sg"; echo $?)" "$(sgl var-image)"
check "lint:semgrep runs on that pinned image" \
  "$(grep -qE '^image=semgrep/semgrep:1\.185\.0@sha256:[0-9a-f]{64}$' <<< "$sg"; echo $?)" "$(sgl image)"
check "no :latest semgrep image anywhere in $ci" "$(tf bash -c '! grep -qE "semgrep/semgrep:latest" "$1"' _ "$ci")" "semgrep/semgrep:latest named"
scans="$(sgl scan)"
check "lint:semgrep has at least one semgrep scan command" "$(tf [ -n "$scans" ])" "no semgrep scan line"
r=0; [ -n "$scans" ] || r=1
while IFS= read -r l; do [ -z "$l" ] || grep -q -- '--metrics=off' <<< "$l" || r=1; done <<< "$scans"
check "every semgrep command passes --metrics=off" "$r" "$scans"
check "lint:semgrep uses p/golang" "$(grep -q 'config[ =]p/golang' <<< "$scans"; echo $?)" "$scans"
check "lint:semgrep uses p/typescript" "$(grep -q 'config[ =]p/typescript' <<< "$scans"; echo $?)" "$scans"
check "lint:semgrep never logs in or uses SEMGREP_APP_TOKEN" "$(tf [ -z "$(sgl login)" ])" "$(sgl login)"
check "lint:semgrep defines no secret-like variables" "$(tf [ -z "$(sgl secret-var)" ])" "$(sgl secret-var)"
check "lint:semgrep has no cache" "$(tf [ -z "$(sgl cache)" ])" "cache set"
check "no job needs lint:semgrep" "$(tf [ -z "$(sgl needed-by)" ])" "$(sgl needed-by | tr '\n' ' ')"
check "lint:semgrep keeps semgrep-report/ for 30 days, when always" \
  "$(grep -qE '^art-paths=.*semgrep-report/?( |$)' <<< "$sg" && grep -qx 'art-expire=30 days' <<< "$sg" && grep -qx 'art-when=always' <<< "$sg"; echo $?)" "$(sgl art-paths) $(sgl art-expire) $(sgl art-when)"
check "lint:semgrep writes the JSON report to semgrep-report/semgrep.json" \
  "$(grep -q 'semgrep-report/semgrep.json' <<< "$scans"; echo $?)" "$scans"
check "lint:semgrep keeps the exit code with '|| rc=\$?' and 'exit \${rc:-0}'" \
  "$(grep -q '^or-rc=' <<< "$sg" && grep -q '^exit-rc=' <<< "$sg"; echo $?)" "no '|| rc=\$?' / exit \${rc:-0}"
check "lint:semgrep does not capture the exit code with '; rc=\$?'" "$(tf [ -z "$(sgl semi-rc)" ])" "$(sgl semi-rc)"
check "dependency-inventory.md has a semgrep row 253 naming 1.185.0 and the Semgrep Rules License" \
  "$(grep -E '^\| *253 *\| *`semgrep`' "$inv" | grep -q '1\.185\.0' && grep -E '^\| *253 *\| *`semgrep`' "$inv" | grep -q 'Semgrep Rules License'; echo $?)" "no row 253 for \`semgrep\`"
check "docs/ci-hops.md has a lint:semgrep row" \
  "$(grep -qE '^\| *`lint:semgrep` *\|' "$repo_root/docs/ci-hops.md"; echo $?)" "no lint:semgrep row"

# 7. Supply-chain pins (#234, #181). pin_failures <ci file> prints one line
#    per breach: PYTHON_ALPINE_IMAGE without a sha256 digest (as
#    DOCKER_CLI_IMAGE has), or a `pip install` without --require-hashes.
pin_failures() {
  python3 -I - "$1" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
m = re.search(r"^\s*PYTHON_ALPINE_IMAGE:\s*(\S+)", text, re.M)
if not m or not re.fullmatch(r"python:[^@\s]+@sha256:[0-9a-f]{64}", m.group(1).strip("'\"")):
    print("PYTHON_ALPINE_IMAGE is not python:<tag>@sha256:<digest>: %s" % (m.group(1) if m else "missing"))
for n, line in enumerate(text.splitlines(), 1):
    code = line.split("#", 1)[0]
    if re.search(r"\bpip3?\s+install\b", code) and "--require-hashes" not in code:
        print("line %d: pip install without --require-hashes: %s" % (n, line.strip()))
PY
}
pf="$(pin_failures "$ci")"
check "PYTHON_ALPINE_IMAGE is pinned by sha256 digest" "$(tf bash -c '! grep -q "^PYTHON_ALPINE_IMAGE" <<< "$1"' _ "$pf")" "$(grep '^PYTHON_ALPINE_IMAGE' <<< "$pf")"
check "every pip install in .gitlab-ci.yml uses --require-hashes" "$(tf bash -c '! grep -q "pip install" <<< "$1"' _ "$pf")" "$(grep 'pip install' <<< "$pf" | head -3 | tr '\n' ';')"

# Self-test: the checks above must fail on a digest-less image and on a bare
# pip install, so they cannot pass by finding nothing.
st="$(mktemp -d)"; trap 'rm -rf "$st"' EXIT
sed -E 's#^(\s*PYTHON_ALPINE_IMAGE:\s*python:[^@[:space:]]+)@sha256:[0-9a-f]{64}#\1#' "$ci" > "$st/nodigest.yml"
check "self-test: a PYTHON_ALPINE_IMAGE without digest is caught" \
  "$(tf bash -c 'grep -q "^PYTHON_ALPINE_IMAGE" <<< "$1"' _ "$(pin_failures "$st/nodigest.yml")")" "not caught"
{ cat "$ci"; printf '\n_selftest:\n  script:\n    - pip install pyyaml\n'; } > "$st/barepip.yml"
check "self-test: a bare pip install pyyaml is caught" \
  "$(tf bash -c 'grep -q "pip install pyyaml" <<< "$1"' _ "$(pin_failures "$st/barepip.yml")")" "not caught"
printf 'variables:\n  PYTHON_ALPINE_IMAGE: python:3.15-alpine@sha256:%064d\nj:\n  script:\n    - pip install --require-hashes -r r.txt\n' 0 > "$st/good.yml"
check "self-test: a pinned image and hashed pip install pass" "$(tf [ -z "$(pin_failures "$st/good.yml")" ])" "$(pin_failures "$st/good.yml")"

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
