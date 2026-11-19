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

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
