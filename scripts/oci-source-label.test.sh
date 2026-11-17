#!/usr/bin/env bash
# Every image build:images builds carries the OCI source label (#167).
#
# GHCR connects a pushed package to its repository from
# org.opencontainers.image.source; without it each package page shows no
# repository and the countersigning workflow needs a manual grant per package.
# The label must point at https://github.com/tomlawesome/birdcage and be set
# either by --label on the docker build command in build:images (covers all
# images) or by a LABEL in the final stage of each image's Dockerfile.
#
# The image list is read from build:images' `for name in ...` loop, so an image
# added to the loop later without a label fails here. Cases: the real tree,
# then fixtures (correct via --label, correct via Dockerfiles, one Dockerfile
# left out, wrong URL) to show the check itself passes and fails correctly.
#
# Runs in lint:scripts (every scripts/*.test.sh); needs python3 with PyYAML.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"
pass=0; fail=0
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

check() { # name, ok(0/1), detail
  if [ "$2" -eq 0 ]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: $3"; fi
}

# label_report <root>: prints "<image>\tok|missing|wrong" per image in the
# build:images loop, or "ERROR\t<why>" if the job cannot be read.
label_report() {
  python3 -I - "$1" <<'PY'
import re, sys, os, yaml
KEY = "org.opencontainers.image.source"
URL = "https://github.com/tomlawesome/birdcage"
root = sys.argv[1]
class L(yaml.SafeLoader):
    pass
L.add_multi_constructor("!", lambda loader, suffix, node: None)
try:
    doc = yaml.load(open(os.path.join(root, ".gitlab-ci.yml")), Loader=L)
    script = "\n".join(str(s) for s in doc["build:images"]["script"])
except Exception as e:
    print("ERROR\tcannot read build:images: %s" % e); sys.exit(0)
m = re.search(r"for\s+name\s+in\s+([^;\n]+?)\s*;\s*do", script)
if not m:
    print("ERROR\tno `for name in ...` loop in build:images"); sys.exit(0)
names = m.group(1).split()
build = re.search(r"docker build\b(?:[^\n]*\\\n)*[^\n]*", script)
build = build.group(0) if build else ""
def values(text):
    return re.findall(re.escape(KEY) + r"""[=\s]+["']?([^\s"'\\]+)""", text)
cmd_vals = [v for lab in re.findall(r"--label[=\s]+(\S+)", build) for v in values(lab)]
for n in names:
    vals = list(cmd_vals)
    df = os.path.join(root, "build", n, "Dockerfile")
    if os.path.exists(df):
        stages = re.split(r"(?im)^FROM\b", open(df).read())
        last = stages[-1]
        for line in re.findall(r"(?im)^LABEL\b(?:[^\n]*\\\n)*[^\n]*", last):
            vals += values(line)
    if not vals:
        print("%s\tmissing" % n)
    elif URL in vals and all(v == URL for v in vals):
        print("%s\tok" % n)
    else:
        print("%s\twrong" % n)
PY
}

# expect <name> <root> <want: pass|fail>
expect() {
  local out bad=0 n=0 line
  out="$(label_report "$2")"
  while IFS=$'\t' read -r img st; do
    [ -n "$img" ] || continue
    n=$((n + 1))
    if [ "$img" = "ERROR" ]; then bad=1; echo "     $st"
    elif [ "$st" != "ok" ]; then bad=1; echo "     $img: label $st"; fi
  done <<< "$out"
  [ "$n" -gt 0 ] || bad=1
  if [ "$3" = pass ]; then
    check "$1" "$bad" "not every image carries the source label"
  else
    check "$1" "$((1 - bad))" "expected the check to reject this config"
  fi
}

mkfix() { # dir, kind: cmd|dockerfiles|partial|wrong
  local d="$1" k="$2" lab='--label org.opencontainers.image.source=https://github.com/tomlawesome/birdcage'
  mkdir -p "$d/build/a" "$d/build/b"
  [ "$k" = cmd ] || lab=""
  [ "$k" = wrong ] && lab='--label org.opencontainers.image.source=https://example.invalid/x'
  cat > "$d/.gitlab-ci.yml" <<YML
build:images:
  script:
    - |
      for name in a b; do
        docker build --build-arg V=1 $lab \\
          --file "build/\${name}/Dockerfile" .
      done
YML
  printf 'FROM scratch\n' > "$d/build/a/Dockerfile"
  printf 'FROM scratch\n' > "$d/build/b/Dockerfile"
  case "$k" in
    dockerfiles) for i in a b; do echo 'LABEL org.opencontainers.image.source="https://github.com/tomlawesome/birdcage"' >> "$d/build/$i/Dockerfile"; done ;;
    partial) echo 'LABEL org.opencontainers.image.source="https://github.com/tomlawesome/birdcage"' >> "$d/build/a/Dockerfile" ;;
  esac
}

for k in cmd dockerfiles; do mkfix "$tmp/$k" "$k"; done
for k in partial wrong; do mkfix "$tmp/$k" "$k"; done

expect "fixture: --label on the build command passes" "$tmp/cmd" pass
expect "fixture: LABEL in every Dockerfile passes" "$tmp/dockerfiles" pass
expect "fixture: an image left out is rejected" "$tmp/partial" fail
expect "fixture: wrong source URL is rejected" "$tmp/wrong" fail
expect "build:images: every image carries the OCI source label" "$repo_root" pass

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
