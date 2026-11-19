#!/usr/bin/env bash
# Pins the verifier identity of the keyless countersignature (#169, item C).
# Every keyless `cosign verify` in the docs, scripts and CI config must
# require the exact workflow identity
#   https://github.com/tomlawesome/birdcage/.github/workflows/countersign.yml@refs/heads/main
# (the project's own owner and repository, as docs/releasing.md names them)
# via --certificate-identity, plus the GitHub OIDC issuer. A repo-wide
# regexp would accept a signature made by any workflow on any ref, which is
# what a pushed rogue branch would produce. The same scan is then run on
# scratch trees to prove a signature identity from another workflow, another
# ref, or a loose regexp is refused.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0
issuer='https://token.actions.githubusercontent.com'

# check <root>: prints one line per violation; exit 0 always.
check() {
  python3 -I - "$1" "$issuer" <<'PY'
import glob, os, re, sys
root, issuer = sys.argv[1], sys.argv[2]
files = glob.glob(os.path.join(root, "docs/**/*.md"), recursive=True)
files += [f for f in glob.glob(os.path.join(root, "scripts/*")) if os.path.isfile(f) and not f.endswith(".test.sh")]
files += [os.path.join(root, ".gitlab-ci.yml")]
files += glob.glob(os.path.join(root, ".github/workflows/*.y*ml"))
exact = re.compile(r"^https://github\.com/tomlawesome/birdcage/\.github/workflows/countersign\.yml@refs/heads/main$")
found_keyless = False
out = []
for f in sorted(files):
    try: text = open(f, errors="replace").read()
    except OSError: continue
    rel = os.path.relpath(f, root)
    # one logical command: join backslash continuations
    flat = re.sub(r"\\\n\s*", " ", text)
    for line in flat.splitlines():
        if "--certificate-identity-regexp" in line or re.search(r"--certificate-identity[= ]", line):
            if "--certificate-identity-regexp" in line:
                m = re.search(r"--certificate-identity-regexp[= ]+['\"]?([^'\" ]+)", line)
                out.append(f"{rel}: certificate-identity-regexp is not allowed ({m.group(1) if m else '?'})")
            m = re.search(r"--certificate-identity[= ]+['\"]?([^'\" ]+)", line)
            if m and "-regexp" not in line[m.start():m.start()+30]:
                found_keyless = True
                if not exact.match(m.group(1)):
                    out.append(f"{rel}: identity not pinned to countersign.yml@refs/heads/main ({m.group(1)})")
                if issuer not in line:
                    out.append(f"{rel}: identity pinned but the GitHub OIDC issuer is missing")
                t = re.search(r"--certificate-github-workflow-trigger[= ]+['\"]?([^'\" ]+)", line)
                if not t:
                    out.append(f"{rel}: workflow trigger not pinned (--certificate-github-workflow-trigger workflow_dispatch)")
                elif t.group(1) != "workflow_dispatch":
                    out.append(f"{rel}: workflow trigger pinned to {t.group(1)}, want workflow_dispatch")
if not found_keyless:
    out.append("no keyless `cosign verify --certificate-identity` found anywhere")
print("\n".join(out))
PY
}

scratch() {
  local d="$work/$1"; rm -rf "$d"; mkdir -p "$d"
  cp -r "$repo/docs" "$repo/scripts" "$repo/.gitlab-ci.yml" "$d/" 2>/dev/null || true
  cp -r "$repo/.github" "$d/.github"
  echo "$d"
}
good_cmd() {
  printf 'cosign verify \\\n  --certificate-identity %s \\\n  --certificate-oidc-issuer %s \\\n  ghcr.io/example-owner/birdcage@sha256:<digest>\n' "$1" "$issuer"
}
# expect <name> <root> <ok|refused> [needle]
expect() {
  local got; got="$(check "$2")"
  if [ "$3" = ok ]; then
    [ -z "$got" ] && { echo "ok   $1"; pass=$((pass + 1)); return; }
  else
    [ -n "$got" ] && { [ -z "${4:-}" ] || grep -qF "$4" <<<"$got"; } && { echo "ok   $1"; pass=$((pass + 1)); return; }
  fi
  echo "FAIL $1: $(echo "$got" | head -3 | tr '\n' '|')"; fail=$((fail + 1))
}

id='https://github.com/tomlawesome/birdcage/.github/workflows/countersign.yml@refs/heads/main'

expect "the real tree pins the exact workflow identity" "$repo" ok

# Scratch base: the real tree with the docs command replaced by a pinned one.
base() {
  local d; d="$(scratch "$1")"
  python3 -I - "$d/docs/releasing.md" "$2" "$issuer" <<'PY'
import re, sys
p, ident, issuer = sys.argv[1:4]
s = open(p).read()
s = re.sub(r"cosign verify \\\n  --certificate-identity(?:-regexp)? [^\n]*\n  --certificate-oidc-issuer [^\n]*\n",
           f"cosign verify \\\n  --certificate-identity {ident} \\\n  --certificate-oidc-issuer {issuer} \\\n  --certificate-github-workflow-trigger workflow_dispatch \\\n", s)
open(p, "w").write(s)
PY
  echo "$d"
}
d="$(base good "$id")"
expect "scratch base with the exact identity passes" "$d" ok
d="$(base otherwf 'https://github.com/tomlawesome/birdcage/.github/workflows/rogue.yml@refs/heads/main')"
expect "another workflow's identity is refused" "$d" refused "not pinned"
d="$(base otherref 'https://github.com/tomlawesome/birdcage/.github/workflows/countersign.yml@refs/heads/feature')"
expect "another ref's identity is refused" "$d" refused "not pinned"
d="$(base tagref 'https://github.com/tomlawesome/birdcage/.github/workflows/countersign.yml@refs/tags/v1')"
expect "a tag ref's identity is refused" "$d" refused "not pinned"

d="$(base otherowner 'https://github.com/someone-else/birdcage/.github/workflows/countersign.yml@refs/heads/main')"
expect "another owner's identity is refused" "$d" refused "not pinned"
d="$(base otherrepo 'https://github.com/tomlawesome/other-repo/.github/workflows/countersign.yml@refs/heads/main')"
expect "another repository's identity is refused" "$d" refused "not pinned"
d="$(base ownerscript "$id")"
printf '#!/usr/bin/env bash\ncosign verify --certificate-identity %s --certificate-oidc-issuer %s --certificate-github-workflow-trigger workflow_dispatch "$1"\n' 'https://github.com/someone-else/birdcage/.github/workflows/countersign.yml@refs/heads/main' "$issuer" > "$d/scripts/rogue-verify.sh"
expect "a script naming another owner's workflow is refused" "$d" refused "not pinned"

d="$(base notrigger "$id")"
sed -i '/--certificate-github-workflow-trigger/d' "$d/docs/releasing.md"
expect "a docs verify command without the trigger pin is refused" "$d" refused "trigger not pinned"
d="$(base pushtrigger "$id")"
sed -i 's/--certificate-github-workflow-trigger workflow_dispatch/--certificate-github-workflow-trigger push/' "$d/docs/releasing.md"
expect "a trigger pinned to push is refused" "$d" refused "want workflow_dispatch"
d="$(base scripttrigger "$id")"
printf '#!/usr/bin/env bash\ncosign verify --certificate-identity %s --certificate-oidc-issuer %s "$1"\n' "$id" "$issuer" > "$d/scripts/rogue-verify.sh"
expect "a script verify command without the trigger pin is refused" "$d" refused "trigger not pinned"
d="$(base citrigger "$id")"
printf 'job:\n  script:\n    - cosign verify --certificate-identity %s --certificate-oidc-issuer %s x\n' "$id" "$issuer" >> "$d/.gitlab-ci.yml"
expect "a CI verify command without the trigger pin is refused" "$d" refused "trigger not pinned"
d="$(base regex "$id")"
printf '\n```sh\ncosign verify --certificate-identity-regexp "^https://github.com/tomlawesome/birdcage/" --certificate-oidc-issuer %s ghcr.io/x@sha256:0\n```\n' "$issuer" >> "$d/docs/releasing.md"
expect "a repo-wide regexp in the docs is refused" "$d" refused "certificate-identity-regexp"
d="$(base regex2 "$id")"
printf '#!/usr/bin/env bash\ncosign verify --certificate-identity-regexp "countersign.yml" --certificate-oidc-issuer %s "$1"\n' "$issuer" > "$d/scripts/rogue-verify.sh"
expect "a loose regexp in a script is refused" "$d" refused "certificate-identity-regexp"
d="$(base regex3 "$id")"
printf 'job:\n  script:\n    - cosign verify --certificate-identity-regexp ".*" --certificate-oidc-issuer %s x\n' "$issuer" >> "$d/.gitlab-ci.yml"
expect "a regexp in .gitlab-ci.yml is refused" "$d" refused "certificate-identity-regexp"
d="$(base noissuer "$id")"
sed -i "s|--certificate-oidc-issuer $issuer|--certificate-oidc-issuer https://example.invalid|" "$d/docs/releasing.md"
expect "the exact identity without the GitHub OIDC issuer is refused" "$d" refused "issuer"
d="$(scratch none)"; python3 -I - "$d/docs/releasing.md" <<'PY'
import re, sys
p = sys.argv[1]; s = open(p).read()
open(p, "w").write(re.sub(r"cosign verify \\\n(  [^\n]*\n)+", "", s))
PY
expect "docs with no keyless verify command at all are refused" "$d" refused "no keyless"

echo "verify-identity-pin: $pass passed, $fail failed"
[ "$fail" = 0 ]
