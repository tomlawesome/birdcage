#!/usr/bin/env bash
# Tests for release-readiness.py (#215): the check that runs first on every
# promotion MR and locally before one is opened.
#
# Written from the #215 final specification (and the design check after it)
# alone, before the script existed. Every check id on both legs has a case
# where the guarded thing is wrong (FAIL, with the spec's message) and one
# where it is right (PASS).
#
# THE SEAM. Git is real: each case runs inside a scratch clone whose
# `origin` is a local bare repository, so ancestry, merge-tree, blob ids,
# authors and trailers are git's own answers. Everything else -- the
# version script, both registries, the GitLab issues API, cosign evidence,
# staleness-check rows and the clock -- comes from a JSON file passed with
# the test-only flag `--stub PATH`, read by the script's one injectable
# lookups object instead of the real one. Stub shape (all keys required by
# these tests; see mkstub below for the full default):
#
#   now              ISO-8601 UTC instant used for every date comparison
#   release_version  {exit, stdout, stderr} of scripts/release-version.sh
#   registry         {gitlab|ghcr: {<image>: {<tag>: <digest>} | "timeout"}}
#                    a tag absent from the map does not exist
#   issues           {<iid>: "opened"|"closed"}; an iid absent is "not found".
#                    Or the whole value is "timeout", "unauthorized" (HTTP
#                    401/403) or "no-credential" (local: glab missing/not
#                    logged in)
#   evidence         {<image>: {ok, recorded, expires, reason?}} as read from
#                    scripts/verify-validation-evidence.sh, or "timeout"
#   staleness        {rows: [{id, pinned, latest, status, note, released?,
#                    hold?, credential_missing?}]} as staleness-check --json
#                    would give, or "timeout". `released` is the latest
#                    version's release date (absent = unknown, counts as
#                    old); `hold` = {lapsed: "expired"|"held-at-differs",
#                    review_by} for a hold that no longer applies.
#
# A stub value of "timeout" is a lookup that hit its time limit: FAIL in CI
# (CI=true), UNCHECKED locally, never a hang (every run here is under
# `timeout 60`, and exit 124 fails the case).
#
# No network: HOME is a scratch directory (no glab login, no git config of
# the host), proxies point at a closed local port, GOPROXY=off. Fixture
# names and addresses are invented (example.invalid).
#
# Runs in lint:scripts; needs python3 with PyYAML and git >= 2.38.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"
script="$here/release-readiness.py"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

# Isolation: nothing of the host's git, glab or CI environment leaks in.
export HOME="$work/home"; mkdir -p "$HOME"
export GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 GOPROXY=off
export http_proxy=http://127.0.0.1:9 https_proxy=http://127.0.0.1:9
export HTTP_PROXY=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 no_proxy= NO_PROXY=
unset CI GITLAB_CI BIRDCAGE_READ_TOKEN CI_JOB_TOKEN CI_REGISTRY_USER CI_REGISTRY_PASSWORD \
  CI_MERGE_REQUEST_SOURCE_BRANCH_NAME CI_MERGE_REQUEST_TARGET_BRANCH_NAME \
  CI_MERGE_REQUEST_DESCRIPTION GITLAB_TOKEN GH_TOKEN 2>/dev/null || true
git config --global user.name "Fixture Bot"
git config --global user.email "fixture-bot@example.invalid"
git config --global init.defaultBranch main
git config --global advice.detachedHead false

FAKE_TOKEN="not-a-real-token-5c1a9e"
IMAGES="birdcage mockingbird opencanary nightjar smb-lure holder"

if [ ! -f "$script" ]; then
  echo "FAIL $script does not exist (tests written before the script, #215)"
fi

# --------------------------------------------------------------------------
# Assertion helpers
# --------------------------------------------------------------------------
out=""; code=0

# expect <name> <want-exit or -> <pattern>...
# A pattern is an ERE matched against any output line; `=text` matches the
# fixed string; a leading `!` negates either form.
expect() {
  local name="$1" want="$2" ok=1 why="" p neg body
  shift 2
  if [ "$want" != "-" ] && [ "$code" != "$want" ]; then ok=0; why="exit $code (want $want)"; fi
  for p in "$@"; do
    neg=0; body="$p"
    if [ "${body:0:1}" = "!" ]; then neg=1; body="${body:1}"; fi
    if [ "${body:0:1}" = "=" ]; then
      if grep -qF -- "${body:1}" <<<"$out"; then hit=1; else hit=0; fi
    else
      if grep -Eq -- "$body" <<<"$out"; then hit=1; else hit=0; fi
    fi
    if [ "$neg" = 0 ] && [ "$hit" = 0 ]; then ok=0; why="$why; missing: $body"; fi
    if [ "$neg" = 1 ] && [ "$hit" = 1 ]; then ok=0; why="$why; unexpected: $body"; fi
  done
  if [ "$ok" = 1 ]; then
    echo "ok   $name"; pass=$((pass + 1))
  else
    echo "FAIL $name: ${why#; }"
    printf '%s\n' "$out" | head -60 | sed 's/^/       /'
    fail=$((fail + 1))
  fi
}

# The `Failed:` list must repeat each named id after the per-check lines.
expect_failed_list() { # name id...
  local name="$1" tail id ok=1 why=""
  shift
  tail="$(sed -n '/^Failed:/,$p' <<<"$out" | tail -n +2)"
  if ! grep -q '^Failed:' <<<"$out"; then ok=0; why="no 'Failed:' line"; fi
  for id in "$@"; do
    grep -Eq "(^|[^A-Z0-9])$id([^0-9]|$)" <<<"$tail" || { ok=0; why="$why; $id not in Failed: list"; }
  done
  if [ "$ok" = 1 ]; then echo "ok   $name"; pass=$((pass + 1))
  else echo "FAIL $name: ${why#; }"; printf '%s\n' "$out" | sed 's/^/       /'; fail=$((fail + 1)); fi
}

# --------------------------------------------------------------------------
# Fixture: a bare origin and a clone holding main, preview and dev
# --------------------------------------------------------------------------
GUIDE='# Releasing

## The version

1. Not a release step: this list is in another section.

## Cutting a release

1. `dev` -> `preview` by merge request, as usual.
   The push pipeline publishes the six images.
2. Do the production-like manual test on `preview`.
3. `preview` -> `main` by merge request.
4. **Press the button.** Play `release:promote`.

   It refuses unless the evidence still verifies.
5. **Countersign, on GitHub.**
6. Back-merge after each promotion.

Evidence expires after seven days.

## Verifying a published image

1. Not a release step either.'

PUBKEY='-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZmFrZWZpeHR1cmVrZXlub3RyZWFsZmFr
ZWZpeHR1cmVrZXlub3RyZWFsZmFrZWZpeHR1cmVrZXlub3RyZWFsZmFrZQ==
-----END PUBLIC KEY-----'

CHANGELOG_GOOD='# Changelog

## [Unreleased]

## [0.2.0] - 2026-11-16

### Added

- Release-readiness check before every promotion.

### Fixed

- A fixture fix.

## [0.1.0] - 2026-10-03

### Added

- First release.'

STEPS_GOOD='step 1: done: pipeline 9001
step 2: after-merge
step 3: after-merge
step 4: after-merge
step 5: after-merge
step 6: after-merge'

# write_record <wt> -- writes docs/releases/v0.2.0.md from R_* variables.
write_record() {
  local wt="$1"
  mkdir -p "$wt/docs/releases"
  {
    [ "${R_NO_VERSION:-}" = 1 ] || echo "version: ${R_VERSION:-v0.2.0}"
    echo "guide-commit: ${R_COMMIT:-$GUIDE_COMMIT}"
    echo "guide-blob: ${R_BLOB:-$GUIDE_BLOB}"
    [ "${R_NO_REVIEW:-}" = 1 ] || echo "review:${R_REVIEW- #206, #213}"
    echo
    printf '%s\n' "${R_STEPS:-$STEPS_GOOD}"
    echo
    [ "${R_NO_SIGN:-}" = 1 ] || printf '%s\n' "${R_SIGN:-Signed-off-by: Fixture Bot}"
  } > "$wt/docs/releases/${R_FILE:-v0.2.0.md}"
}

# commit_record <wt> [author-name] [trailer-name or "-" for none]
commit_record() {
  local wt="$1" author="${2:-Fixture Bot}" trailer="${3:-Fixture Bot}"
  git -C "$wt" add docs/releases
  if [ "$trailer" = "-" ]; then
    git -C "$wt" -c user.name="$author" commit -q --allow-empty -m "docs: release record v0.2.0"
  else
    git -C "$wt" -c user.name="$author" commit -q --allow-empty -m "docs: release record v0.2.0" \
      --trailer "Signed-off-by: $trailer"
  fi
}

build_base() {
  local b="$work/base" wt
  mkdir -p "$b"
  git init -q --bare "$b/origin.git"
  git clone -q "$b/origin.git" "$b/wt" 2>/dev/null
  wt="$b/wt"
  mkdir -p "$wt/docs"
  echo "0.1.0" > "$wt/VERSION"
  echo "fixture project" > "$wt/README.md"
  git -C "$wt" add . && git -C "$wt" commit -q -m "release 0.1.0"
  git -C "$wt" tag v0.1.0
  echo "0.2.0" > "$wt/VERSION"
  printf '%s\n' "$GUIDE" > "$wt/docs/releasing.md"
  printf '%s\n' "$PUBKEY" > "$wt/cosign.pub"
  printf '%s\n' "$CHANGELOG_GOOD" > "$wt/CHANGELOG.md"
  git -C "$wt" add . && git -C "$wt" commit -q -m "work for 0.2.0"
  GUIDE_COMMIT="$(git -C "$wt" rev-parse HEAD)"
  GUIDE_BLOB="$(git -C "$wt" rev-parse HEAD:docs/releasing.md)"
  git -C "$wt" branch -f preview HEAD
  git -C "$wt" checkout -q -b dev
  write_record "$wt"
  commit_record "$wt"
  git -C "$wt" push -q origin main preview dev --tags 2>/dev/null
  git -C "$wt" fetch -q origin
}
build_base
export GUIDE_COMMIT GUIDE_BLOB

# newcase -- a fresh copy of the base fixture in $c; work tree $wt, on dev.
n=0
newcase() {
  n=$((n + 1)); c="$work/c$n"; cp -a "$work/base" "$c"
  git -C "$c/wt" remote set-url origin "$c/origin.git"
  wt="$c/wt"
}

# push_fetch <branch>... -- publish branches to origin and refresh refs.
push_fetch() {
  git -C "$wt" push -q -f origin "$@" 2>/dev/null
  git -C "$wt" fetch -q origin
}

# to_main_leg -- preview fast-forwards to dev; the clone stands on preview.
to_main_leg() {
  git -C "$wt" checkout -q preview
  git -C "$wt" merge -q --ff-only dev
  push_fetch preview
  printf 'Step 2: production-like test on the lab host, all six services answered\n' > "$c/desc.txt"
}

# mkstub <out> <tip-sha> [json-patch] -- default stub where everything is
# right; the patch is deep-merged, a null deletes the key.
cat > "$work/mkstub.py" <<'PY'
import json, sys
out, tip = sys.argv[1], sys.argv[2]
patch = json.loads(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else {}
images = ["birdcage", "mockingbird", "opencanary", "nightjar", "smb-lure", "holder"]
def digest(i, n):
    return "sha256:" + format(i * 16 + n, "x").rjust(64, "0")
gitlab, ghcr, evidence = {}, {}, {}
for i, img in enumerate(images, 1):
    d, att = digest(i, 1), digest(i, 2)
    gitlab[img] = {"sha-" + tip: d, "preview": d, "v0.1.0": digest(i, 9)}
    ghcr[img] = {"preview": d, "sha256-" + d.split(":")[1]: att, "v0.1.0": digest(i, 9)}
    evidence[img] = {"ok": True, "recorded": "2026-11-15T10:00:00Z",
                     "expires": "2026-11-22T10:00:00Z"}
stub = {
    "now": "2026-11-17T12:00:00Z",
    "release_version": {"exit": 0, "stdout": "0.2.0\n", "stderr": ""},
    "registry": {"gitlab": gitlab, "ghcr": ghcr},
    "issues": {"206": "closed", "213": "closed"},
    "evidence": evidence,
    "staleness": {"rows": [
        {"id": "apk:build/mockingbird/Dockerfile:python3", "pinned": "3.12.4-r0",
         "latest": "3.12.4-r0", "status": "current", "note": ""},
        {"id": "go:example.invalid/fixture/mod", "pinned": "1.2.0", "latest": "1.2.0",
         "status": "current", "note": ""},
        {"id": "pypi:fixture-held", "pinned": "3.2.0", "latest": "4.0.0",
         "status": "accepted", "note": "held until 2026-12-27"},
        {"id": "image:fixture-floating", "pinned": "latest", "latest": "latest",
         "status": "floating", "note": ""},
    ]},
}
def merge(a, b):
    for k, v in b.items():
        if v is None:
            a.pop(k, None)
        elif isinstance(v, dict) and isinstance(a.get(k), dict):
            merge(a[k], v)
        else:
            a[k] = v
merge(stub, patch)
json.dump(stub, open(out, "w"), indent=1)
PY

# stub [json-patch] -- writes $c/stub.json for the clone's current HEAD.
stub() {
  python3 -I "$work/mkstub.py" "$c/stub.json" "$(git -C "$wt" rev-parse HEAD)" "${1:-}"
}

# run <args...> -- runs the script in the clone with the stub; sets out/code.
# Environment for CI runs is given as prefix assignments on the call.
run() {
  out="$(cd "$wt" && timeout 60 python3 "$script" --stub "$c/stub.json" "$@" 2>&1)" && code=0 || code=$?
}
prev() { run --target preview --remote origin "$@"; }
mainleg() { run --target main --remote origin --description-file "$c/desc.txt" "$@"; }

# A row helper for staleness patches: behind <id> [released-date]
behind_row() {
  if [ -n "${2:-}" ]; then
    printf '{"id":"%s","pinned":"1.0.0","latest":"1.1.0","status":"behind","note":"","released":"%s"}' "$1" "$2"
  else
    printf '{"id":"%s","pinned":"1.0.0","latest":"1.1.0","status":"behind","note":""}' "$1"
  fi
}
ROWS_OK='{"id":"apk:build/mockingbird/Dockerfile:python3","pinned":"3.12.4-r0","latest":"3.12.4-r0","status":"current","note":""}'

# ==========================================================================
# Group A: the all-good runs, output format, every id present
# ==========================================================================
newcase; stub; prev
expect "A1 preview leg, everything right: exit 0" 0 \
  '^PASS P1 [^:]*:' '^PASS P2 [^:]*:' '^PASS P3 [^:]*:' '^PASS P4 [^:]*:' \
  '^PASS P5 [^:]*:' '^PASS P6 [^:]*:' '^PASS P7 [^:]*:' '^PASS S1 [^:]*:' \
  '^PASS S2 [^:]*:' '^PASS K1 [^:]*:' '^PASS R1 [^:]*:' '!^FAIL ' '!^UNCHECKED '
expect "A2 preview leg prints no main-leg ids" - '!^[A-Z]+ M[0-9] '

newcase; to_main_leg; stub; mainleg
expect "A3 main leg, everything right: exit 0" 0 \
  '^PASS M1 [^:]*:' '^PASS M2 [^:]*:' '^PASS M3 [^:]*:' '^PASS M4 [^:]*:' \
  '^PASS M5 [^:]*:' '^PASS M6 [^:]*:' '^PASS M7 [^:]*:' '^PASS M8 [^:]*:' \
  '^PASS M9 [^:]*:' '^PASS S1 [^:]*:' '^PASS S2 [^:]*:' '^PASS K1 [^:]*:' \
  '!^FAIL ' '!^UNCHECKED '
expect "A4 main leg prints no preview-leg ids" - '!^[A-Z]+ (P[0-9]|R1) '

expect "A5 every check line has the form STATUS ID NAME: MESSAGE" - \
  '!^(PASS|FAIL|UNCHECKED|INFO) [A-Z][0-9]+ *:'
# (a line with a status word must carry a name between id and colon)

# ==========================================================================
# Group B: exit codes, keep-going, Failed: list
# ==========================================================================
newcase
git -C "$wt" rm -q CHANGELOG.md && git -C "$wt" commit -q -m "drop changelog" && push_fetch dev
stub '{"release_version":{"exit":1,"stdout":"","stderr":"release-version: VERSION holds 0.2"}}'
prev
expect "B1 an early failure (P1) does not stop the run: every id still reported, exit 1" 1 \
  '^FAIL P1 ' '^FAIL P4 ' '^[A-Z]+ P2 ' '^[A-Z]+ P3 ' '^[A-Z]+ P5 ' '^[A-Z]+ P6 ' \
  '^[A-Z]+ P7 ' '^[A-Z]+ S1 ' '^[A-Z]+ S2 ' '^PASS K1 ' '^[A-Z]+ R1 '
expect_failed_list "B2 the Failed: list repeats each FAIL" P1 P4
expect "B3 the Failed: list says what to do" - '=docs/releasing.md'

newcase; stub '{"issues":"no-credential"}'; prev
expect "B4 local run, only UNCHECKED (no glab login): exit 3" 3 '^UNCHECKED P5 ' '!^FAIL '

newcase; stub '{"issues":"no-credential","registry":{"gitlab":{"holder":{"v0.2.0":"sha256:aa"}}}}'; prev
expect "B5 FAIL and UNCHECKED together: exit 1" 1 '^UNCHECKED P5 ' '^FAIL P3 '

newcase; stub
run --target staging --remote origin
expect "B6 unknown --target: usage error, exit 2" 2
run --remote origin
expect "B7 missing --target: usage error, exit 2" 2
run --target preview --remote origin --no-such-flag
expect "B8 unknown flag: usage error, exit 2" 2
out="$(cd "$work" && timeout 60 python3 "$script" --stub "$c/stub.json" --target preview 2>&1)" && code=0 || code=$?
expect "B9 run outside a git repository: internal error, exit 2" 2

newcase; stub '{"issues":"timeout"}'; prev
expect "B10 local: a timed-out lookup is UNCHECKED, exit 3, no hang" 3 '^UNCHECKED P5 '
CI=true BIRDCAGE_READ_TOKEN="$FAKE_TOKEN" CI_MERGE_REQUEST_SOURCE_BRANCH_NAME=dev \
  CI_MERGE_REQUEST_TARGET_BRANCH_NAME=preview prev
expect "B11 CI: a timed-out lookup is FAIL (CI never exits 3)" 1 '^FAIL P5 ' '!^UNCHECKED '

newcase; stub '{"registry":{"gitlab":{"nightjar":"timeout"}}}'; prev
expect "B12 local: registry timeout is UNCHECKED" 3 '^UNCHECKED P3 '
CI=true BIRDCAGE_READ_TOKEN="$FAKE_TOKEN" CI_MERGE_REQUEST_SOURCE_BRANCH_NAME=dev prev
expect "B13 CI: registry timeout is FAIL" 1 '^FAIL P3 ' '!^UNCHECKED '

newcase; stub; CI=true BIRDCAGE_READ_TOKEN="$FAKE_TOKEN" CI_MERGE_REQUEST_SOURCE_BRANCH_NAME=dev \
  CI_MERGE_REQUEST_TARGET_BRANCH_NAME=preview prev
expect "B14 CI run with everything right: exit 0" 0 '!^FAIL ' '!^UNCHECKED '

# ==========================================================================
# Group C: P1-P3 and M3 (version)
# ==========================================================================
newcase; stub '{"release_version":{"exit":1,"stdout":"","stderr":"release-version: not a plain version"}}'; prev
expect "C1 P1 fails when release-version.sh exits non-zero" 1 \
  '^FAIL P1 ' '=MAJOR.MINOR.PATCH'

newcase; git -C "$wt" tag v0.2.0 && git -C "$wt" push -q origin v0.2.0 2>/dev/null; stub; prev
expect "C2 P2 fails when tag v0.2.0 already exists on the remote" 1 \
  '^FAIL P2 ' '=already released' '=bump VERSION'

newcase; stub '{"release_version":{"exit":0,"stdout":"0.0.9\n","stderr":""}}'; prev
expect "C3 P2 fails when the version is not newer than the newest tag" 1 \
  '^FAIL P2 ' '=v0.1.0'

newcase; stub '{"registry":{"gitlab":{"mockingbird":{"v0.2.0":"sha256:0b"}}}}'; prev
expect "C4 P3 fails when one GitLab image repo carries the tag" 1 \
  '^FAIL P3 ' '=mockingbird' '=burnt' '=next patch version'

newcase; stub '{"registry":{"ghcr":{"holder":{"v0.2.0":"sha256:0c"}}}}'; prev
expect "C5 P3 fails when one GHCR mirror carries the tag" 1 '^FAIL P3 ' '=holder' '=burnt'

newcase; to_main_leg; stub '{"registry":{"gitlab":{"smb-lure":{"v0.2.0":"sha256:0d"}}}}'; mainleg
expect "C6 M3 fails on the main leg when the version is burnt" 1 '^FAIL M3 ' '=smb-lure'

newcase; to_main_leg; stub '{"release_version":{"exit":1,"stdout":"","stderr":"bad"}}'; mainleg
expect "C7 M3 fails on the main leg when the version is invalid" 1 '^FAIL M3 '

# ==========================================================================
# Group D: P4 and M6 (change log)
# ==========================================================================
cl_case() { # name file-content|__missing__ [leg]
  newcase
  if [ "$2" = "__missing__" ]; then git -C "$wt" rm -q CHANGELOG.md
  else printf '%s\n' "$2" > "$wt/CHANGELOG.md"; git -C "$wt" add CHANGELOG.md; fi
  git -C "$wt" commit -q --allow-empty -m "change log edit"; push_fetch dev
}
cl_case x __missing__; stub; prev
expect "D1 P4 fails when CHANGELOG.md is missing" 1 '^FAIL P4 ' '=## [0.2.0]'

cl_case x '# Changelog

## [Unreleased]

### Added

- Something.

## [0.1.0] - 2026-10-03

### Added

- First release.'
stub; prev
expect "D2 P4 fails when there is no 0.2.0 section (Unreleased holds entries)" 1 '^FAIL P4 ' '=Unreleased'

cl_case x '# Changelog

## [Unreleased]

### Fixed

- Left behind.

## [0.2.0] - 2026-11-16

### Added

- Thing.'
stub; prev
expect "D3 P4 fails when Unreleased still holds entries beside the 0.2.0 section" 1 '^FAIL P4 '

cl_case x '# Changelog

## [Unreleased]

## [0.2.0] - 2026-11-16

## [0.1.0] - 2026-10-03

### Added

- First release.'
stub; prev
expect "D4 P4 fails when the 0.2.0 section is empty" 1 '^FAIL P4 '

cl_case x '# Changelog

## [Unreleased]

## [0.2.0] - 2026-11-16

### Misc

- Thing.'
stub; prev
expect "D5 P4 fails on a heading other than the six Keep a Changelog ones" 1 '^FAIL P4 ' '=Misc'

cl_case x '# Changelog

## [Unreleased]

## [0.2.0] - soon

### Added

- Thing.'
stub; prev
expect "D6 P4 fails when the section date is not YYYY-MM-DD" 1 '^FAIL P4 '

cl_case x "$CHANGELOG_GOOD"; stub; prev
expect "D7 P4 passes on a well-formed 0.2.0 section" - '^PASS P4 '

newcase; git -C "$wt" rm -q CHANGELOG.md && git -C "$wt" commit -q -m "drop" && push_fetch dev
to_main_leg; stub; mainleg
expect "D8 M6 fails on the main leg when the preview tip lacks the change log" 1 '^FAIL M6 '

# ==========================================================================
# Group E: P5 and M7 (review issue closed), and the read token
# ==========================================================================
newcase; stub '{"issues":{"206":"closed","213":"opened"}}'; prev
expect "E1 P5 fails when a named review issue is open" 1 \
  '^FAIL P5 ' '=Review issue #213 is open' '=close it with evidence'

newcase; stub '{"issues":{"206":"closed"}}'; prev
expect "E2 P5 fails when a named issue is not found" 1 '^FAIL P5 ' '=#213'

newcase; R_REVIEW="" write_record "$wt"; commit_record "$wt"; push_fetch dev; stub; prev
expect "E3 P5 fails when review: is empty" 1 '^FAIL P5 '

newcase; R_NO_REVIEW=1 write_record "$wt"; commit_record "$wt"; push_fetch dev; stub; prev
expect "E4 P5 fails when review: is missing" 1 '^FAIL P5 '

newcase; stub; prev
expect "E5 P5 passes when every named issue is closed" - '^PASS P5 '

newcase; to_main_leg; stub '{"issues":{"206":"opened","213":"closed"}}'; mainleg
expect "E6 M7 fails on the main leg when a review issue is open" 1 '^FAIL M7 ' '=#206'

newcase; stub
CI=true CI_MERGE_REQUEST_SOURCE_BRANCH_NAME=dev CI_MERGE_REQUEST_TARGET_BRANCH_NAME=preview prev
expect "E7 CI without BIRDCAGE_READ_TOKEN: P5 fails naming the variable" 1 \
  '^FAIL P5 ' '=BIRDCAGE_READ_TOKEN is not available' '=review token: absent'

newcase; stub '{"issues":"unauthorized"}'
CI=true BIRDCAGE_READ_TOKEN="$FAKE_TOKEN" CI_MERGE_REQUEST_SOURCE_BRANCH_NAME=dev prev
expect "E8 CI with a rejected token: P5 fails, owner renews it" 1 \
  '^FAIL P5 ' '=read_api' '=review token: present'

# The token must never be printed: not on success, rejection, timeout or a
# usage error, in CI or locally.
leaks=0
for patch in '' '{"issues":"unauthorized"}' '{"issues":"timeout"}' '{"issues":{"206":"opened"}}'; do
  newcase; stub "$patch"
  CI=true BIRDCAGE_READ_TOKEN="$FAKE_TOKEN" CI_MERGE_REQUEST_SOURCE_BRANCH_NAME=dev prev
  grep -qF "$FAKE_TOKEN" <<<"$out" && leaks=$((leaks + 1))
  BIRDCAGE_READ_TOKEN="$FAKE_TOKEN" prev
  grep -qF "$FAKE_TOKEN" <<<"$out" && leaks=$((leaks + 1))
done
BIRDCAGE_READ_TOKEN="$FAKE_TOKEN" run --target nowhere
grep -qF "$FAKE_TOKEN" <<<"$out" && leaks=$((leaks + 1))
out="leaks=$leaks"; code=0
expect "E9 the read token value never appears in any output" - '^leaks=0$'

newcase; stub; CI=true BIRDCAGE_READ_TOKEN="$FAKE_TOKEN" CI_MERGE_REQUEST_SOURCE_BRANCH_NAME=dev prev
expect "E10 CI says only that the token is present" 0 '=review token: present'

# ==========================================================================
# Group F: P6 (contains preview) and M2 (lands preview exactly)
# ==========================================================================
newcase
git -C "$wt" checkout -q preview && echo "hotfix" > "$wt/fix.txt" && git -C "$wt" add fix.txt \
  && git -C "$wt" commit -q -m "fix on preview" && push_fetch preview && git -C "$wt" checkout -q dev
stub; prev
expect "F1 P6 fails when dev is behind preview" 1 '^FAIL P6 ' '=behind preview' '=back-merge preview into dev'

newcase; stub; prev
expect "F2 P6 passes when dev contains preview" - '^PASS P6 '

newcase; to_main_leg
git -C "$wt" checkout -q main && echo "drift" > "$wt/drift.txt" && git -C "$wt" add drift.txt \
  && git -C "$wt" commit -q -m "commit only on main" && push_fetch main && git -C "$wt" checkout -q preview
stub; mainleg
expect "F3 M2 fails when main is not contained in preview" 1 \
  '^FAIL M2 ' '=would change files relative to the tested preview'

newcase; to_main_leg
# main moved by a merge that preview already contains: still exact.
git -C "$wt" checkout -q main && git -C "$wt" merge -q --no-ff -m "merge preview" preview \
  && push_fetch main && git -C "$wt" checkout -q preview && git -C "$wt" merge -q --ff-only main \
  && push_fetch preview
stub; mainleg
expect "F4 M2 passes when preview contains main and the trees match" - '^PASS M2 '

# ==========================================================================
# Group G: P7 and M1 (hop)
# ==========================================================================
newcase; git -C "$wt" checkout -q -b feature/x; stub; prev
expect "G1 P7 fails for a feature branch into preview" 1 '^FAIL P7 ' '=preview only accepts merge requests from dev or hotfix/<name>'

newcase; git -C "$wt" checkout -q -b hotfix/fix-1; stub; prev
expect "G2 P7 passes for hotfix/<name>" - '^PASS P7 '

newcase; stub; prev
expect "G3 P7 passes for dev" - '^PASS P7 '

newcase; stub; CI=true BIRDCAGE_READ_TOKEN="$FAKE_TOKEN" CI_MERGE_REQUEST_SOURCE_BRANCH_NAME=batch-b \
  CI_MERGE_REQUEST_TARGET_BRANCH_NAME=preview prev
expect "G4 P7 in CI reads the MR source branch" 1 '^FAIL P7 '

newcase; to_main_leg; git -C "$wt" checkout -q dev; stub
run --target main --remote origin --description-file "$c/desc.txt"
expect "G5 M1 fails for dev into main" 1 '^FAIL M1 ' '=main only accepts merge requests from preview'

newcase; to_main_leg; stub; mainleg
expect "G6 M1 passes for preview into main" - '^PASS M1 '

# ==========================================================================
# Group H: M4 (preview published) and M5 (evidence fresh)
# ==========================================================================
newcase; to_main_leg; tip="$(git -C "$wt" rev-parse HEAD)"
stub "{\"registry\":{\"gitlab\":{\"opencanary\":{\"sha-$tip\":null}}}}"; mainleg
expect "H1 M4 fails when an image lacks sha-<preview tip>" 1 \
  '^FAIL M4 ' '=opencanary' '=re-run the preview pipeline'

newcase; to_main_leg
stub '{"registry":{"gitlab":{"nightjar":{"preview":"sha256:00000000000000000000000000000000000000000000000000000000000000ff"}}}}'; mainleg
expect "H2 M4 fails when GitLab :preview differs from sha-<tip>" 1 '^FAIL M4 ' '=nightjar'

newcase; to_main_leg
stub '{"registry":{"ghcr":{"birdcage":{"preview":"sha256:00000000000000000000000000000000000000000000000000000000000000ee"}}}}'; mainleg
expect "H3 M4 fails when GHCR :preview has another digest" 1 '^FAIL M4 ' '=birdcage'

newcase; to_main_leg
stub '{"registry":{"ghcr":{"holder":{"sha256-0000000000000000000000000000000000000000000000000000000000000061":null}}}}'; mainleg
expect "H4 M4 fails when GHCR lacks the attestation tag (#162)" 1 '^FAIL M4 ' '=holder'

newcase; to_main_leg; stub; mainleg
expect "H5 M4 passes when all six are published and mirrored" - '^PASS M4 '

newcase; to_main_leg
stub '{"evidence":{"mockingbird":{"ok":false,"reason":"signature rejected","recorded":"2026-11-15T10:00:00Z","expires":"2026-11-22T10:00:00Z"}}}'; mainleg
expect "H6 M5 fails when evidence is rejected" 1 '^FAIL M5 ' '=mockingbird'

newcase; to_main_leg
stub '{"evidence":{"nightjar":{"ok":true,"recorded":"2026-11-09T10:00:00Z","expires":"2026-11-16T10:00:00Z"}}}'; mainleg
expect "H7 M5 fails when evidence has expired" 1 '^FAIL M5 ' '=nightjar' '=merge to preview again'

newcase; to_main_leg
stub '{"evidence":{"holder":{"ok":true,"recorded":"2026-11-11T06:00:00Z","expires":"2026-11-18T06:00:00Z"}}}'; mainleg
expect "H8 M5 fails with less than one day left (18 h)" 1 '^FAIL M5 ' '=holder' '=2026-11-18'

newcase; to_main_leg
stub '{"evidence":{"holder":{"ok":true,"recorded":"2026-11-11T14:00:00Z","expires":"2026-11-18T14:00:00Z"}}}'; mainleg
expect "H9 M5 passes with just over one day left (26 h)" - '^PASS M5 '

newcase; to_main_leg; stub '{"evidence":"timeout"}'; mainleg
expect "H10 M5 local evidence timeout is UNCHECKED" 3 '^UNCHECKED M5 '

# ==========================================================================
# Group I: M9 (step 2 recorded in the MR description)
# ==========================================================================
newcase; to_main_leg; stub; printf 'Promote v0.2.0.\n' > "$c/desc.txt"; mainleg
expect "I1 M9 fails when the description has no Step 2 line" 1 '^FAIL M9 ' "=Step 2: ..."

newcase; to_main_leg; stub; printf 'Step 2:   \n' > "$c/desc.txt"; mainleg
expect "I2 M9 fails when Step 2 has no evidence" 1 '^FAIL M9 '

newcase; to_main_leg; stub; run --target main --remote origin
expect "I3 M9 fails locally without --description-file" 1 '^FAIL M9 '

newcase; to_main_leg; stub; mainleg
expect "I4 M9 passes with a Step 2 line" - '^PASS M9 '

newcase; to_main_leg; stub
CI=true BIRDCAGE_READ_TOKEN="$FAKE_TOKEN" CI_MERGE_REQUEST_SOURCE_BRANCH_NAME=preview \
  CI_MERGE_REQUEST_TARGET_BRANCH_NAME=main \
  CI_MERGE_REQUEST_DESCRIPTION=$'Promote.\nStep 2: lab test passed, all six services answered' \
  run --target main --remote origin
expect "I5 M9 in CI reads CI_MERGE_REQUEST_DESCRIPTION" 0 '^PASS M9 '

# ==========================================================================
# Group J: K1 (signing public key)
# ==========================================================================
newcase; git -C "$wt" rm -q cosign.pub && git -C "$wt" commit -q -m "drop key" && push_fetch dev; stub; prev
expect "J1 K1 fails when cosign.pub is missing" 1 '^FAIL K1 ' '=owner setup step 2'

newcase; echo "not a key" > "$wt/cosign.pub" && git -C "$wt" commit -q -am "break key" && push_fetch dev; stub; prev
expect "J2 K1 fails when cosign.pub is not a PEM public key" 1 '^FAIL K1 '

newcase; to_main_leg; git -C "$wt" rm -q cosign.pub && git -C "$wt" commit -q -m "drop key" \
  && push_fetch preview; stub; mainleg
expect "J3 K1 fails on the main leg too" 1 '^FAIL K1 '

newcase; stub; prev
expect "J4 K1 passes with a PEM public key" - '^PASS K1 '

# ==========================================================================
# Group K: R1 and M8 (release record, rules 3.2/1-9)
# ==========================================================================
rec() { # commit a rewritten record on dev, then stub and run the preview leg
  write_record "$wt"; commit_record "$wt" "${AUTHOR:-Fixture Bot}" "${TRAILER:-Fixture Bot}"
  push_fetch dev; stub; prev
}

newcase; git -C "$wt" rm -q docs/releases/v0.2.0.md && git -C "$wt" commit -q -m "drop record" \
  && push_fetch dev; stub; prev
expect "K1 rule 1: a missing record fails, naming the template" 1 \
  '^FAIL R1 ' '=docs/releases/TEMPLATE.md' '=Signed-off-by'

newcase; R_VERSION=v0.1.9 rec
expect "K2 rule 2: version: not v0.2.0 fails" 1 '^FAIL R1 '
newcase; R_NO_VERSION=1 rec
expect "K3 rule 2: version: missing fails" 1 '^FAIL R1 '

newcase
printf '%s\n\n7. A new step.\n' "$GUIDE" > "$wt/docs/releasing.md"
git -C "$wt" commit -q -am "guide gains a step" && push_fetch dev; stub; prev
expect "K4 rule 3: guide changed after the record: fails" 1 '^FAIL R1 ' '=re-read'

newcase
git -C "$wt" checkout -q -b side main && echo x > "$wt/side.txt" && git -C "$wt" add side.txt \
  && git -C "$wt" commit -q -m side
side="$(git -C "$wt" rev-parse HEAD)"; git -C "$wt" checkout -q dev
R_COMMIT="$side" rec
expect "K5 rule 4: guide-commit not an ancestor of the source fails" 1 '^FAIL R1 '

newcase; first="$(git -C "$wt" rev-list --max-parents=0 HEAD)"
R_COMMIT="$first" rec
expect "K6 rule 4: guide-commit whose guide blob differs fails" 1 '^FAIL R1 '

newcase; R_STEPS="$(grep -v '^step 4:' <<<"$STEPS_GOOD")" rec
expect "K7 rule 5: a missing step fails" 1 '^FAIL R1 ' '=step 4'
newcase; R_STEPS="$STEPS_GOOD
step 6: after-merge" rec
expect "K8 rule 5: a doubled step fails" 1 '^FAIL R1 '
newcase; R_STEPS='step 1: done: pipeline 9001
step 3: after-merge
step 2: after-merge
step 4: after-merge
step 5: after-merge
step 6: after-merge' rec
expect "K9 rule 5: steps out of order fail" 1 '^FAIL R1 '
newcase; R_STEPS="$STEPS_GOOD
step 7: after-merge" rec
expect "K10 rule 5: a step the guide lacks fails" 1 '^FAIL R1 ' '=step 7'

newcase; R_STEPS="${STEPS_GOOD/step 2: after-merge/step 2: maybe later}" rec
expect "K11 rule 6: a value not done/not-needed/after-merge fails" 1 '^FAIL R1 '
newcase; R_STEPS="${STEPS_GOOD/step 1: done: pipeline 9001/step 1: done:}" rec
expect "K12 rule 6: done: with no evidence fails" 1 '^FAIL R1 '
newcase; R_STEPS="${STEPS_GOOD/step 2: after-merge/step 2: not-needed:}" rec
expect "K13 rule 6: not-needed: with no decision fails" 1 '^FAIL R1 '
newcase; R_STEPS="${STEPS_GOOD/step 1: done: pipeline 9001/step 1: done: <link or job id>}" rec
expect "K14 rule 6: a <...> placeholder left in fails" 1 '^FAIL R1 '
newcase; R_STEPS="${STEPS_GOOD/step 2: after-merge/step 2: not-needed: owner decision #168}" rec
expect "K15 rule 6: not-needed with a decision passes" 0 '^PASS R1 '

newcase; R_NO_SIGN=1 rec
expect "K16 rule 7: no Signed-off-by line (unsigned) fails" 1 '^FAIL R1 '
newcase; R_SIGN='Signed-off-by: Fixture Bot
Signed-off-by: Fixture Bot' rec
expect "K17 rule 7: two Signed-off-by lines fail" 1 '^FAIL R1 '
newcase; R_SIGN='Signed-off-by: Fixture Bot <fixture-bot@example.invalid>' rec
expect "K18 rule 7: an email in the sign-off fails" 1 '^FAIL R1 '
newcase; R_SIGN='Signed-off-by: fixture-bot@example.invalid' rec
expect "K19 rule 7: an @ in the sign-off fails" 1 '^FAIL R1 '

newcase; AUTHOR="Other Bot" TRAILER="Fixture Bot" rec
expect "K20 rule 8: commit author differs from the sign-off name: fails" 1 '^FAIL R1 '
newcase; AUTHOR="Fixture Bot" TRAILER="Other Bot" rec
expect "K21 rule 8: commit trailer differs from the sign-off name: fails" 1 '^FAIL R1 '
newcase; AUTHOR="Fixture Bot" TRAILER="-" rec
expect "K22 rule 8: commit without a Signed-off-by trailer fails" 1 '^FAIL R1 '

newcase; R_REVIEW="" rec
expect "K23 rule 9: empty review: fails R1 too" 1 '^FAIL R1 '

newcase; stub; prev
expect "K24 the good record passes R1" 0 '^PASS R1 '

newcase; to_main_leg; R_VERSION=v0.1.9 write_record "$wt"; commit_record "$wt"; push_fetch preview
stub; mainleg
expect "K25 M8 fails on the main leg when the record on the preview tip is wrong" 1 '^FAIL M8 '

newcase; to_main_leg
printf '%s\n\n7. A new step.\n' "$GUIDE" > "$wt/docs/releasing.md"
git -C "$wt" commit -q -am "guide gains a step" && push_fetch preview; stub; mainleg
expect "K26 M8 checks against the guide on the preview tip" 1 '^FAIL M8 '

# ==========================================================================
# Group L: S1 and S2 (staleness, owner answers 42c and 49)
# Default: a 14-day cooldown (a version released fewer than 14 days ago
# does not count as newer; no release date counts as old); stale-and-unheld
# fails on the preview leg and is INFO on the main leg. --cooldown-days N
# changes the window.
# ==========================================================================
srows() { printf '{"staleness":{"rows":[%s]}}' "$1"; }

newcase; stub "$(srows "$ROWS_OK,$(behind_row go:example.invalid/old 2026-10-01)")"; prev
expect "L1 S1 fails on preview for an unheld pin behind upstream (47 days old)" 1 \
  '^FAIL S1 ' '=go:example.invalid/old' '=supply-chain/staleness.yml' '=review-by'

newcase; stub "$(srows "$ROWS_OK,$(behind_row go:example.invalid/undated)")"; prev
expect "L2 S1: no release date counts as old, so it fails" 1 '^FAIL S1 ' '=go:example.invalid/undated'

newcase; stub "$(srows "$ROWS_OK,$(behind_row npm:fixture-young 2026-11-04)")"; prev
expect "L3 S1: a version 13 days old is inside the cooldown, so it passes" 0 '^PASS S1 '

newcase; stub "$(srows "$ROWS_OK,$(behind_row npm:fixture-older 2026-11-02)")"; prev
expect "L4 S1: a version 15 days old is outside the cooldown, so it fails" 1 '^FAIL S1 ' '=npm:fixture-older'

newcase; stub "$(srows "$ROWS_OK,$(behind_row npm:fixture-older 2026-11-02)")"; prev --cooldown-days 30
expect "L5 --cooldown-days 30 widens the window: the 15-day version passes" 0 '^PASS S1 '

newcase; stub "$(srows "$ROWS_OK,$(behind_row npm:fixture-young 2026-11-14)")"; prev --cooldown-days 0
expect "L6 --cooldown-days 0 counts every newer version" 1 '^FAIL S1 '

newcase; stub "$(srows "$ROWS_OK,{\"id\":\"pypi:fixture-held\",\"pinned\":\"3.2.0\",\"latest\":\"4.0.0\",\"status\":\"accepted\",\"note\":\"held\"}")"; prev
expect "L7 S1 passes for a pin under a live hold" 0 '^PASS S1 '

newcase; stub "$(srows "$ROWS_OK,{\"id\":\"pypi:fixture-lapsed\",\"pinned\":\"3.2.0\",\"latest\":\"4.0.0\",\"status\":\"behind\",\"note\":\"\",\"released\":\"2026-09-01\",\"hold\":{\"lapsed\":\"expired\",\"review_by\":\"2026-11-01\"}}")"; prev
expect "L8 S1 fails once a hold's review-by date has passed" 1 \
  '^FAIL S1 ' '=the hold on pypi:fixture-lapsed expired on 2026-11-01' '=renew the hold'

newcase; stub "$(srows "$ROWS_OK,{\"id\":\"go:example.invalid/dark\",\"pinned\":\"1.0.0\",\"latest\":\"\",\"status\":\"unverifiable\",\"note\":\"no answer\"}")"; prev
expect "L9 S1 fails for an unverifiable row not covered" 1 '^FAIL S1 ' '=go:example.invalid/dark'

cred_row='{"id":"image:fixture-digest","pinned":"sha256:aa","latest":"","status":"unverifiable","note":"registry login absent","credential_missing":true}'
newcase; stub "$(srows "$ROWS_OK,$cred_row")"; prev
expect "L10 S1 locally: unverifiable only for a missing CI credential is UNCHECKED" 3 '^UNCHECKED S1 '
CI=true BIRDCAGE_READ_TOKEN="$FAKE_TOKEN" CI_MERGE_REQUEST_SOURCE_BRANCH_NAME=dev prev
expect "L11 S1 in CI: the same row is FAIL" 1 '^FAIL S1 '

newcase; stub '{"staleness":"timeout"}'; prev
expect "L12 staleness timeout locally is UNCHECKED" 3 '^UNCHECKED S1 '
CI=true BIRDCAGE_READ_TOKEN="$FAKE_TOKEN" CI_MERGE_REQUEST_SOURCE_BRANCH_NAME=dev prev
expect "L13 staleness timeout in CI is FAIL" 1 '^FAIL S1 '

newcase; to_main_leg; stub "$(srows "$ROWS_OK,$(behind_row go:example.invalid/old 2026-10-01)")"; mainleg
expect "L14 S1 on the main leg is INFO, not FAIL: exit 0" 0 '^INFO S1 ' '!^FAIL S1 ' '=go:example.invalid/old'

newcase; to_main_leg; stub "$(srows "$ROWS_OK,{\"id\":\"pypi:fixture-lapsed\",\"pinned\":\"3.2.0\",\"latest\":\"4.0.0\",\"status\":\"behind\",\"note\":\"\",\"hold\":{\"lapsed\":\"expired\",\"review_by\":\"2026-11-01\"}}")"; mainleg
expect "L15 an expired hold on the main leg is INFO too" 0 '^INFO S1 ' '!^FAIL S1 '

apk_bad='{"id":"apk:build/mockingbird/Dockerfile:python3","pinned":"3.12.4-r0","latest":"3.12.4-r1","status":"behind","note":"","released":"2026-11-16"}'
newcase; stub "$(srows "$apk_bad")"; prev
expect "L16 S2 fails when Alpine no longer carries an apk pin" 1 \
  '^FAIL S2 ' '=Alpine no longer carries' '=python3' '=dependency-inventory.md'

apk_held='{"id":"apk:build/mockingbird/Dockerfile:python3","pinned":"3.12.4-r0","latest":"3.12.4-r1","status":"accepted","note":"held"}'
newcase; stub "$(srows "$apk_held")"; prev
expect "L17 S2: a hold cannot excuse an unbuildable apk pin" 1 '^FAIL S2 '

newcase; stub "$(srows "$apk_bad")"; prev
expect "L18 S2: the cooldown does not excuse an apk pin either" 1 '^FAIL S2 '

newcase; to_main_leg; stub "$(srows "$apk_bad")"; mainleg
expect "L19 S2 fails on the main leg too (never INFO)" 1 '^FAIL S2 ' '!^INFO S2 '

newcase; stub; prev
expect "L20 S2 passes when every apk pin is current" 0 '^PASS S2 '

# ==========================================================================
# Group M: the CI wiring in .gitlab-ci.yml
# ==========================================================================
ci_report="$(python3 -I - "$repo_root/.gitlab-ci.yml" <<'PY' 2>&1 || true
import sys, yaml
class L(yaml.SafeLoader):
    pass
L.add_multi_constructor("!", lambda loader, suffix, node: None)  # !reference
doc = yaml.load(open(sys.argv[1]), Loader=L)
job = doc.get("release_readiness")
def say(k, v): print(f"{k}={v}")
say("exists", int(isinstance(job, dict)))
if not isinstance(job, dict):
    job = {}
say("stage", job.get("stage"))
say("needs_empty", int(job.get("needs") == []))
say("timeout", job.get("timeout"))
say("depth", (job.get("variables") or {}).get("GIT_DEPTH"))
af = job.get("allow_failure", False)
say("allow_failure", int(bool(af)))
script = "\n".join(str(s) for s in (job.get("script") or []))
say("runs_script", int("scripts/release-readiness.py" in script and "--target" in script))
rules = " ".join(str((r or {}).get("if", "")) for r in (job.get("rules") or []) if isinstance(r, dict))
say("rule_promotion", int("merge_request_event" in rules and '"preview"' in rules and '"main"' in rules))
wait = ["lint:go", "lint:licences", "lint:licences-python", "lint:ci", "lint:scripts",
        "test:release-scripts", "lint:agent-deps", "lint:govulncheck", "test:frontend",
        "test:go", "test:go:quarantine", "build:images", "e2e:postgres-requires-tls"]
def waits(j):
    for n in (j.get("needs") or []):
        if isinstance(n, dict) and n.get("job") == "release_readiness" and n.get("optional") is True:
            return True
    return False
for name in wait:
    j = doc.get(name)
    if isinstance(j, dict):
        say("waits:" + name, int(waits(j)))
beside = {"release_readiness", "policy:promotion-hop", "policy:release-record",
          "lint:gitleaks", "lint:flake-check"}
for name, j in doc.items():
    if not isinstance(j, dict) or name.startswith(".") or name in beside:
        continue
    if name.startswith(("release:", "sync:", "audit:")):
        continue
    if j.get("needs") == []:
        say("starts_beside:" + name, 1)
rr = doc.get("policy:release-record")
say("fence_exists", int(isinstance(rr, dict)))
if isinstance(rr, dict):
    s = "\n".join(str(x) for x in (rr.get("script") or []))
    say("fence_runs_script", int("scripts/release-record-policy.py" in s))
    r = " ".join(str((x or {}).get("if", "")) for x in (rr.get("rules") or []) if isinstance(x, dict))
    say("fence_rule_release", int("release/" in r and "merge_request_event" in r))
PY
)"
out="$ci_report"; code=0
expect "M1 release_readiness job exists" - '^exists=1$'
expect "M2 it is in the first stage (lint) and needs nothing" - '^stage=lint$' '^needs_empty=1$'
expect "M3 job timeout 10m, full history (GIT_DEPTH 0)" - '^timeout=10m$' '^depth=0$'
expect "M4 exit 3 fails the job (no allow_failure)" - '^exists=1$' '^allow_failure=0$'
expect "M5 the job runs scripts/release-readiness.py --target" - '^runs_script=1$'
expect "M6 the job runs on MRs into preview and main" - '^rule_promotion=1$'
expect "M7 every listed fast job waits on release_readiness (optional need)" - \
  '^waits:' '!^waits:.*=0$'
expect "M8 no other job starts beside it (needs: [])" - '!^starts_beside:'
expect "M9 policy:release-record job exists, on release/* MRs, running its script" - \
  '^fence_exists=1$' '^fence_runs_script=1$' '^fence_rule_release=1$'

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
