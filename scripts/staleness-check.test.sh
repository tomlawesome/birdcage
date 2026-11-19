#!/usr/bin/env bash
# Tests for staleness-check.py (#139). Fully offline: every case below
# passes --upstream, which replaces every network fetch, so no test here
# ever depends on this host's route to the internet.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
check="$here/staleness-check.py"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

# A small, fixed manifest tree -- one pin per ecosystem this suite
# exercises, not every ecosystem staleness-check.py knows about. The
# scenarios below drive their pass/fail entirely through --upstream and
# supply-chain/staleness.yml, never by editing these files.
root="$work/repo"
mkdir -p "$root/frontend" "$root/build/opencanary" "$root/build/sample" "$root/supply-chain"

cat > "$root/go.mod" <<'EOF'
module test

go 1.21.0

require (
	github.com/tomlawesome/gauntlet v0.4.1
)
EOF

cat > "$root/frontend/package.json" <<'EOF'
{
  "devDependencies": {
    "widget": "^1.0.0"
  }
}
EOF

cat > "$root/frontend/package-lock.json" <<'EOF'
{
  "packages": {
    "node_modules/widget": { "version": "1.0.0" }
  }
}
EOF

cat > "$root/build/opencanary/requirements.txt" <<'EOF'
gadget==2.0.0
EOF

cat > "$root/build/sample/Dockerfile" <<'EOF'
FROM alpine:3.20
EOF

cat > "$root/.gitlab-ci.yml" <<'EOF'
variables:
  GOLANG_IMAGE: golang:1.21
  E2E_POISONER_FIXTURE_DIGEST: registry.example.test/group/poisoner@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
EOF

# The fixture:poisoner pin above, in one place so every scenario's
# default upstream_json() response (current, matching the pin at its
# only tag) and the dedicated fixture-tag scenarios further down agree
# on the URLs.
fixture_repo_url="https://registry.example.test/v2/group/poisoner"
fixture_pin_digest="sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

# The owner module in go.mod above is looked up on the Git host's tags
# API, never the Go proxy (ADR-0016 decision 1). Default response: its
# only tag is the pin, i.e. current.
owner_tags_url="https://api.github.com/repos/tomlawesome/gauntlet/tags?per_page=100"

# expect <want-exit> <name> <upstream-json> <staleness-yml> [--today VALUE]
expect() {
  local want="$1" name="$2" upstream_json="$3" staleness_yml="$4"
  shift 4
  local got=0 out
  printf '%s\n' "$upstream_json" > "$work/upstream.json"
  printf '%s\n' "$staleness_yml" > "$root/supply-chain/staleness.yml"
  out="$(python3 "$check" --root "$root" --upstream "$work/upstream.json" "$@" 2>&1)" || got=$?
  # must_contain, when set by the caller, is a row the table has to show
  # verbatim -- the exit code alone cannot tell "behind at 3.22" from
  # "behind at 3.21".
  if [ "$got" = "$want" ] && { [ -z "${must_contain:-}" ] || printf '%s' "$out" | grep -qF -- "$must_contain"; }; then
    echo "ok   $name"; pass=$((pass + 1))
  else
    echo "FAIL $name: exit $got, want $want"; echo "$out" | sed 's/^/       /'
    fail=$((fail + 1))
  fi
}

# staleness-check.py finds the newest alpine:3.2x by probing Docker Hub's
# single-tag endpoint (.../tags/<tag>, 200 or 404) one release at a time
# from the pin, never by listing -- Docker Hub's own tag-listing endpoint
# refuses to page past its 1000th result, which a broad cross-major
# search hits in exactly the two repositories (node, python) with that
# many tags; see docker_hub_walk's docstring. So each scenario below is
# every probe that walk makes: the pin itself (3.20, confirmed to
# exist), then one number at a time upward until three consecutive
# misses (the walk's gap tolerance -- a family's numbers are not always
# contiguous, see the docstring), and 4.0 (the one-level-looser probe for
# the informational "newer line" note, always made, always a miss here).
alpine_current='{
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.20": "{}",
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.21": {"status": 404},
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.22": {"status": 404},
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.23": {"status": 404},
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.24": {"status": 404},
  "https://hub.docker.com/v2/repositories/library/alpine/tags/4.0": {"status": 404}
}'
alpine_behind='{
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.20": "{}",
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.21": "{}",
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.22": {"status": 404},
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.23": {"status": 404},
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.24": {"status": 404},
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.25": {"status": 404},
  "https://hub.docker.com/v2/repositories/library/alpine/tags/4.0": {"status": 404}
}'

# 3.21 never existed but 3.22 does: the shape that made the first live run
# call node:22-trixie current (no node:23-trixie, but 24, 25 and 26).
alpine_gap='{
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.20": "{}",
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.22": "{}",
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.21": {"status": 404},
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.23": {"status": 404},
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.24": {"status": 404},
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.25": {"status": 404},
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.26": {"status": 404},
  "https://hub.docker.com/v2/repositories/library/alpine/tags/4.0": {"status": 404}
}'

# upstream_json <alpine-probes-json> [drop-pypi (1 to omit it)] [fixture-override-json]
#
# The fixture-tag scenarios (fixture:poisoner, below) pass their own
# tags/list and/or manifest response as the third argument, which wins
# over the default (a single version tag matching the pin, i.e.
# "current") -- so every other scenario in this suite, which never
# touches that third argument, keeps seeing a current fixture row and
# is unaffected by it.
upstream_json() {
  local alpine_probes="$1" drop_pypi="${2:-0}" fixture_override="${3:-}"
  [ -n "$fixture_override" ] || fixture_override='{}'
  python3 - "$alpine_probes" "$drop_pypi" "$fixture_override" \
    "$fixture_repo_url" "$fixture_pin_digest" <<'PYEOF'
import json, sys
alpine_probes, drop_pypi, fixture_override, repo_url, pin_digest = sys.argv[1:6]
merged = {
    "https://go.dev/dl/?mode=json": json.dumps([{"version": "go1.21.0", "stable": True}]),
    "https://registry.npmjs.org/widget/latest": json.dumps({"version": "1.0.0"}),
    f"{repo_url}/tags/list": {"tags": ["v1.0.0"]},
    f"{repo_url}/manifests/v1.0.0": pin_digest,
    "https://api.github.com/repos/tomlawesome/gauntlet/tags?per_page=100": [{"name": "v0.4.1"}],
}
if drop_pypi != "1":
    merged["https://pypi.org/pypi/gadget/json"] = json.dumps({"info": {"version": "2.0.0"}})
merged.update(json.loads(alpine_probes))
merged.update(json.loads(fixture_override))
print(json.dumps(merged))
PYEOF
}

no_config="accepted: []
unchecked: []
alpine-branch: {}"

expect 0 "all current" "$(upstream_json "$alpine_current")" "$no_config"

expect 1 "one deliberately stale pin (image:alpine:3.20 behind)" \
  "$(upstream_json "$alpine_behind")" "$no_config"

must_contain='| image:alpine:3.20 | 3.20 | 3.22 | behind |' \
  expect 1 "a gap in the tag family does not hide the newer tag beyond it" \
  "$(upstream_json "$alpine_gap")" "$no_config"

accepted_far="accepted:
  - pin: \"image:alpine:3.20\"
    held-at: \"3.20\"
    reason: \"test fixture -- deliberately stale, accepted for the test\"
    review-by: \"2099-01-01\"
unchecked: []
alpine-branch: {}"

expect 0 "an accepted entry covers the stale pin" \
  "$(upstream_json "$alpine_behind")" "$accepted_far" --today 2026-01-01

expect 1 "the same accepted entry, but review-by is in the past" \
  "$(upstream_json "$alpine_behind")" "$accepted_far" --today 2099-06-01

# A URL missing from the fixture: drop the pypi entry entirely rather than
# reusing upstream_json, so the missing key is the only thing in play.
missing_url_upstream="$(upstream_json "$alpine_current" 1)"

expect 1 "a URL missing from --upstream is unverifiable" \
  "$missing_url_upstream" "$no_config"

unchecked_config="accepted: []
unchecked:
  - pin: \"pypi:gadget\"
    reason: \"test fixture -- deliberately unreachable, covered for the test\"
    review-by: \"2099-01-01\"
alpine-branch: {}"

expect 0 "an unchecked entry covers the unreachable pin" \
  "$missing_url_upstream" "$unchecked_config" --today 2026-01-01

# #215 D11: an unchecked: entry needs a review-by date, like a hold.
must_contain='unchecked entry expired on 2099-01-01' \
  expect 1 "an unchecked entry past its review-by excuses nothing" \
  "$missing_url_upstream" "$unchecked_config" --today 2099-06-01

unchecked_undated="accepted: []
unchecked:
  - pin: \"pypi:gadget\"
    reason: \"test fixture -- no review-by\"
alpine-branch: {}"
must_contain='unchecked entry has no review-by' \
  expect 1 "an unchecked entry without review-by excuses nothing" \
  "$missing_url_upstream" "$unchecked_undated"

# fixture:poisoner (#147): the private fixtures project publishes the
# poisoner fixture only under a version tag, never `latest`, so this
# check lists tags/list, picks the newest v-tag and HEADs its manifest.

# Several tags, only some of them version-shaped (v1.0.0, v1.2.0):
# "latest" and "dev" are ignored, v1.2.0 wins as newest, and its
# manifest digest matches the pin.
fixture_current="{
  \"$fixture_repo_url/tags/list\": {\"tags\": [\"v1.0.0\", \"v1.2.0\", \"latest\", \"dev\"]},
  \"$fixture_repo_url/manifests/v1.2.0\": \"$fixture_pin_digest\"
}"

must_contain='| fixture:poisoner | '"$fixture_pin_digest"' | v1.2.0 | current |' \
  expect 0 "fixture pin matches the newest version tag's digest -- current" \
  "$(upstream_json "$alpine_current" 0 "$fixture_current")" "$no_config"

# Same single v1.0.0 tag as the suite's default, but its manifest
# digest has moved on from the pin.
fixture_behind="{
  \"$fixture_repo_url/manifests/v1.0.0\": \"sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321\"
}"

must_contain='| fixture:poisoner | '"$fixture_pin_digest"' | v1.0.0 | behind |' \
  expect 1 "fixture pin no longer matches the newest tag's digest -- behind" \
  "$(upstream_json "$alpine_current" 0 "$fixture_behind")" "$no_config"

# The real pin names its registry as $CI_REGISTRY (#192): expanded from
# the environment, as GitLab does in the job; unverifiable when unset.
cp "$root/.gitlab-ci.yml" "$work/ci.yml.orig"
sed -i 's|registry\.example\.test/group/poisoner@|$CI_REGISTRY/group/poisoner@|' "$root/.gitlab-ci.yml"
must_contain='| fixture:poisoner | '"$fixture_pin_digest"' | v1.2.0 | current |' \
CI_REGISTRY=registry.example.test \
  expect 0 "fixture pin written as \$CI_REGISTRY expands from the environment -- current" \
  "$(upstream_json "$alpine_current" 0 "$fixture_current")" "$no_config"
must_contain='CI_REGISTRY not set' \
CI_REGISTRY= \
  expect 1 "fixture pin written as \$CI_REGISTRY with CI_REGISTRY unset -- unverifiable" \
  "$(upstream_json "$alpine_current" 0 "$fixture_current")" "$no_config"
cp "$work/ci.yml.orig" "$root/.gitlab-ci.yml"

# No tag in the repository parses as a version at all.
fixture_no_version_tags="{
  \"$fixture_repo_url/tags/list\": {\"tags\": [\"latest\", \"dev\"]}
}"

expect 1 "no version tag among the fixture repository's tags -- unverifiable" \
  "$(upstream_json "$alpine_current" 0 "$fixture_no_version_tags")" "$no_config"

# tags/list itself 404s.
fixture_tags_404="{
  \"$fixture_repo_url/tags/list\": {\"status\": 404}
}"

expect 1 "fixture tags/list 404s -- unverifiable" \
  "$(upstream_json "$alpine_current" 0 "$fixture_tags_404")" "$no_config"

# Owner modules (github.com/tomlawesome/*) -- ADR-0016 decision 1: a lookup
# through proxy.golang.org publishes the version for good, so the script
# reads GitHub's tags API instead. The default fixture above is the
# "current" case (tag v0.4.1 == pin).
must_contain='| gomod:github.com/tomlawesome/gauntlet | v0.4.1 | v0.4.1 | current |' \
  expect 0 "owner module at the newest GitHub tag -- current" \
  "$(upstream_json "$alpine_current")" "$no_config"

owner_behind="{
  \"$owner_tags_url\": [{\"name\": \"v0.4.1\"}, {\"name\": \"v0.5.0\"}, {\"name\": \"v0.4.9\"}]
}"

must_contain='| gomod:github.com/tomlawesome/gauntlet | v0.4.1 | v0.5.0 | behind |' \
  expect 1 "owner module behind the newest GitHub tag -- behind" \
  "$(upstream_json "$alpine_current" 0 "$owner_behind")" "$no_config"

# Non-semver tags (and a partial vX.Y) are ignored, even where they would
# sort above the real newest tag.
owner_junk_tags="{
  \"$owner_tags_url\": [{\"name\": \"v0.4.1\"}, {\"name\": \"v9.9\"}, {\"name\": \"latest\"}, {\"name\": \"v0.9.0-rc1\"}, {\"name\": \"release-99.0.0\"}]
}"

must_contain='| gomod:github.com/tomlawesome/gauntlet | v0.4.1 | v0.4.1 | current |' \
  expect 0 "owner module: non-semver tags are ignored" \
  "$(upstream_json "$alpine_current" 0 "$owner_junk_tags")" "$no_config"

# The fake fetcher records every URL requested. Drives check_go_modules
# directly (go.mod: an owner module, plus a subpackage `go install` of
# one owner module and a /v2 module in .gitlab-ci.yml) and asserts the
# proxy is never asked about any owner module, and that the proxy helpers
# themselves refuse one.
mkdir -p "$work/owner" && cp "$root/go.mod" "$work/owner/go.mod"
cat > "$work/owner/.gitlab-ci.yml" <<'CIEOF'
script:
  - go install github.com/tomlawesome/gauntlet/cmd/gauntlet@v0.4.1
  - go install github.com/tomlawesome/other/v2@v2.0.0
CIEOF
if python3 - "$check" "$work/owner" <<'PYEOF'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("staleness_check", sys.argv[1])
sc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sc)

class Recording:
    def __init__(self):
        self.urls = []
    def get(self, url, headers=None):
        self.urls.append(url)
        if url == "https://api.github.com/repos/tomlawesome/gauntlet/tags?per_page=100":
            return True, json.dumps([{"name": "v0.4.1"}, {"name": "v0.5.0"}, {"name": "v2.0.0"}]).encode(), None
        if url == "https://api.github.com/repos/tomlawesome/other/tags?per_page=100":
            return True, json.dumps([{"name": "v1.9.0"}, {"name": "v2.0.0"}, {"name": "v2.1.0"}, {"name": "v3.0.0"}]).encode(), None
        return False, None, "unexpected URL: " + url

f = Recording()
rows = {r.id: r for r in sc.check_go_modules(sys.argv[2], f)}
bad = [u for u in f.urls if "proxy.golang.org" in u or "sum.golang.org" in u]
assert not bad, f"owner module reached the Go proxy: {bad}"
assert f.urls, "no URL requested at all"
g = rows["gomod:github.com/tomlawesome/gauntlet"]
assert (g.latest, g.status) == ("v0.5.0", "behind"), (g.latest, g.status)
o = rows["gomod:github.com/tomlawesome/other/v2"]
assert (o.latest, o.status) == ("v2.1.0", "behind"), (o.latest, o.status)

for name in ("go_proxy_latest", "go_proxy_version_list"):
    f2 = Recording()
    for mod in ("github.com/tomlawesome/gauntlet", "github.com/TomLawesome/gauntlet/cmd/x"):
        try:
            getattr(sc, name)(f2, mod)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"{name} accepted owner module {mod}")
    assert not f2.urls, f"{name} requested {f2.urls}"
# A look-alike is not an owner module.
assert not sc.is_owner_module("github.com/tomlawesomeness/x")
assert not sc.is_owner_module("github.com/tomlawesome")
PYEOF
then echo "ok   owner modules never reach the Go proxy (recorded URLs, helpers refuse)"; pass=$((pass + 1))
else echo "FAIL owner modules never reach the Go proxy"; fail=$((fail + 1)); fi

# image_ci_vars reads plain Docker Hub names (what .gitlab-ci.yml uses now),
# the Docker Hub cache prefix, and skips ghcr.io / mcr.microsoft.com names
# given through $CI_IMAGE_CACHE_GHCR / _MCR (not Docker Hub images, ai/agent-infra#65).
got="$(python3 - "$check" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("staleness_check", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print(json.dumps(mod.image_ci_vars({"variables": {
    "NODE_IMAGE": "node:26-trixie",
    "ALPINE_IMAGE": "library/alpine:3.24",
    "CACHED_IMAGE": "${CI_IMAGE_CACHE_DOCKERHUB}/library/postgres:18-alpine",
    "CACHED2_IMAGE": "$CI_IMAGE_CACHE_DOCKERHUB/debian:trixie-slim",
    "GHCR_IMAGE": "$CI_IMAGE_CACHE_GHCR/owner/tool:1.0",
    "MCR_IMAGE": "$CI_IMAGE_CACHE_MCR/playwright:v1",
    "GOLANG_IMAGE": "golang:1.27.3",
}}), sort_keys=True))
PY
)"
want='{"ALPINE_IMAGE": "alpine:3.24", "CACHED2_IMAGE": "debian:trixie-slim", "CACHED_IMAGE": "postgres:18-alpine", "NODE_IMAGE": "node:26-trixie"}'
if [ "$got" = "$want" ]; then
  pass=$((pass + 1)); echo "ok   image_ci_vars: plain names and cache prefixes"
else
  fail=$((fail + 1)); echo "FAIL image_ci_vars: got $got"
fi

# Digest-pinned image refs (#226). Own root holding only a .gitlab-ci.yml,
# own --upstream (Docker Hub single-tag probes only), so nothing here can
# reach the network, the Go proxy included.
d_root="$work/digest-repo"
mkdir -p "$d_root/supply-chain"
d1="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
d2="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
d3="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
cat > "$d_root/.gitlab-ci.yml" <<YML
variables:
  DOCKER_CLI_IMAGE: docker:29.6.2-cli@$d1
  DIGEST_ONLY_IMAGE: busybox@$d3
  NODE_IMAGE: node:26-trixie

.dind_service:
  services:
    - name: \${CI_IMAGE_CACHE_DOCKERHUB}/library/docker:29.6.2-dind@$d2
      alias: docker
YML
printf 'accepted: []\nunchecked: []\nalpine-branch: {}\n' > "$d_root/supply-chain/staleness.yml"
python3 - > "$work/digest-upstream.json" <<'PYEOF'
import json
hub = "https://hub.docker.com/v2/repositories/library"
m = {}
for suffix in ("-cli", "-dind"):
    m[f"{hub}/docker/tags/29.6.2{suffix}"] = "{}"
    for tag in ("29.6.3", "29.6.4", "29.6.5", "29.6.6", "29.7.0"):
        m[f"{hub}/docker/tags/{tag}{suffix}"] = {"status": 404}
m[f"{hub}/node/tags/26-trixie"] = "{}"
for n in (27, 28, 29, 30):
    m[f"{hub}/node/tags/{n}-trixie"] = {"status": 404}
print(json.dumps(m))
PYEOF
digest_out="$(python3 "$check" --root "$d_root" --upstream "$work/digest-upstream.json" 2>&1 || true)"

# row_has <name> <row-prefix> [must-also-contain...]: the first output line
# containing the prefix has to contain every further string.
row_has() {
  local name="$1" prefix="$2" row ok=1 want
  shift 2
  row="$(printf '%s\n' "$digest_out" | grep -F -- "$prefix" | head -1 || true)"
  [ -n "$row" ] || ok=0
  for want in "$@"; do printf '%s' "$row" | grep -qF -- "$want" || ok=0; done
  if [ "$ok" = 1 ]; then echo "ok   $name"; pass=$((pass + 1))
  else echo "FAIL $name"; echo "       row: ${row:-<none>}"; fail=$((fail + 1)); fi
}

row_has "digest pin: CI variable name:tag@digest gives a docker / 29.6.2-cli row, digest kept" \
  "| image:docker:29.6.2-cli |" "$d1"
row_has "digest pin: services: entry name:tag@digest gives a docker / 29.6.2-dind row, digest kept" \
  "| image:docker:29.6.2-dind |" "$d2"
row_has "digest pin: name@digest with no tag is a floating row noted as pinned by digest only" \
  "| image:busybox |" "floating" "pinned by digest only" "$d3"
row_has "plain name:tag still parses (node:26-trixie)" \
  "| image:node:26-trixie |" "| 26-trixie |"

# ---------------------------------------------------------------------------
# #215: --json rows, --deadline, --timeout, fuzzy apk pins, lapsed holds,
# release dates and the credential flag the release-readiness check reads.
# ---------------------------------------------------------------------------
json_ok() { # name python-assertions (j = parsed --json output, rows = by id)
  local name="$1" body="$2"
  if python3 - "$work/rows.json" "$body" <<'PYEOF'
import json, sys
j = json.load(open(sys.argv[1]))
rows = {r["id"]: r for r in j["rows"]}
exec(sys.argv[2])
PYEOF
  then echo "ok   $name"; pass=$((pass + 1))
  else echo "FAIL $name"; sed 's/^/       /' "$work/rows.json" 2>/dev/null || true; fail=$((fail + 1)); fi
}

# A behind pin whose newer tag carries its push date, and a hold on it that
# expired: the row says when the newer version came out and why the hold
# no longer applies.
alpine_behind_dated="$(python3 - "$(upstream_json "$alpine_behind")" <<'PYEOF'
import json, sys
m = json.loads(sys.argv[1])
m["https://hub.docker.com/v2/repositories/library/alpine/tags/3.21"] = json.dumps(
    {"name": "3.21", "tag_last_pushed": "2026-11-10T08:00:00Z"})
print(json.dumps(m))
PYEOF
)"
printf '%s\n' "$alpine_behind_dated" > "$work/upstream.json"
printf '%s\n' "$accepted_far" > "$root/supply-chain/staleness.yml"
python3 "$check" --root "$root" --upstream "$work/upstream.json" --today 2099-06-01 \
  --json "$work/rows.json" > /dev/null 2>&1 || true
# #215 review (63831, decided): Docker Hub's tag date moves on every rebuild of
# an official image, so it is never trusted for the cooldown: a behind image
# row carries no `released`, and a newer image version always counts as newer.
json_ok "--json: a Docker Hub behind row carries NO release date (not trusted for the cooldown)" '
r = rows["image:alpine:3.20"]
assert (r["status"], r["latest"]) == ("behind", "3.21"), r
assert "released" not in r, "Docker Hub tag date must not be reported as a release date: " + repr(r)'
json_ok "--json: an expired hold is named, with its review-by date" '
r = rows["image:alpine:3.20"]
assert r["hold"]["lapsed"] == "expired" and r["hold"]["review_by"] == "2099-01-01", r
assert "hold expired on 2099-01-01" in r["note"], r'
json_ok "--json: current rows carry id, pinned, latest, status, note" '
r = rows["npm:widget"]
assert set(r) >= {"id", "pinned", "latest", "status", "note"} and r["status"] == "current", r
assert "released" not in r and "hold" not in r, r'

held_at_other="accepted:
  - pin: \"image:alpine:3.20\"
    held-at: \"3.19\"
    reason: \"test fixture -- held at another tag\"
    review-by: \"2099-01-01\"
unchecked: []
alpine-branch: {}"
printf '%s\n' "$held_at_other" > "$root/supply-chain/staleness.yml"
python3 "$check" --root "$root" --upstream "$work/upstream.json" --today 2026-01-01 \
  --json "$work/rows.json" > /dev/null 2>&1 || true
json_ok "--json: a hold for another held-at is named as not applying" '
r = rows["image:alpine:3.20"]
assert r["status"] == "behind" and r["hold"]["lapsed"] == "held-at-differs", r'

# The fixture digest row without registry credentials (a real run, so no
# --upstream for that row): unverifiable only for a missing credential.
cred_root="$work/cred-repo"; mkdir -p "$cred_root/supply-chain"
printf 'variables:\n  E2E_POISONER_FIXTURE_DIGEST: registry.example.test/group/poisoner@%s\n' \
  "$fixture_pin_digest" > "$cred_root/.gitlab-ci.yml"
printf 'accepted: []\nunchecked: []\nalpine-branch: {}\n' > "$cred_root/supply-chain/staleness.yml"
(unset CI_REGISTRY_USER CI_REGISTRY_PASSWORD
 python3 "$check" --root "$cred_root" --json "$work/rows.json" > /dev/null 2>&1) || true
json_ok "--json: a row unverifiable for a missing CI credential says so" '
r = rows["fixture:poisoner"]
assert r["status"] == "unverifiable" and r.get("credential_missing") is True, r'

# --deadline cuts a slow run short: each npm/pypi answer takes 1.5 s, the
# run may take 2 s, so the second slow lookup is "deadline reached" and
# its row unverifiable -- and the run ends well inside the time a full
# wait would take.
slow_upstream="$(python3 - "$(upstream_json "$alpine_current")" <<'PYEOF'
import json, sys
m = json.loads(sys.argv[1])
for url in ("https://registry.npmjs.org/widget/latest", "https://pypi.org/pypi/gadget/json"):
    m[url] = {"delay": 1.5, "body": m[url]}
print(json.dumps(m))
PYEOF
)"
printf '%s\n' "$slow_upstream" > "$work/upstream.json"
printf '%s\n' "$no_config" > "$root/supply-chain/staleness.yml"
start=$(date +%s)
code=0; python3 "$check" --root "$root" --upstream "$work/upstream.json" --deadline 2 \
  --json "$work/rows.json" > /dev/null 2>&1 || code=$?
took=$(( $(date +%s) - start ))
json_ok "--deadline: the lookup after the deadline is unverifiable, deadline reached" '
assert rows["npm:widget"]["status"] == "current", rows["npm:widget"]
r = rows["pypi:gadget"]
assert r["status"] == "unverifiable" and "deadline reached" in r["note"], r'
if [ "$code" = 1 ] && [ "$took" -lt 6 ]; then echo "ok   --deadline: exit 1, finished in ${took}s"; pass=$((pass + 1))
else echo "FAIL --deadline: exit $code after ${took}s (want 1, under 6s)"; fail=$((fail + 1)); fi

code=0; python3 "$check" --root "$root" --upstream "$work/upstream.json" --deadline 0 > /dev/null 2>&1 || code=$?
if [ "$code" = 2 ]; then echo "ok   --deadline 0 is a usage error"; pass=$((pass + 1))
else echo "FAIL --deadline 0: exit $code (want 2)"; fail=$((fail + 1)); fi

# Unit level: fuzzy `~=` apk pins (git~=2.54 produced no row before #215),
# the Dockerfile on each apk row, --timeout reaching urlopen, the Git-host
# tag for a Go module's release date (never the proxy), and the
# per-ecosystem date readers.
apk_root="$work/apk-repo"; mkdir -p "$apk_root/build/x" "$apk_root/build/y"
cat > "$apk_root/build/x/Dockerfile" <<'EOF'
FROM alpine:3.24
RUN apk add --no-cache git~=2.54 \
    curl=8.17.0-r0 jq~=1.7
EOF
cat > "$apk_root/build/y/Dockerfile" <<'EOF'
FROM golang:1.27.4-alpine AS backend
RUN apk add --no-cache git~=2.5
EOF
if python3 - "$check" "$apk_root" <<'PYEOF'
import importlib.util, io, json, sys, tarfile
spec = importlib.util.spec_from_file_location("staleness_check", sys.argv[1])
sc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sc)

def apkindex(entries):
    text = "".join(f"P:{n}\nV:{v}\n\n" for n, v in entries).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo("APKINDEX"); info.size = len(text)
        tf.addfile(info, io.BytesIO(text))
    return buf.getvalue()

index = apkindex([("git", "2.54.1-r0"), ("curl", "8.17.0-r1"), ("jq", "1.70-r0")])

class F:
    fixture = None
    def get(self, url, headers=None):
        if url.endswith("/main/x86_64/APKINDEX.tar.gz"):
            return True, index, None
        return False, None, "HTTP 404"

rows = {(r.file, r.id): r for r in sc.check_apk(sys.argv[2], F(), {"build/y/Dockerfile": "v3.24"})}
g = rows[("build/x/Dockerfile", "apk:git")]
assert (g.pinned, g.latest, g.status) == ("~=2.54", "2.54.1-r0", "current"), vars(g)
c = rows[("build/x/Dockerfile", "apk:curl")]
assert (c.pinned, c.status) == ("8.17.0-r0", "behind"), vars(c)
j = rows[("build/x/Dockerfile", "apk:jq")]
assert j.status == "behind", "1.7 must not fuzzy-match 1.70: " + repr(vars(j))
y = rows[("build/y/Dockerfile", "apk:git")]
assert y.status == "behind", "2.5 must not fuzzy-match 2.54.1: " + repr(vars(y))
assert g.as_json()["file"] == "build/x/Dockerfile"

# --timeout reaches every real call.
sc._LIMITS["timeout"] = 7.0
assert sc._call_timeout() == 7.0
import time
sc._LIMITS["deadline_at"] = time.monotonic() + 3
assert sc._call_timeout() <= 3.0
sc._LIMITS["deadline_at"] = time.monotonic() - 1
try:
    sc._call_timeout()
except sc.DeadlineReached:
    pass
else:
    raise AssertionError("no DeadlineReached after the deadline")
assert sc._fetch_with_retry("https://example.invalid/x", {}) == (False, None, "deadline reached")
sc._LIMITS["deadline_at"] = None

# Release dates come from the Git host for Go modules, never the proxy.
assert sc.go_module_git_tag("github.com/a/b", "v1.2.3") == ("github_commit", "a/b", "v1.2.3")
assert sc.go_module_git_tag("github.com/a/b/v2", "v2.0.1") == ("github_commit", "a/b", "v2.0.1")
assert sc.go_module_git_tag("github.com/a/b/sub", "v0.3.0") == ("github_commit", "a/b", "sub/v0.3.0")
assert sc.go_module_git_tag("golang.org/x/net", "v0.40.0") == ("github_commit", "golang/net", "v0.40.0")
assert sc.go_module_git_tag("go.example.invalid/m", "v1.0.0") is None

class D:
    fixture = None
    def __init__(self): self.urls = []
    def get(self, url, headers=None):
        self.urls.append(url)
        bodies = {
            "https://api.github.com/repos/a/b/commits/sub%2Fv0.3.0":
                {"commit": {"committer": {"date": "2026-11-01T00:00:00Z"}}},
            "https://registry.npmjs.org/w": {"time": {"2.0.0": "2026-10-02T03:04:05.000Z"}},
            "https://api.github.com/repos/s/c/releases/latest": {"published_at": "2026-09-09T00:00:00Z"},
        }
        if url in bodies:
            return True, json.dumps(bodies[url]).encode(), None
        return False, None, "HTTP 404"
d = D()
assert sc.release_date(d, ("github_commit", "a/b", "sub/v0.3.0")).startswith("2026-11-01")
assert sc.release_date(d, ("npm", "w", "2.0.0")).startswith("2026-10-02")
assert sc.release_date(d, ("github_release", "s/c")).startswith("2026-09-09")
assert sc.release_date(d, ("github_commit", "a/b", "v9.9.9")) is None
assert sc.release_date(d, ("value", "2026-01-01T00:00:00Z")) == "2026-01-01T00:00:00Z"
assert not [u for u in d.urls if "proxy.golang.org" in u]
PYEOF
then echo "ok   fuzzy apk pins, apk row files, time limits, Git-host release dates"; pass=$((pass + 1))
else echo "FAIL fuzzy apk pins, apk row files, time limits, Git-host release dates"; fail=$((fail + 1)); fi

# ---------------------------------------------------------------------------
# #215 review (63831): independent checks of the staleness features against
# spec 2.3 and owner answers 42c / 49b, and the Low hardening items.
# ---------------------------------------------------------------------------

# Release dates, 49b: the pin is behind if ANY newer version is 14+ days old,
# so a row's `released` is the date of the OLDEST version newer than the pin
# (the date from which the pin has counted as behind). A newer version with
# no date makes the row undated, and undated counts as old.
cd_root="$work/cooldown-repo"; mkdir -p "$cd_root/frontend" "$cd_root/build/opencanary" "$cd_root/supply-chain"
cp "$root/frontend/package.json" "$root/frontend/package-lock.json" "$cd_root/frontend/"
cp "$root/build/opencanary/requirements.txt" "$cd_root/build/opencanary/"
printf 'accepted: []\nunchecked: []\nalpine-branch: {}\n' > "$cd_root/supply-chain/staleness.yml"
dated_upstream() { # npm-time-json pypi-releases-json -> upstream file
  python3 - "$1" "$2" > "$work/dated.json" <<'PYEOF'
import json, sys
npm_time, pypi_releases = json.loads(sys.argv[1]), json.loads(sys.argv[2])
newest_npm = max(npm_time, key=lambda v: tuple(int(x) for x in v.split(".")))
newest_pypi = max(pypi_releases, key=lambda v: tuple(int(x) for x in v.split(".")))
print(json.dumps({
  "https://registry.npmjs.org/widget/latest": json.dumps({"version": newest_npm}),
  "https://registry.npmjs.org/widget": json.dumps({"time": npm_time}),
  "https://pypi.org/pypi/gadget/json": json.dumps({
      "info": {"version": newest_pypi},
      "urls": [{"upload_time_iso_8601": pypi_releases[newest_pypi][0]["upload_time_iso_8601"]}],
      "releases": pypi_releases}),
}))
PYEOF
}
run_dated() { python3 "$check" --root "$cd_root" --upstream "$work/dated.json" --json "$work/rows.json" >/dev/null 2>&1 || true; }
up() { printf '[{"upload_time_iso_8601":"%s"}]' "$1"; }

dated_upstream '{"1.0.0":"2025-01-01T00:00:00Z","1.1.0":"2026-10-01T00:00:00Z","1.2.0":"2026-11-15T00:00:00Z"}' \
  "{\"2.0.0\":$(up 2025-01-01T00:00:00Z),\"2.1.0\":$(up 2026-10-02T00:00:00Z),\"2.2.0\":$(up 2026-11-16T00:00:00Z)}"
run_dated
json_ok "released (npm): the OLDEST newer version's date, not the latest's (49b: any newer version 14+ days old)" '
r = rows["npm:widget"]
assert (r["status"], r["latest"]) == ("behind", "1.2.0"), r
assert r.get("released", "").startswith("2026-10-01"), r'
json_ok "released (pypi): the OLDEST newer version's date, not the latest's" '
r = rows["pypi:gadget"]
assert (r["status"], r["latest"]) == ("behind", "2.2.0"), r
assert r.get("released", "").startswith("2026-10-02"), r'

dated_upstream '{"1.0.0":"2025-01-01T00:00:00Z","1.1.0":"2026-11-10T00:00:00Z","1.2.0":"2026-11-15T00:00:00Z"}' \
  "{\"2.0.0\":$(up 2025-01-01T00:00:00Z),\"2.2.0\":$(up 2026-11-16T00:00:00Z)}"
run_dated
json_ok "released: when every newer version is young the row's date is the oldest of them" '
assert rows["npm:widget"]["released"].startswith("2026-11-10"), rows["npm:widget"]
assert rows["pypi:gadget"]["released"].startswith("2026-11-16"), rows["pypi:gadget"]'

dated_upstream '{"1.0.0":"2025-01-01T00:00:00Z","1.2.0":"2026-11-15T00:00:00Z"}' \
  "{\"2.0.0\":$(up 2025-01-01T00:00:00Z),\"2.2.0\":$(up 2026-11-16T00:00:00Z)}"
python3 - "$work/dated.json" <<'PYEOF'
import json, sys
p = sys.argv[1]; m = json.load(open(p))
d = json.loads(m["https://registry.npmjs.org/widget"]); d["time"]["1.1.0"] = None
d["versions"] = {"1.0.0": {}, "1.1.0": {}, "1.2.0": {}}   # 1.1.0 exists but has no date
m["https://registry.npmjs.org/widget"] = json.dumps(d)
json.dump(m, open(p, "w"))
PYEOF
run_dated
json_ok "released: a newer version with no date makes the row undated (undated counts as old)" '
r = rows["npm:widget"]
assert r["status"] == "behind" and not r.get("released"), r'

# --timeout: a per-call limit that is a usage error at 0, and it really
# bounds a hung server (local HTTP server; nothing leaves this host).
code=0; python3 "$check" --root "$root" --upstream "$work/upstream.json" --timeout 0 >/dev/null 2>&1 || code=$?
if [ "$code" = 2 ]; then echo "ok   --timeout 0 is a usage error"; pass=$((pass + 1))
else echo "FAIL --timeout 0: exit $code (want 2)"; fail=$((fail + 1)); fi

cat > "$work/srv.py" <<'PYEOF'
# Test server. argv: mode logfile [redirect-port]. Prints its port on line 1.
#   hang     never answers (sleeps 20 s)
#   429      answers HTTP 429 to everything (counts requests)
#   big      200 with Content-Length 256 MiB, streamed; logs "SENT n"
#   redirect 302 to http://localhost:<port>/<same path>
#   record   200 {"state":"closed", ...}; logs request headers
import http.server, sys, threading, time, json
mode, log = sys.argv[1], sys.argv[2]
rport = sys.argv[3] if len(sys.argv) > 3 else ""
lock = threading.Lock()
def note(line):
    with lock, open(log, "a") as f:
        f.write(line + "\n")
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_GET(self):
        for k, v in self.headers.items():
            note(f"HDR {k.lower()}: {v}")
        note("REQ " + self.path)
        if mode == "hang":
            time.sleep(20); return
        if mode == "429":
            self.send_response(429); self.send_header("Content-Length", "0"); self.end_headers(); return
        if mode == "redirect":
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{rport}{self.path}")
            self.send_header("Content-Length", "0"); self.end_headers(); return
        if mode == "record":
            body = json.dumps({"state": "closed", "version": "9.9.9", "time": {}}).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body); return
        if mode == "big":
            total, sent, chunk = 256 * 1024 * 1024, 0, b"0" * 65536
            self.send_response(200); self.send_header("Content-Length", str(total)); self.end_headers()
            try:
                while sent < total:
                    self.wfile.write(chunk); sent += len(chunk)
            except OSError:
                pass
            note(f"SENT {sent}")
    do_HEAD = do_GET
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
print(srv.server_address[1], flush=True)
srv.serve_forever()
PYEOF
srv_pids=()
start_srv() { # mode log [redirect-port] -> port in $srv_port
  local portfile="$work/port.$RANDOM"
  python3 -I "$work/srv.py" "$@" > "$portfile" &
  srv_pids+=($!)
  for _ in $(seq 50); do [ -s "$portfile" ] && break; sleep 0.1; done
  srv_port="$(head -n1 "$portfile")"
}
trap 'kill "${srv_pids[@]}" 2>/dev/null || true; rm -rf "$work"' EXIT
export no_proxy=127.0.0.1,localhost NO_PROXY=127.0.0.1,localhost
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY 2>/dev/null || true

start_srv hang "$work/hang.log"; hang_port="$srv_port"
start_srv 429 "$work/429.log"; r429_port="$srv_port"
start_srv big "$work/big.log"; big_port="$srv_port"
start_srv record "$work/record.log"; rec_port="$srv_port"
start_srv redirect "$work/redir.log" "$rec_port"; redir_port="$srv_port"

net_ok() { # name python-body (sc = module; ports and log dir in P)
  local name="$1" body="$2"
  if python3 -I - "$check" "$hang_port" "$r429_port" "$big_port" "$redir_port" "$work" "$body" <<'PYEOF'
import importlib.util, os, sys, time
spec = importlib.util.spec_from_file_location("staleness_check", sys.argv[1])
sc = importlib.util.module_from_spec(spec); spec.loader.exec_module(sc)
P = dict(zip(("hang", "r429", "big", "redir", "work"), sys.argv[2:7]))
exec(sys.argv[7])
PYEOF
  then echo "ok   $name"; pass=$((pass + 1))
  else echo "FAIL $name"; fail=$((fail + 1)); fi
}

net_ok "--timeout bounds a call to a server that never answers" '
sc._LIMITS["timeout"] = 1.0; sc._LIMITS["deadline_at"] = None
t = time.monotonic()
ok, body, err = sc._fetch_with_retry("http://127.0.0.1:%s/x" % P["hang"], {})
took = time.monotonic() - t
assert ok is False and took < 5, (ok, err, took)'

net_ok "retries never sleep past --deadline (HTTP 429 is retried with 2, 4, 6 s pauses)" '
sc._LIMITS["timeout"] = 5.0; sc._LIMITS["deadline_at"] = time.monotonic() + 3
t = time.monotonic()
ok, body, err = sc._fetch_with_retry("http://127.0.0.1:%s/x" % P["r429"], {})
took = time.monotonic() - t
assert ok is False and took < 5, ("slept past the deadline", took, err)
assert "deadline" in err or "429" in err, err'

net_ok "size limit: a server offering 256 MiB is a failure, not a 256 MiB body" '
f = sc.Fetcher()
ok, body, err = f.get("http://127.0.0.1:%s/doc" % P["big"])
assert ok is False, "an oversize response must be a failure, got %d bytes" % len(body or b"")'

net_ok "size limit: the oversize body is not read to the end" '
f = sc.Fetcher()
f.get("http://127.0.0.1:%s/doc2" % P["big"])
time.sleep(1)
log = open(os.path.join(P["work"], "big.log")).read()
sent = [int(l.split()[1]) for l in log.splitlines() if l.startswith("SENT ")]
assert sent and max(sent) < 128 * 1024 * 1024, ("the whole body was read: %r" % sent)'

net_ok "no token is forwarded to another host on a redirect (Authorization, PRIVATE-TOKEN)" '
f = sc.Fetcher()
f.get("http://127.0.0.1:%s/repos/x/tags" % P["redir"],
      {"Authorization": "Bearer not-a-real-token-5c1a9e", "PRIVATE-TOKEN": "not-a-real-token-5c1a9e"})
first = open(os.path.join(P["work"], "redir.log")).read()
assert "authorization: bearer not-a-real-token-5c1a9e" in first.lower(), "test sanity: first host gets the header"
second = open(os.path.join(P["work"], "record.log")).read()
assert "not-a-real-token-5c1a9e" not in second, "token forwarded to another host:\n" + second'

# Spec 2.3: build/birdcage/Dockerfile has no FROM alpine:X.Y (its base is
# golang:...-alpine), so supply-chain/staleness.yml must carry its
# alpine-branch: entry, and the `git~=` pin must then read as a row.
repo_top="$(cd "$here/.." && pwd)"
if python3 -I - "$check" "$repo_top" <<'PYEOF'
import importlib.util, io, sys, tarfile, yaml, re
spec = importlib.util.spec_from_file_location("staleness_check", sys.argv[1])
sc = importlib.util.module_from_spec(spec); spec.loader.exec_module(sc)
top = sys.argv[2]
cfg = yaml.safe_load(open(top + "/supply-chain/staleness.yml"))
branch = (cfg.get("alpine-branch") or {}).get("build/birdcage/Dockerfile")
assert branch and re.fullmatch(r"v3\.\d+", str(branch)), "alpine-branch entry for build/birdcage/Dockerfile: %r" % branch
text = open(top + "/build/birdcage/Dockerfile").read()
assert "git~=" in text
m = re.search(r"^FROM golang:[\d.]+-alpine(\d+\.\d+)?", text, re.M)
tags = []
class F:
    fixture = None
    def get(self, url, headers=None):
        tags.append(url)
        data = b"P:git\nV:2.54.1-r0\n\n"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            i = tarfile.TarInfo("APKINDEX"); i.size = len(data); tf.addfile(i, io.BytesIO(data))
        return True, buf.getvalue(), None
rows = [r for r in sc.check_apk(top, F(), cfg["alpine-branch"]) if r.file == "build/birdcage/Dockerfile"]
git = [r for r in rows if r.id == "apk:git"]
assert git and git[0].status == "current" and git[0].pinned == "~=2.54", [vars(r) for r in rows]
assert any(f"/alpine/{branch}/" in u for u in tags), (branch, tags)
PYEOF
then echo "ok   build/birdcage/Dockerfile has an alpine-branch entry and its git~= pin is a row"; pass=$((pass + 1))
else echo "FAIL build/birdcage/Dockerfile alpine-branch entry / git~= row"; fail=$((fail + 1)); fi

# `~=` pins with no matching version in the index are behind, and the row
# says which Dockerfile it came from.
if python3 -I - "$check" <<'PYEOF'
import importlib.util, io, os, sys, tarfile, tempfile
spec = importlib.util.spec_from_file_location("staleness_check", sys.argv[1])
sc = importlib.util.module_from_spec(spec); spec.loader.exec_module(sc)
d = tempfile.mkdtemp(); os.makedirs(d + "/build/z")
open(d + "/build/z/Dockerfile", "w").write("FROM alpine:3.24\nRUN apk add --no-cache git~=2.60 tzdata~=2025\n")
class F:
    fixture = None
    def get(self, url, headers=None):
        data = b"P:git\nV:2.54.1-r0\n\nP:tzdata\nV:2025c-r0\n\n"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            i = tarfile.TarInfo("APKINDEX"); i.size = len(data); tf.addfile(i, io.BytesIO(data))
        return True, buf.getvalue(), None
rows = {r.id: r for r in sc.check_apk(d, F(), {})}
assert rows["apk:git"].status == "behind" and rows["apk:git"].pinned == "~=2.60", vars(rows["apk:git"])
assert rows["apk:tzdata"].status == "current", vars(rows["apk:tzdata"])
PYEOF
then echo "ok   ~= apk pin with no matching version is behind; letters after the prefix still match"; pass=$((pass + 1))
else echo "FAIL ~= apk pin semantics"; fail=$((fail + 1)); fi

# A live hold still reads as accepted in --json, with no lapsed marker.
printf '%s\n' "$alpine_behind_dated" > "$work/upstream.json"
printf '%s\n' "$accepted_far" > "$root/supply-chain/staleness.yml"
python3 "$check" --root "$root" --upstream "$work/upstream.json" --today 2026-01-01 \
  --json "$work/rows.json" > /dev/null 2>&1 || true
json_ok "--json: a live hold is accepted and carries no lapsed marker" '
r = rows["image:alpine:3.20"]
assert r["status"] == "accepted" and not (r.get("hold") or {}).get("lapsed"), r
assert "today" in j'

# ---------------------------------------------------------------------------
# #215 note 63992: Go module, action and tool rows are dated from the Git
# host's tag list: the release date of a row is the date of the OLDEST tag
# newer than the pin (a minor bump included, not only the next patch), read
# from https://api.github.com/repos/<o>/<r>/tags?per_page=100 and one
# commit (or release) lookup for that tag -- never the Go proxy.
# ---------------------------------------------------------------------------
cat > "$work/dating.py" <<'PYEOF'
import importlib.util, json, os, sys, tempfile
spec = importlib.util.spec_from_file_location("staleness_check", sys.argv[1])
sc = importlib.util.module_from_spec(spec); spec.loader.exec_module(sc)
kind, scen = sys.argv[2], sys.argv[3]

# kind: (repo, pin, pin as the manifest writes it)
K = {"gomod": ("golang/net", "v0.62.0"), "owner": ("tomlawesome/gauntlet", "v0.4.1"),
     "action": ("actions/checkout", "v4.1.0"), "tool": ("sigstore/cosign", "v2.4.0")}
repo, pin = K[kind]
M, m, pt = (int(x) for x in pin.lstrip("v").split("."))
patch, minor = f"v{M}.{m}.{pt + 1}", f"v{M}.{m + 1}.0"
newer = {"minor": [minor], "patch": [patch], "multi": [patch, minor], "undated": [patch, minor]}[scen]
dates = {patch: "2026-10-01T00:00:00Z", minor: "2026-11-16T00:00:00Z"}
if scen == "undated":
    del dates[patch]
want = {"minor": dates.get(minor), "patch": dates.get(patch), "multi": dates.get(patch), "undated": None}[scen]
tags = [{"name": t} for t in [pin, "nightly", "v0.0", *newer]]
newest = max(newer, key=lambda v: tuple(int(x) for x in v.lstrip("v").split(".")))

served = {f"https://api.github.com/repos/{repo}/tags?per_page=100": tags}
for t, d in dates.items():
    served[f"https://api.github.com/repos/{repo}/commits/{t}"] = {"commit": {"committer": {"date": d}}}
    served[f"https://api.github.com/repos/{repo}/releases/tags/{t}"] = {"published_at": d}
served[f"https://api.github.com/repos/{repo}/releases/latest"] = {"tag_name": newest, "published_at": dates.get(newest, "2026-11-16T00:00:00Z")}
served["https://proxy.golang.org/golang.org/x/net/@latest"] = {"Version": newest}

urls = []
class F:
    fixture = None
    def get(self, url, headers=None):
        urls.append(url)
        if url in served:
            return True, json.dumps(served[url]).encode(), None
        return False, None, "HTTP 404"
    def head_digest(self, url, headers=None):
        return False, None, "HTTP 404"

d = tempfile.mkdtemp()
if kind in ("gomod", "owner"):
    mod = "golang.org/x/net" if kind == "gomod" else "github.com/tomlawesome/gauntlet"
    open(d + "/go.mod", "w").write(f"module t\n\ngo 1.21.0\n\nrequire (\n\t{mod} {pin}\n)\n")
    rows = sc.check_go_modules(d, F())
elif kind == "action":
    os.makedirs(d + "/.github/workflows")
    open(d + "/.github/workflows/ci.yml", "w").write(
        "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@" + "a" * 40 + f" # {pin}\n")
    rows = sc.check_actions(d, F())
else:
    os.makedirs(d + "/scripts")
    open(d + "/scripts/ensure-cosign.sh", "w").write(f'COSIGN_VERSION="{pin}"\n')
    rows = [r for r in sc.check_tools(d, F()) if r.id == "tool:cosign"]
assert len(rows) == 1 and rows[0].status == "behind", [vars(r) for r in rows]
sc.add_release_dates(rows, F())
got = rows[0].released
if want is None:
    assert not got, f"a newer tag with no date must leave the row undated, got {got!r}"
else:
    assert got and got.startswith(want[:10]), f"released={got!r}, want the oldest newer tag's date {want}"
assert not any("proxy.golang.org" in u and "@latest" not in u for u in urls), \
    "dates must not come from the Go proxy: " + repr([u for u in urls if "proxy.golang.org" in u])
PYEOF
for kind in gomod owner action tool; do
  for scen in minor patch multi undated; do
    if python3 -I "$work/dating.py" "$check" "$kind" "$scen" 2>"$work/dating.err"; then
      echo "ok   dating ($kind, $scen): oldest newer tag from the Git host's tag list"; pass=$((pass + 1))
    else
      echo "FAIL dating ($kind, $scen): oldest newer tag from the Git host's tag list"
      tail -n 3 "$work/dating.err" | cut -c1-220 | sed 's/^/       /'; fail=$((fail + 1))
    fi
  done
done

# Same host, https -> http: the scheme is compared too, so no credential
# survives a downgrade (a port or scheme change is a different origin). The
# redirect handler is driven directly: the origin cannot be faked with two
# local servers, since their ports differ.
if python3 -I - "$check" <<'PYEOF'
import importlib.util, io, sys, urllib.request
spec = importlib.util.spec_from_file_location("staleness_check", sys.argv[1])
sc = importlib.util.module_from_spec(spec); spec.loader.exec_module(sc)
H = sc._SameHostCredentials()
def follow(old, new):
    req = urllib.request.Request(old, headers={"Authorization": "Bearer not-a-real-token-5c1a9e",
                                              "PRIVATE-TOKEN": "not-a-real-token-5c1a9e"})
    out = H.redirect_request(req, io.BytesIO(b""), 302, "Found", {}, new)
    names = {k.lower() for k in list(out.headers) + list(out.unredirected_hdrs)}
    return names
down = follow("https://example.invalid/a", "http://example.invalid/a")
assert not ({"authorization", "private-token"} & down), f"credential kept on https -> http: {down}"
same = follow("https://example.invalid/a", "https://example.invalid/b")
assert {"authorization", "private-token"} <= same, f"same origin should keep it (sanity): {same}"
PYEOF
then echo "ok   staleness-check: no credential on a same-host https -> http redirect"; pass=$((pass + 1))
else echo "FAIL staleness-check: no credential on a same-host https -> http redirect"; fail=$((fail + 1)); fi

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
