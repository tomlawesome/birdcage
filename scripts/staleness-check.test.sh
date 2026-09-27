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
alpine-branch: {}"

expect 0 "an unchecked entry covers the unreachable pin" \
  "$missing_url_upstream" "$unchecked_config"

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

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
