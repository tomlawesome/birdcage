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
EOF

# expect <want-exit> <name> <upstream-json> <staleness-yml> [--today VALUE]
expect() {
  local want="$1" name="$2" upstream_json="$3" staleness_yml="$4"
  shift 4
  local got=0 out
  printf '%s\n' "$upstream_json" > "$work/upstream.json"
  printf '%s\n' "$staleness_yml" > "$root/supply-chain/staleness.yml"
  out="$(python3 "$check" --root "$root" --upstream "$work/upstream.json" "$@" 2>&1)" || got=$?
  if [ "$got" = "$want" ]; then
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
# exist), 3.21 (the only one that differs between "current" and
# "behind"), 3.22 (only reached if 3.21 exists, to confirm the walk
# stops there), and 4.0 (the one-level-looser probe for the informational
# "newer line" note, always made, always a miss here).
alpine_current='{
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.20": "{}",
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.21": {"status": 404},
  "https://hub.docker.com/v2/repositories/library/alpine/tags/4.0": {"status": 404}
}'
alpine_behind='{
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.20": "{}",
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.21": "{}",
  "https://hub.docker.com/v2/repositories/library/alpine/tags/3.22": {"status": 404},
  "https://hub.docker.com/v2/repositories/library/alpine/tags/4.0": {"status": 404}
}'

# upstream_json <alpine-probes-json> [drop-pypi (1 to omit it)]
upstream_json() {
  local alpine_probes="$1" drop_pypi="${2:-0}"
  python3 - "$alpine_probes" "$drop_pypi" <<'PYEOF'
import json, sys
alpine_probes, drop_pypi = sys.argv[1], sys.argv[2]
merged = {
    "https://go.dev/dl/?mode=json": json.dumps([{"version": "go1.21.0", "stable": True}]),
    "https://registry.npmjs.org/widget/latest": json.dumps({"version": "1.0.0"}),
}
if drop_pypi != "1":
    merged["https://pypi.org/pypi/gadget/json"] = json.dumps({"info": {"version": "2.0.0"}})
merged.update(json.loads(alpine_probes))
print(json.dumps(merged))
PYEOF
}

no_config="accepted: []
unchecked: []
alpine-branch: {}"

expect 0 "all current" "$(upstream_json "$alpine_current")" "$no_config"

expect 1 "one deliberately stale pin (image:alpine:3.20 behind)" \
  "$(upstream_json "$alpine_behind")" "$no_config"

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

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
