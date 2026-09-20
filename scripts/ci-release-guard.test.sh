#!/usr/bin/env bash
# Tests for ci-release-guard.py. A guard that cannot fail guards nothing,
# so every rule it enforces has a case here that proves it fires.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
guard="$here/ci-release-guard.py"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

# expect <want-exit> <name> <yaml> [needle]
# `needle`, when given, must appear somewhere in the guard's output -- this
# is how each rule's fixture proves the message names the offending job,
# not just that something failed.
expect() {
  local want="$1" name="$2" yaml="$3" needle="${4:-}" got=0 out ok=1
  printf '%s\n' "$yaml" > "$work/ci.yml"
  out="$(python3 "$guard" "$work/ci.yml" 2>&1)" || got=$?
  [ "$got" = "$want" ] || ok=0
  if [ -n "$needle" ] && ! grep -qF "$needle" <<<"$out"; then
    ok=0
  fi
  if [ "$ok" = 1 ]; then
    echo "ok   $name"; pass=$((pass + 1))
  else
    echo "FAIL $name: exit $got (want $want)$([ -n "$needle" ] && echo ", needle '$needle' missing")"
    echo "$out" | sed 's/^/       /'
    fail=$((fail + 1))
  fi
}

# A fixture that satisfies every rule: a release stage with a signer (tagged
# for the signing runner, not shipping, not verifying), a verifier, and a
# publisher, all interruptible and none allowed to fail.
good="stages: [build, test, release]
sign:
  stage: release
  tags: [birdcage-signing]
  interruptible: false
  script:
    - scripts/attest-tested-image.sh
verify:
  stage: release
  interruptible: false
  script:
    - scripts/verify-validation-evidence.sh
publish:
  stage: release
  interruptible: false
  script:
    - scripts/publish-channel.sh"

expect 0 "a compliant release stage passes" "$good" "signed exactly once by sign"

# Rule 1: the release stage itself.
expect 1 "rule 1: release missing from stages: is caught" "stages: [build, test]
sign:
  stage: release
  tags: [birdcage-signing]
  interruptible: false
  script:
    - scripts/attest-tested-image.sh" "release"

expect 1 "rule 1: a release stage with no job in it is caught" "stages: [build, test, release]
sign:
  stage: build
  tags: [birdcage-signing]
  interruptible: false
  script:
    - scripts/attest-tested-image.sh" "no job is in it"

# Rule 2: exactly one signer.
expect 1 "rule 2: no job calling attest-tested-image.sh is caught" "stages: [build, test, release]
verify:
  stage: release
  interruptible: false
  script:
    - scripts/verify-validation-evidence.sh" "no job calls scripts/attest-tested-image.sh"

expect 1 "rule 2: two jobs calling attest-tested-image.sh is caught" "stages: [build, test, release]
sign:
  stage: release
  tags: [birdcage-signing]
  interruptible: false
  script:
    - scripts/attest-tested-image.sh
sign2:
  stage: release
  tags: [birdcage-signing]
  interruptible: false
  script:
    - scripts/attest-tested-image.sh" "sign, sign2"

# Rule 3: the signer must carry the signing runner's tag.
expect 1 "rule 3: signer missing the birdcage-signing tag is caught" "stages: [build, test, release]
sign:
  stage: release
  interruptible: false
  script:
    - scripts/attest-tested-image.sh" "sign: calls scripts/attest-tested-image.sh but its \`tags:\` do not include"

# Rule 4: the signer must not also ship. Uses a raw docker push rather than
# publish-channel.sh/promote-release.sh, so this fixture does not also trip
# rule 6 below (which is about that pair specifically) -- each fixture
# should isolate the rule it is testing wherever the rules allow it.
expect 1 "rule 4: signer also running docker push is caught" "stages: [build, test, release]
sign:
  stage: release
  tags: [birdcage-signing]
  interruptible: false
  script:
    - scripts/attest-tested-image.sh
    - docker push registry.example/birdcage:latest" "sign: signs the image with scripts/attest-tested-image.sh but also runs \`docker push\`"

# Rule 5: signing and verifying are different jobs by design.
expect 1 "rule 5: one job calling both attest and verify is caught" "stages: [build, test, release]
sign:
  stage: release
  tags: [birdcage-signing]
  interruptible: false
  script:
    - scripts/attest-tested-image.sh
    - scripts/verify-validation-evidence.sh" "sign: calls both scripts/attest-tested-image.sh and scripts/verify-validation-evidence.sh"

# Rule 6: the converse of rule 4, phrased so the message names the shipping
# job. A job that calls both publish-channel.sh and attest-tested-image.sh
# is, by construction, also the sole signer calling a ship script -- so this
# fixture necessarily trips rule 4's message as well. That overlap is
# expected: the two rules describe the same wrong shape from each job's own
# point of view, and this test only asserts that rule 6's own wording (naming
# the job as the shipper) is present, not that it fires alone.
expect 1 "rule 6: a job that ships and signs is caught, naming the shipper" "stages: [build, test, release]
ship:
  stage: release
  tags: [birdcage-signing]
  interruptible: false
  script:
    - scripts/attest-tested-image.sh
    - scripts/publish-channel.sh" "ship: ships the release but also calls scripts/attest-tested-image.sh"

# Rule 7: every release job must be interruptible: false.
expect 1 "rule 7: a release job without interruptible: false is caught" "stages: [build, test, release]
sign:
  stage: release
  tags: [birdcage-signing]
  script:
    - scripts/attest-tested-image.sh" "sign: is not \`interruptible: false\`"

# Rule 8: no release job may be allowed to fail.
expect 1 "rule 8: a release job with allow_failure: true is caught" "stages: [build, test, release]
sign:
  stage: release
  tags: [birdcage-signing]
  interruptible: false
  allow_failure: true
  script:
    - scripts/attest-tested-image.sh" "sign: allow_failure is true"

# A dot-prefixed template is never run on its own, so its shape cannot
# violate anything -- only real jobs are judged.
expect 0 "a dot-prefixed template is not judged" ".template: &template
  stage: release
  allow_failure: true
stages: [build, test, release]
sign:
  stage: release
  tags: [birdcage-signing]
  interruptible: false
  script:
    - scripts/attest-tested-image.sh"

got=0
out="$(python3 "$guard" "$work/does-not-exist.yml" 2>&1)" || got=$?
if [ "$got" = 2 ]; then
  echo "ok   a missing file fails red, not green"; pass=$((pass + 1))
else
  echo "FAIL a missing file fails red, not green: exit $got"
  echo "$out" | sed 's/^/       /'
  fail=$((fail + 1))
fi

expect 2 "unparseable YAML fails red, not green" 'stages: [release
  this is not: valid yaml: at all'

# Deliberately not tested here: this repository's own .gitlab-ci.yml. The
# release stage is being written concurrently with this guard (issue #90),
# so it is expected -- and fine -- for the real file to fail this guard
# right now. That is a fact for the person wiring the stage in, not a bug
# in this test file.

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
