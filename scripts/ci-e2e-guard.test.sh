#!/usr/bin/env bash
# Tests for ci-e2e-guard.py. A guard that cannot fail guards nothing,
# so every rule it enforces has a case here that proves it fires.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
guard="$here/ci-e2e-guard.py"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

# expect <want-exit> <name> <yaml>
expect() {
  local want="$1" name="$2" yaml="$3" got=0 out
  printf '%s\n' "$yaml" > "$work/ci.yml"
  out="$(python3 "$guard" "$work/ci.yml" 2>&1)" || got=$?
  if [ "$got" = "$want" ]; then
    echo "ok   $name"; pass=$((pass + 1))
  else
    echo "FAIL $name: exit $got, want $want"; echo "$out" | sed 's/^/       /'
    fail=$((fail + 1))
  fi
}

# Both hop anchors, in the shape .gitlab-ci.yml actually uses (a
# `rules:` list the loader expands into the job via `<<:`). Every
# fixture below that is meant to pass, or to fail for a reason other
# than the anchors themselves, carries both of these so that reason is
# the only one in play.
anchors='.gate: &gate
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "dev"
.higher_bar: &higher_bar
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "preview"'

good="stages: [test, e2e]
$anchors
e2e:enrol:
  stage: e2e
  <<: *gate
  script: [true]
e2e:enrol:postgres:
  stage: e2e
  <<: *higher_bar
  script: [true]"

expect 0 "both anchors present, one job of each class, passes" "$good"

expect 1 "the stage missing from stages: is caught" 'stages: [test]
test:go:
  stage: test
  script: [true]'

expect 1 "a stage with no jobs is caught" 'stages: [test, e2e]
test:go:
  stage: test
  script: [true]'

expect 1 "allow_failure is caught" "stages: [e2e]
$anchors
e2e:enrol:
  stage: e2e
  allow_failure: true
  <<: *gate
  script: [true]
e2e:enrol:postgres:
  stage: e2e
  <<: *higher_bar
  script: [true]"

expect 1 "when: manual is caught" "stages: [e2e]
$anchors
e2e:enrol:
  stage: e2e
  when: manual
  <<: *gate
  script: [true]
e2e:enrol:postgres:
  stage: e2e
  <<: *higher_bar
  script: [true]"

expect 1 "rules that never reach a merge request are caught" "stages: [e2e]
$anchors
e2e:enrol:
  stage: e2e
  <<: *gate
  script: [true]
e2e:enrol:postgres:
  stage: e2e
  <<: *higher_bar
  script: [true]
e2e:scheduled-only:
  stage: e2e
  rules:
    - if: \$CI_PIPELINE_SOURCE == \"schedule\"
  script: [true]"

expect 1 "a rule matching merge requests only to refuse them is caught" "stages: [e2e]
$anchors
e2e:enrol:
  stage: e2e
  <<: *gate
  script: [true]
e2e:enrol:postgres:
  stage: e2e
  <<: *higher_bar
  script: [true]
e2e:refused-on-mr:
  stage: e2e
  rules:
    - if: \$CI_PIPELINE_SOURCE == \"merge_request_event\"
      when: never
  script: [true]"

# A job with no rules at all used to run everywhere and be waved through
# as stricter-than-required. Now that every e2e job's rules must be
# exactly one of the two anchors (docs/ci-hops.md), that leniency is
# gone: a job with no rules is a shape that matches neither anchor, and
# the guard refuses it the same as any other unrecognised shape.
expect 1 "a job with no rules is now an unrecognised shape" "stages: [e2e]
$anchors
e2e:enrol:
  stage: e2e
  <<: *gate
  script: [true]
e2e:enrol:postgres:
  stage: e2e
  <<: *higher_bar
  script: [true]
e2e:no-rules:
  stage: e2e
  script: [true]"

expect 1 "hand-written rules matching neither anchor are caught" "stages: [e2e]
$anchors
e2e:enrol:
  stage: e2e
  <<: *gate
  script: [true]
e2e:enrol:postgres:
  stage: e2e
  <<: *higher_bar
  script: [true]
e2e:hand-written:
  stage: e2e
  rules:
    - if: \$CI_PIPELINE_SOURCE == \"merge_request_event\"
    - if: \$CI_COMMIT_BRANCH == \"main\"
  script: [true]"

expect 1 ".higher_bar anchor missing is caught" "stages: [e2e]
.gate: &gate
  rules:
    - if: \$CI_PIPELINE_SOURCE == \"merge_request_event\"
    - if: \$CI_COMMIT_BRANCH == \"dev\"
e2e:enrol:
  stage: e2e
  <<: *gate
  script: [true]"

expect 1 ".gate anchor missing is caught" "stages: [e2e]
.higher_bar: &higher_bar
  rules:
    - if: \$CI_PIPELINE_SOURCE == \"merge_request_event\"
    - if: \$CI_COMMIT_BRANCH == \"preview\"
e2e:enrol:postgres:
  stage: e2e
  <<: *higher_bar
  script: [true]"

expect 1 "every e2e job at .gate, none at .higher_bar, is caught" "stages: [e2e]
$anchors
e2e:enrol:
  stage: e2e
  <<: *gate
  script: [true]
e2e:enrol2:
  stage: e2e
  <<: *gate
  script: [true]"

expect 1 "a .higher_bar job with no .gate job is caught" "stages: [e2e]
$anchors
e2e:enrol:postgres:
  stage: e2e
  <<: *higher_bar
  script: [true]"

# Templates are never run on their own, so their settings cannot skip
# anything; only real jobs are judged.
expect 0 "a dot-prefixed template is not judged" "stages: [e2e]
$anchors
.e2e_template:
  stage: e2e
  when: manual
e2e:enrol:
  stage: e2e
  <<: *gate
  script: [true]
e2e:enrol:postgres:
  stage: e2e
  <<: *higher_bar
  script: [true]"

expect 2 "an unreadable file fails red, not green" 'stages: [e2e
  this is not: valid yaml: at all'

# The real thing must pass.
repo_root="$(cd "$here/.." && pwd)"
if python3 "$guard" "$repo_root/.gitlab-ci.yml" >/dev/null 2>&1; then
  echo "ok   this repository's own .gitlab-ci.yml passes"; pass=$((pass + 1))
else
  echo "FAIL this repository's own .gitlab-ci.yml does not pass"; fail=$((fail + 1))
fi

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
