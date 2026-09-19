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

good='stages: [test, e2e]
e2e:enrol:
  stage: e2e
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script: [true]'

expect 0 "a proper e2e stage passes" "$good"

expect 1 "the stage missing from stages: is caught" 'stages: [test]
test:go:
  stage: test
  script: [true]'

expect 1 "a stage with no jobs is caught" 'stages: [test, e2e]
test:go:
  stage: test
  script: [true]'

expect 1 "allow_failure is caught" 'stages: [e2e]
e2e:enrol:
  stage: e2e
  allow_failure: true
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script: [true]'

expect 1 "when: manual is caught" 'stages: [e2e]
e2e:enrol:
  stage: e2e
  when: manual
  script: [true]'

expect 1 "rules that never reach a merge request are caught" 'stages: [e2e]
e2e:enrol:
  stage: e2e
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
  script: [true]'

expect 1 "a rule matching merge requests only to refuse them is caught" 'stages: [e2e]
e2e:enrol:
  stage: e2e
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      when: never
  script: [true]'

# A job with no rules at all runs everywhere, which is stricter than
# required, not weaker -- it must not be reported.
expect 0 "a job with no rules is fine" 'stages: [e2e]
e2e:enrol:
  stage: e2e
  script: [true]'

# Templates are never run on their own, so their settings cannot skip
# anything; only real jobs are judged.
expect 0 "a dot-prefixed template is not judged" 'stages: [e2e]
.e2e_template:
  stage: e2e
  when: manual
e2e:enrol:
  stage: e2e
  script: [true]'

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
