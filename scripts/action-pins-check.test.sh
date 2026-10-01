#!/usr/bin/env bash
# Tests for action-pins-check.py (#27). A supply-chain check that cannot
# fail guards nothing, so every rule it enforces has a case here that
# proves it fires -- and the real repository is proved to pass it too.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"
guard="$here/action-pins-check.py"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

# A reviewBy comfortably in the future, so fixtures that are not testing
# expiry never trip it by accident.
FUTURE="2099-01-01"
PAST="2000-01-01"

# expect <want-exit> <name> <workflow-yaml> <policy-json> [needle]
expect() {
  local want="$1" name="$2" workflow="$3" policy="$4" needle="${5:-}" got=0 out ok=1
  rm -rf "$work/workflows"; mkdir -p "$work/workflows"
  printf '%s\n' "$workflow" > "$work/workflows/w.yml"
  printf '%s\n' "$policy" > "$work/policy.json"
  out="$(python3 "$guard" "$work/workflows" --policy "$work/policy.json" 2>&1)" || got=$?
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

good_workflow="on: push
jobs:
  build:
    steps:
      - uses: actions/checkout@111111111111111111111111111111111111111a # v1.2.3"

good_policy='{
  "schemaVersion": 1,
  "actions": [
    {
      "name": "actions/checkout",
      "commit": "111111111111111111111111111111111111111a",
      "version": "v1.2.3",
      "licence": "MIT",
      "source": "https://github.com/actions/checkout",
      "updateOwner": "Birdcage maintainers",
      "reviewBy": "'"$FUTURE"'"
    }
  ],
  "exceptions": []
}'

expect 0 "a recorded, full-SHA, matching pin passes" "$good_workflow" "$good_policy" "1 \`uses:\` pin(s)"

# Rule: pin not a full 40-hex commit.
expect 1 "a short SHA is caught" "on: push
jobs:
  build:
    steps:
      - uses: actions/checkout@1111111 # v1.2.3" "$good_policy" "not a full 40-hex commit SHA"

# Rule: pin the policy does not record at all.
expect 1 "an unrecorded pin is caught" "on: push
jobs:
  build:
    steps:
      - uses: actions/setup-node@222222222222222222222222222222222222222b # v4.0.0" "$good_policy" "records no \`actions/setup-node\` entry"

# Rule: the workflow pins a different commit than the policy records.
expect 1 "a pin whose commit does not match the policy's is caught" "on: push
jobs:
  build:
    steps:
      - uses: actions/checkout@333333333333333333333333333333333333333c # v1.2.3" "$good_policy" "the policy records actions/checkout at 111111111111111111111111111111111111111a"

# Rule: inline comment disagrees with the recorded version.
expect 1 "a mismatched version comment is caught" "on: push
jobs:
  build:
    steps:
      - uses: actions/checkout@111111111111111111111111111111111111111a # v9.9.9" "$good_policy" "inline comment says \`v9.9.9\`"

# Rule: no inline comment at all to check.
expect 1 "a pin with no version comment is caught" "on: push
jobs:
  build:
    steps:
      - uses: actions/checkout@111111111111111111111111111111111111111a" "$good_policy" "no inline \`# vX.Y.Z\` version comment"

# Rule: an expired reviewBy on a recorded action is caught.
expect 1 "an expired reviewBy is caught" "$good_workflow" '{
  "schemaVersion": 1,
  "actions": [
    {
      "name": "actions/checkout",
      "commit": "111111111111111111111111111111111111111a",
      "version": "v1.2.3",
      "licence": "MIT",
      "source": "https://github.com/actions/checkout",
      "updateOwner": "Birdcage maintainers",
      "reviewBy": "'"$PAST"'"
    }
  ],
  "exceptions": []
}' "reviewBy 2000-01-01 has passed"

# Rule: a duplicate action name in the policy is caught.
expect 1 "a duplicate policy entry is caught" "$good_workflow" '{
  "schemaVersion": 1,
  "actions": [
    {"name": "actions/checkout", "commit": "111111111111111111111111111111111111111a", "version": "v1.2.3", "licence": "MIT", "source": "https://github.com/actions/checkout", "updateOwner": "x", "reviewBy": "'"$FUTURE"'"},
    {"name": "actions/checkout", "commit": "111111111111111111111111111111111111111a", "version": "v1.2.3", "licence": "MIT", "source": "https://github.com/actions/checkout", "updateOwner": "x", "reviewBy": "'"$FUTURE"'"}
  ],
  "exceptions": []
}' "is recorded more than once"

# Rule: schemaVersion must be 1.
expect 1 "a wrong schemaVersion is caught" "$good_workflow" '{
  "schemaVersion": 2,
  "actions": [
    {"name": "actions/checkout", "commit": "111111111111111111111111111111111111111a", "version": "v1.2.3", "licence": "MIT", "source": "https://github.com/actions/checkout", "updateOwner": "x", "reviewBy": "'"$FUTURE"'"}
  ],
  "exceptions": []
}' "schemaVersion must be 1"

# Deliberate exceptions (#27 acceptance 4): a named exception, with its own
# reason/owner/reviewBy, covers a pin the rules above would otherwise catch.
exception_policy='{
  "schemaVersion": 1,
  "actions": [],
  "exceptions": [
    {
      "name": "actions/checkout",
      "reason": "test fixture",
      "owner": "Birdcage maintainers",
      "reviewBy": "'"$FUTURE"'"
    }
  ]
}'

expect 0 "an exception covers a short SHA" "on: push
jobs:
  build:
    steps:
      - uses: actions/checkout@1111111 # v1.2.3" "$exception_policy"

expect 0 "an exception covers an unrecorded action" "$good_workflow" "$exception_policy"

expect 1 "an expired exception is caught, not silently honoured" "$good_workflow" '{
  "schemaVersion": 1,
  "actions": [],
  "exceptions": [
    {
      "name": "actions/checkout",
      "reason": "test fixture",
      "owner": "Birdcage maintainers",
      "reviewBy": "'"$PAST"'"
    }
  ]
}' "reviewBy 2000-01-01 has passed"

# A dot-free sanity check: two different pins of the same action at the
# same commit (codeql-action's init and analyze) are each checked and
# recorded independently by full `name`, not merged.
expect 0 "two sub-actions of the same repo are checked independently" "on: push
jobs:
  build:
    steps:
      - uses: github/codeql-action/init@444444444444444444444444444444444444444d # v4.0.0
      - uses: github/codeql-action/analyze@444444444444444444444444444444444444444d # v4.0.0" '{
  "schemaVersion": 1,
  "actions": [
    {"name": "github/codeql-action/init", "commit": "444444444444444444444444444444444444444d", "version": "v4.0.0", "licence": "MIT", "source": "https://github.com/github/codeql-action", "updateOwner": "x", "reviewBy": "'"$FUTURE"'"},
    {"name": "github/codeql-action/analyze", "commit": "444444444444444444444444444444444444444d", "version": "v4.0.0", "licence": "MIT", "source": "https://github.com/github/codeql-action", "updateOwner": "x", "reviewBy": "'"$FUTURE"'"}
  ],
  "exceptions": []
}' "2 \`uses:\` pin(s)"

# A missing policy file, a missing workflow directory, and unparseable JSON
# all fail red (exit 2), never quietly green.
got=0
out="$(python3 "$guard" "$work/workflows" --policy "$work/does-not-exist.json" 2>&1)" || got=$?
if [ "$got" = 2 ]; then
  echo "ok   a missing policy file fails red, not green"; pass=$((pass + 1))
else
  echo "FAIL a missing policy file fails red, not green: exit $got"
  echo "$out" | sed 's/^/       /'
  fail=$((fail + 1))
fi

got=0
out="$(python3 "$guard" "$work/does-not-exist-dir" --policy "$work/policy.json" 2>&1)" || got=$?
if [ "$got" = 2 ]; then
  echo "ok   a missing workflow directory fails red, not green"; pass=$((pass + 1))
else
  echo "FAIL a missing workflow directory fails red, not green: exit $got"
  echo "$out" | sed 's/^/       /'
  fail=$((fail + 1))
fi

printf '%s\n' "not json at all" > "$work/bad-policy.json"
got=0
out="$(python3 "$guard" "$work/workflows" --policy "$work/bad-policy.json" 2>&1)" || got=$?
if [ "$got" = 2 ]; then
  echo "ok   unparseable policy JSON fails red, not green"; pass=$((pass + 1))
else
  echo "FAIL unparseable policy JSON fails red, not green: exit $got"
  echo "$out" | sed 's/^/       /'
  fail=$((fail + 1))
fi

# The real repository: the whole point of this check is to pass against
# what is actually pinned today, not only against hand-built fixtures.
got=0
out="$(cd "$repo_root" && python3 "$guard" 2>&1)" || got=$?
if [ "$got" = 0 ] && grep -qF "pin(s) across the workflow files" <<<"$out"; then
  echo "ok   the real .github/workflows pins pass against the real policy"; pass=$((pass + 1))
else
  echo "FAIL the real .github/workflows pins pass against the real policy: exit $got"
  echo "$out" | sed 's/^/       /'
  fail=$((fail + 1))
fi

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
