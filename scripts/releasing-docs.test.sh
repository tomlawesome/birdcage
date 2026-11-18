#!/usr/bin/env bash
# Pins what docs/releasing.md must say about the countersign controls
# (#169 review, note 63795). Prose cannot be proven true, so this only pins
# that each statement exists, in one paragraph, in plain words; each rule is
# also shown firing on a scratch copy with the statement removed.
#   1. Deployments write is named as forbidden, with Actions write, for any
#      credential on the runner host (a token with it can approve the
#      waiting run through the API, so no human is involved).
#   2. The docs say plainly that check-no-actions-write.sh does NOT test
#      Deployments write (decided: it is documented, not probed -- probing
#      would mean creating or approving a deployment, a side effect).
#   3. The one-person gap: the owner both starts and approves, which is not
#      the SLSA two-person rule.
#   4. A failed sync:mirror-to-github job is expected when a workflow file
#      changes, and the by-hand push steps (a `git push`) follow.
#   5. No owner-account token may hold contents or workflows write.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

# check <file>: one line per missing statement.
check() {
  python3 -I - "$1" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
paras = [re.sub(r"\s+", " ", p).lower() for p in re.split(r"\n\s*\n", text)]
raw = [p.lower() for p in re.split(r"\n\s*\n", text)]
forbid = r"\b(never|must not|forbidden|may not|no credential|must never)\b"
bad = []
if not any("deployments write" in p and "actions write" in p and re.search(forbid, p) for p in paras):
    bad.append("deployments-forbidden")
if not any("deployments" in p and re.search(r"(does not|doesn't|do not|not) (test|check|probe)|cannot test|is not tested|not covered", p) and "check-no-actions-write" in p for p in paras):
    bad.append("deployments-not-checked")
if not any("approv" in p and re.search(r"same person|one person|single person|one human|one account", p) and re.search(r"two-person|two person|second approver", p) for p in paras):
    bad.append("one-person-gap")
idx = [i for i, p in enumerate(paras) if "sync:mirror-to-github" in p and "expected" in p and re.search(r"fail", p) and re.search(r"workflow", p)]
if not idx:
    bad += ["sync-failure-expected", "by-hand-push-steps"]
elif not any("git push" in " ".join(raw[i:i + 3]) for i in idx):
    bad.append("by-hand-push-steps")
if not any("contents" in p and "workflows" in p and "write" in p and re.search(r"owner", p) and re.search(forbid, p) for p in paras):
    bad.append("owner-token-no-contents-workflows")
print("\n".join(bad))
PY
}

# expect <name> <file> <none | the missing item that must be reported>
expect() {
  local got; got="$(check "$2")"
  if { [ "$3" = none ] && [ -z "$got" ]; } || { [ "$3" != none ] && grep -qx "$3" <<<"$got"; }; then
    echo "ok   $1"; pass=$((pass + 1))
  else
    echo "FAIL $1: got '${got//$'\n'/ }', want $3"; fail=$((fail + 1))
  fi
}

doc="$repo/docs/releasing.md"
got="$(check "$doc")"
for item in deployments-forbidden deployments-not-checked one-person-gap sync-failure-expected by-hand-push-steps owner-token-no-contents-workflows; do
  if grep -qx "$item" <<<"$got"; then echo "FAIL docs/releasing.md lacks: $item"; fail=$((fail + 1)); else echo "ok   docs/releasing.md has: $item"; pass=$((pass + 1)); fi
done

# The checker must fire: an empty doc lacks every statement, and a doc that
# is good except for one removed statement lacks exactly that one.
: > "$work/empty.md"
got="$(check "$work/empty.md")"
n="$(grep -c . <<<"$got" || true)"
[ "$n" = 6 ] && { echo "ok   an empty document lacks all six statements"; pass=$((pass + 1)); } || { echo "FAIL empty document lacks $n of 6"; fail=$((fail + 1)); }

cat > "$work/good.md" <<'DOC'
Never give any credential on the runner host Actions write or Deployments write: a token with Deployments write can approve the waiting run through the API.

scripts/check-no-actions-write.sh does not test Deployments write; that stays a rule, not a probe.

The owner both starts and approves the run: that is one person, not the SLSA two-person rule, and approval is no second approver.

A failed sync:mirror-to-github job is expected when a workflow file changes, because the ruleset refuses the push. Push it by hand:

    git push github-mirror dev

No token on the owner's account may hold contents or workflows write; it must never be given either.
DOC
expect "a minimal good document satisfies all six" "$work/good.md" none
for pair in "deployments-forbidden:Never give any" "deployments-not-checked:does not test Deployments" "one-person-gap:one person" "sync-failure-expected:is expected when" "by-hand-push-steps:git push" "owner-token-no-contents-workflows:contents or workflows write"; do
  item="${pair%%:*}"; needle="${pair#*:}"
  grep -v -F "$needle" "$work/good.md" > "$work/m.md" || true
  # one removed line can take another statement with it only if they share a line, which they do not
  expect "removing the statement for $item is caught" "$work/m.md" "$item"
done

echo "releasing-docs: $pass passed, $fail failed"
[ "$fail" = 0 ]
