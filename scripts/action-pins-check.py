#!/usr/bin/env python3
"""Refuse a GitHub Actions `uses:` pin the policy does not vouch for.

Issue #27. A pin by commit SHA proves the reference cannot move; it says
nothing about whether anyone looked at what that commit contains, or when.
supply-chain/action-pins.json is the record of that review -- for every
`uses:` pin in .github/workflows/*.yml it names the action, the pinned
commit, the human version that commit corresponds to, its licence, who
owns keeping it current, and a review-by date. This script is the check
that the record is still true, the way ci-e2e-guard.py is the check that
the live-testing rule is still true.

What it refuses, and why each one matters:

  - a `uses:` pin not pinned to a full 40-hex commit -- a tag or branch can
    be repointed after review, which is exactly what pinning exists to
    rule out;
  - a pin whose (action, commit) the policy does not record -- an
    unreviewed pin is indistinguishable from one reviewed years ago unless
    every pin is in the record;
  - a pin recorded under a different commit than the policy has -- the
    workflow moved and the policy was not updated with it, so the record
    is now describing a commit nobody runs;
  - a pin whose inline `# vX.Y.Z` comment disagrees with the policy's
    `version` for that action -- the comment is what a human reads at the
    call site, so if it drifts from the record the record is no longer
    describing what is actually pinned;
  - a pin with no inline version comment at all -- nothing to check the
    record against;
  - a policy entry (or exception) whose `reviewBy` has passed -- a review
    date nobody enforces is decoration, not a review.

A pin may instead be covered by a named entry in `exceptions`, each with
its own reason, owner and reviewBy -- for a pin that genuinely cannot meet
one of the rules above. There are none as of this writing; every current
pin is a full-commit, recorded, comment-matching pin.

Scope: GitHub Actions `uses:` pins only (issue #27). Container images
pinned by digest were considered and left out -- .gitlab-ci.yml has
exactly one (E2E_POISONER_FIXTURE_DIGEST), and it is a private fixture
image with no public source to verify a licence against, already governed
by its own documented control (AGENTS.md, "Attack-tool fixtures"; the pin
itself is the version check). Folding it into this schema would misrepresent
a pin that is not an action and has no licence to record.

Usage: scripts/action-pins-check.py [workflow-dir] [--policy path]
Exit codes: 0 fine; 1 a rule above is broken; 2 the policy or a workflow
file could not be read (fail red, never quietly green).
"""
import json
import re
import sys
from datetime import date, datetime
from pathlib import Path

DEFAULT_WORKFLOW_DIR = ".github/workflows"
DEFAULT_POLICY_PATH = "supply-chain/action-pins.json"

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
USES_LINE = re.compile(
    r"^\s*(?:-\s+)?uses:\s*([^\s@'\"]+)@([0-9A-Fa-f]+)\s*(?:#\s*(\S.*?)\s*)?$"
)


def load_policy(path):
    try:
        with open(path, encoding="utf-8") as f:
            policy = json.load(f)
    except (OSError, json.JSONDecodeError) as err:
        print(f"action-pins-check: cannot read {path}: {err}", file=sys.stderr)
        raise SystemExit(2)
    if not isinstance(policy, dict):
        print(f"action-pins-check: {path} is not a JSON object", file=sys.stderr)
        raise SystemExit(2)
    return policy


def find_pins(workflow_dir):
    """Every `uses:` line across every workflow file, in file order.

    Yields (file, line_no, name, ref, comment-or-None). Parsed with a
    regex rather than a YAML loader on purpose: a YAML parser discards
    comments, and the inline `# vX.Y.Z` comment beside the pin is exactly
    what this check needs to read.
    """
    root = Path(workflow_dir)
    if not root.is_dir():
        print(f"action-pins-check: {workflow_dir} is not a directory", file=sys.stderr)
        raise SystemExit(2)
    files = sorted(root.glob("*.yml")) + sorted(root.glob("*.yaml"))
    if not files:
        print(f"action-pins-check: no workflow files found under {workflow_dir}", file=sys.stderr)
        raise SystemExit(2)
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as err:
            print(f"action-pins-check: cannot read {path}: {err}", file=sys.stderr)
            raise SystemExit(2)
        for line_no, line in enumerate(text.splitlines(), start=1):
            match = USES_LINE.match(line)
            if not match:
                continue
            name, ref, comment = match.groups()
            yield (str(path), line_no, name, ref, comment)


def valid_date(value):
    if not isinstance(value, str) or not DATE_PATTERN.match(value):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def check_policy_shape(policy, today):
    """Validate the policy file's own records, independent of any workflow.

    Returns (actions-by-name, exceptions-by-name, problems).
    """
    problems = []
    if policy.get("schemaVersion") != 1:
        problems.append("supply-chain/action-pins.json: schemaVersion must be 1.")

    actions = policy.get("actions")
    if not isinstance(actions, list):
        problems.append("supply-chain/action-pins.json: `actions` must be a list.")
        actions = []

    by_name = {}
    for index, entry in enumerate(actions):
        label = f"actions[{index}]"
        if not isinstance(entry, dict):
            problems.append(f"{label}: must be an object.")
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            problems.append(f"{label}: `name` is required.")
            continue
        if name in by_name:
            problems.append(f"{label}: `{name}` is recorded more than once.")
        by_name[name] = entry
        for field in ("version", "licence", "source", "updateOwner"):
            value = entry.get(field)
            if not isinstance(value, str) or not value.strip():
                problems.append(f"{label} ({name}): `{field}` is required.")
        commit = entry.get("commit")
        if not isinstance(commit, str) or not FULL_SHA.match(commit):
            problems.append(f"{label} ({name}): `commit` must be a full 40-hex SHA.")
        source = entry.get("source")
        if isinstance(source, str) and not source.startswith("https://"):
            problems.append(f"{label} ({name}): `source` must use HTTPS.")
        review_by = valid_date(entry.get("reviewBy"))
        if review_by is None:
            problems.append(f"{label} ({name}): `reviewBy` must be an ISO date (YYYY-MM-DD).")
        elif review_by < today:
            problems.append(
                f"{label} ({name}): reviewBy {entry.get('reviewBy')} has passed. "
                f"Re-review the pin and move the date, or drop it if it no longer applies."
            )

    exceptions = policy.get("exceptions")
    if not isinstance(exceptions, list):
        problems.append("supply-chain/action-pins.json: `exceptions` must be a list.")
        exceptions = []

    exceptions_by_name = {}
    for index, entry in enumerate(exceptions):
        label = f"exceptions[{index}]"
        if not isinstance(entry, dict):
            problems.append(f"{label}: must be an object.")
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            problems.append(f"{label}: `name` is required.")
            continue
        exceptions_by_name[name] = entry
        for field in ("reason", "owner"):
            value = entry.get(field)
            if not isinstance(value, str) or not value.strip():
                problems.append(f"{label} ({name}): `{field}` is required.")
        review_by = valid_date(entry.get("reviewBy"))
        if review_by is None:
            problems.append(f"{label} ({name}): `reviewBy` must be an ISO date (YYYY-MM-DD).")
        elif review_by < today:
            problems.append(
                f"{label} ({name}): reviewBy {entry.get('reviewBy')} has passed. "
                f"A lapsed exception is a silent one -- renew it with a reason, or drop it."
            )

    return by_name, exceptions_by_name, problems


def check_pins(pins, actions_by_name, exceptions_by_name):
    problems = []
    for path, line_no, name, ref, comment in pins:
        where = f"{path}:{line_no} ({name})"
        exception = exceptions_by_name.get(name)

        if not FULL_SHA.match(ref):
            if exception is not None:
                continue
            problems.append(
                f"{where}: pinned to `{ref}`, not a full 40-hex commit SHA. "
                f"A tag or branch can move after review; record a deliberate "
                f"exception if this one genuinely cannot be pinned."
            )
            continue

        entry = actions_by_name.get(name)
        if entry is None:
            if exception is not None:
                continue
            problems.append(
                f"{where}: pinned to {ref} but supply-chain/action-pins.json "
                f"records no `{name}` entry. An unrecorded pin cannot be told "
                f"apart from one nobody has ever reviewed."
            )
            continue

        if entry.get("commit") != ref:
            problems.append(
                f"{where}: pinned to {ref}, but the policy records {name} at "
                f"{entry.get('commit')}. The workflow moved and the policy "
                f"was not updated with it."
            )
            continue

        if comment is None:
            problems.append(
                f"{where}: pinned to {ref} with no inline `# vX.Y.Z` version "
                f"comment, so there is nothing to check the recorded version "
                f"({entry.get('version')}) against."
            )
        elif comment != entry.get("version"):
            problems.append(
                f"{where}: inline comment says `{comment}`, but the policy "
                f"records {name}@{ref} as `{entry.get('version')}`. One of "
                f"the two is wrong."
            )
    return problems


def check(workflow_dir=DEFAULT_WORKFLOW_DIR, policy_path=DEFAULT_POLICY_PATH, today=None):
    today = today or date.today()
    policy = load_policy(policy_path)
    actions_by_name, exceptions_by_name, problems = check_policy_shape(policy, today)
    pins = list(find_pins(workflow_dir))
    problems += check_pins(pins, actions_by_name, exceptions_by_name)

    if problems:
        print("action-pins-check: a `uses:` pin is not backed by the policy:\n", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print(
            "\nSee issue #27 and supply-chain/action-pins.json. If a pin "
            "genuinely has to differ, update the policy deliberately and "
            "say why.",
            file=sys.stderr,
        )
        return 1

    print(
        f"action-pins-check: {len(pins)} `uses:` pin(s) across the workflow "
        f"files, all recorded, full-SHA, and matching their policy version "
        f"({len(actions_by_name)} action(s), {len(exceptions_by_name)} "
        f"exception(s))."
    )
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    workflow_dir = DEFAULT_WORKFLOW_DIR
    policy_path = DEFAULT_POLICY_PATH
    positional = []
    i = 0
    while i < len(args):
        if args[i] == "--policy" and i + 1 < len(args):
            policy_path = args[i + 1]
            i += 2
            continue
        positional.append(args[i])
        i += 1
    if positional:
        workflow_dir = positional[0]
    raise SystemExit(check(workflow_dir, policy_path))
