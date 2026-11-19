#!/usr/bin/env python3
"""The fence on the one release MR per release (#215, owner answer 41b).

A `release/vX.Y.Z` branch carries the release record and the change-log
rename straight into `dev`, without a batch. The central exceptions file
allows exactly that: one MR per release, into dev, changing only
`docs/releases/` (this release's record) and `CHANGELOG.md`. This script is
the `policy:release-record` job's rule, so the exception cannot quietly
carry anything else.

Refuses (exit 1) unless all of these hold:
  - the target branch is `dev`;
  - the source branch is exactly `release/v<VERSION>`, VERSION read from
    <remote>/<target> (a version bump goes through a batch, not here);
  - `docs/releases/v<VERSION>.md` does not already exist on <remote>/<target>
    (one release MR per release: a mistake after it merges goes to the owner);
  - every path the branch changes (`git diff --name-only --no-renames
    <remote>/<target>...HEAD`, so dev moving on does not count) is
    `CHANGELOG.md` or `docs/releases/v<VERSION>.md`.

A source branch outside `release/` is not this job's business: exit 0.

Usage (in the MR's checkout, HEAD = source tip; the CI job fetches the
target first):
  CI_MERGE_REQUEST_SOURCE_BRANCH_NAME=release/v0.2.0 \\
  CI_MERGE_REQUEST_TARGET_BRANCH_NAME=dev \\
    scripts/release-record-policy.py [--remote NAME]

Exit codes: 0 allowed; 1 refused; 2 usage or git error.
"""
import argparse
import os
import re
import subprocess
import sys

GIT_TIMEOUT = 30


def git(*args):
    out = subprocess.run(["git", *args], capture_output=True, text=True,
                         timeout=GIT_TIMEOUT)
    if out.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {out.stderr.strip()}")
    return out.stdout


def main(argv):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--remote", default="origin")
    args = parser.parse_args(argv[1:])

    source = os.environ.get("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", "")
    target = os.environ.get("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "")
    if not source or not target:
        print("release-record-policy: CI_MERGE_REQUEST_SOURCE_BRANCH_NAME and "
              "CI_MERGE_REQUEST_TARGET_BRANCH_NAME must be set", file=sys.stderr)
        return 2
    if not source.startswith("release/"):
        print(f"release-record-policy: {source} is not a release/* branch; nothing to check")
        return 0

    if target != "dev":
        print(f"release-record-policy: refused: a release/* branch merges into dev only, "
              f"not {target} (the exception covers dev; promote dev -> preview after it)")
        return 1

    problems = []

    try:
        base = f"{args.remote}/{target}"
        version = git("show", f"{base}:VERSION").strip()
        # No rename detection: a rename prints only its new name, which would
        # hide the deletion of the source path from the check below.
        changed = [p for p in git("diff", "--name-only", "--no-renames",
                                  f"{base}...HEAD").splitlines() if p]
        on_target = set(git("ls-tree", "-r", "--name-only", base, "--", "docs/releases").split())
    except (RuntimeError, subprocess.TimeoutExpired) as e:
        print(f"release-record-policy: {e}", file=sys.stderr)
        return 2

    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        problems.append(f"VERSION on {target} is not MAJOR.MINOR.PATCH ({version!r})")
    want = f"release/v{version}"
    if source != want:
        problems.append(f"the branch must be named {want} (VERSION on {target} is {version}); "
                        f"{source} is not. A version bump goes through a batch, not this MR")

    record = f"docs/releases/v{version}.md"
    if record in on_target:
        problems.append(f"{record} already exists on {target}: v{version} already has its one "
                        "release MR. A mistake in it is a question for the owner, not a second "
                        "release MR")

    allowed = {"CHANGELOG.md", f"docs/releases/v{version}.md"}
    others = [p for p in changed if p not in allowed]
    if others:
        problems.append("a release MR may change only CHANGELOG.md and "
                        f"docs/releases/v{version}.md; it also changes: " + ", ".join(others)
                        + ". Move those changes to a batch")

    if problems:
        for p in problems:
            print(f"release-record-policy: refused: {p}")
        return 1
    print(f"release-record-policy: {source} -> {target} changes only "
          f"{', '.join(sorted(changed)) or 'nothing'}: allowed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
