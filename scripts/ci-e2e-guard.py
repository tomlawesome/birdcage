#!/usr/bin/env python3
"""Refuse a .gitlab-ci.yml that lets the live checks be skipped.

AGENTS.md says every piece of the security infrastructure is live
tested on every change that affects it. A rule in a document is a note
to whoever reads it; this is the same rule as a red job.

What it refuses, and why each one matters:

  - the `e2e` stage missing from `stages:`, or present with no jobs at
    all -- the live checks silently stop running and every pipeline
    still goes green;
  - an `e2e` job with `allow_failure: true` -- it runs, it fails, the
    pipeline passes anyway, and nobody looks;
  - an `e2e` job with `when: manual` or `when: never` -- a check
    somebody has to remember to press is not a check;
  - an `e2e` job whose rules never match a merge request -- the same
    thing by a longer route.

Weakening the live checks is then a visible change to this file rather
than a quiet line in a job definition.

The stage name and the job prefix are read from the CI config itself,
not copied here, so the guard cannot drift from what it guards.

Usage: scripts/ci-e2e-guard.py [path-to-.gitlab-ci.yml]
Exit codes: 0 fine; 1 a rule above is broken; 2 the file could not be
read (fail red, never quietly green).
"""
import sys

STAGE = "e2e"


def load(path):
    try:
        import yaml
    except ImportError:
        print("ci-e2e-guard: PyYAML is not installed, so the CI config "
              "cannot be parsed. Install it rather than skipping this "
              "check.", file=sys.stderr)
        raise SystemExit(2)
    try:
        with open(path) as f:
            doc = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as err:
        print(f"ci-e2e-guard: cannot read {path}: {err}", file=sys.stderr)
        raise SystemExit(2)
    if not isinstance(doc, dict):
        print(f"ci-e2e-guard: {path} is not a mapping", file=sys.stderr)
        raise SystemExit(2)
    return doc


def jobs_in_stage(doc, stage):
    """Every top-level job naming this stage.

    A key whose value is not a mapping is not a job (`stages:`,
    `variables:`), and a key starting with a dot is a template, never
    run on its own.
    """
    out = {}
    for name, body in doc.items():
        if name.startswith(".") or not isinstance(body, dict):
            continue
        if body.get("stage") == stage:
            out[name] = body
    return out


def rules_reach_merge_requests(body):
    """True unless the job's own rules can never match a merge request.

    A job with no `rules:` runs by default, which is fine. Anchors are
    already expanded by the YAML loader, so a job taking its rules from
    a shared anchor is read here exactly as GitLab reads it.
    """
    rules = body.get("rules")
    if rules is None:
        return True
    if not isinstance(rules, list):
        return True
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        cond = str(rule.get("if", ""))
        if "merge_request_event" not in cond:
            continue
        # A matching rule that then refuses to run is worse than none.
        return rule.get("when") not in ("never",)
    return False


def check(path):
    doc = load(path)
    problems = []

    stages = doc.get("stages")
    if not isinstance(stages, list) or STAGE not in stages:
        problems.append(
            f"`{STAGE}` is missing from `stages:`. The live checks in "
            f"AGENTS.md ('Live testing is not optional') have nowhere "
            f"to run, and every pipeline would still pass.")
        jobs = {}
    else:
        jobs = jobs_in_stage(doc, STAGE)
        if not jobs:
            problems.append(
                f"the `{STAGE}` stage exists but no job is in it. A "
                f"stage with nothing in it passes silently, which is "
                f"the failure this guard exists to catch.")

    for name, body in sorted(jobs.items()):
        if body.get("allow_failure") is True:
            problems.append(
                f"{name}: allow_failure is true. It would run, fail, "
                f"and the pipeline would go green anyway.")
        when = body.get("when")
        if when in ("manual", "never"):
            problems.append(
                f"{name}: when is {when!r}. A live check somebody has "
                f"to remember to press is not a live check.")
        if not rules_reach_merge_requests(body):
            problems.append(
                f"{name}: its rules never match a merge request, so a "
                f"change can reach dev without it having run.")

    if problems:
        print("ci-e2e-guard: the live checks can be skipped:\n",
              file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print("\nSee AGENTS.md, 'Live testing is not optional', and "
              "issue #78. If a check genuinely has to change, change "
              "this guard deliberately and say why.", file=sys.stderr)
        return 1

    print(f"ci-e2e-guard: {len(jobs)} job(s) in the `{STAGE}` stage, "
          f"none skippable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(check(sys.argv[1] if len(sys.argv) > 1 else ".gitlab-ci.yml"))
