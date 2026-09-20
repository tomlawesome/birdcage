#!/usr/bin/env python3
"""Refuse a .gitlab-ci.yml that lets one job both judge a release and ship it.

The house rule for releases (issue #90) is that no job both judges an
artefact and ships it, and that exactly one job may hold the signing key.
Those properties currently live only in prose. This guard turns them into a
red pipeline instead, the way `ci-e2e-guard.py` already does for the
live-testing rule.

What it refuses, and why each one matters:

  - the `release` stage missing from `stages:`, or present with no jobs at
    all -- a release with nothing in it passes silently;
  - none, or more than one, job calling `scripts/attest-tested-image.sh` --
    exactly one job may hold the signing key, so either extreme is wrong;
  - that signing job missing the `birdcage-signing` tag -- the key is
    fenced by the runner, not by this file, so a signing job without the
    tag would run on an ordinary runner and either fail confusingly or
    succeed somewhere it should not;
  - that signing job also calling a publish/promote script or a raw
    `docker push` / `docker buildx imagetools create` -- it signs, it does
    not ship;
  - any job calling both the signer and the evidence verifier -- minting
    evidence and judging it are different jobs by design;
  - a publish/promote job that also calls the signer -- the converse of the
    point above, named so the message points at the shipping job;
  - a `release`-stage job that is not `interruptible: false` -- a
    cancelled release can leave a pushed digest with no evidence, or a
    validated digest with no name;
  - a `release`-stage job with `allow_failure: true` -- a release step
    allowed to fail is not a gate.

The stage name and the job set are read from the CI config itself, not
copied here, so the guard cannot drift from what it guards.

Usage: scripts/ci-release-guard.py [path-to-.gitlab-ci.yml]
Exit codes: 0 fine; 1 a rule above is broken; 2 the file could not be
read (fail red, never quietly green).
"""
import sys

STAGE = "release"

SIGN = "scripts/attest-tested-image.sh"
VERIFY = "scripts/verify-validation-evidence.sh"
PUBLISH_CHANNEL = "scripts/publish-channel.sh"
PROMOTE_RELEASE = "scripts/promote-release.sh"
PUBLISH_IMAGE = "scripts/publish-image.sh"
DOCKER_PUSH = "docker push"
DOCKER_IMAGETOOLS = "docker buildx imagetools create"
SIGNING_TAG = "birdcage-signing"


def load(path):
    try:
        import yaml
    except ImportError:
        print("ci-release-guard: PyYAML is not installed, so the CI config "
              "cannot be parsed. Install it rather than skipping this "
              "check.", file=sys.stderr)
        raise SystemExit(2)
    try:
        with open(path) as f:
            doc = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as err:
        print(f"ci-release-guard: cannot read {path}: {err}", file=sys.stderr)
        raise SystemExit(2)
    if not isinstance(doc, dict):
        print(f"ci-release-guard: {path} is not a mapping", file=sys.stderr)
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


def all_jobs(doc):
    """Every top-level job, in any stage, for the checks that are not
    stage-specific (the signing rules apply wherever the signer lives).

    Dot-prefixed keys are templates, never run on their own. Keys such as
    `workflow:`, `default:` or `variables:` are configuration, not jobs, so
    a mapping only counts as a job here if it carries a `script:` or a
    `stage:` -- every real job has at least one of those.
    """
    out = {}
    for name, body in doc.items():
        if name.startswith(".") or not isinstance(body, dict):
            continue
        if "script" in body or "stage" in body:
            out[name] = body
    return out


def script_lines(body):
    """Every line of a job's script/before_script/after_script.

    Each key may be a single multi-line string or a list of lines; either
    way this flattens them so a substring search sees all of them.
    """
    lines = []
    for key in ("script", "before_script", "after_script"):
        val = body.get(key)
        if isinstance(val, str):
            lines.extend(val.splitlines())
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    lines.extend(item.splitlines())
    return lines


def calls(body, substring):
    """True if a job's script/before_script/after_script mentions this
    path or command anywhere -- that is what "a job calls a script" means
    throughout this file."""
    return any(substring in line for line in script_lines(body))


def check(path):
    doc = load(path)
    problems = []

    stages = doc.get("stages")
    if not isinstance(stages, list) or STAGE not in stages:
        problems.append(
            f"`{STAGE}` is missing from `stages:`. A release stage that "
            f"does not exist cannot gate anything, and every pipeline "
            f"would still pass.")
        release_jobs = {}
    else:
        release_jobs = jobs_in_stage(doc, STAGE)
        if not release_jobs:
            problems.append(
                f"the `{STAGE}` stage exists but no job is in it. A "
                f"stage with nothing in it passes silently, which is "
                f"the failure this guard exists to catch.")

    jobs = all_jobs(doc)

    signers = [name for name, body in sorted(jobs.items())
               if calls(body, SIGN)]

    if not signers:
        problems.append(
            f"no job calls {SIGN}. Nothing signs the tested image, so a "
            f"release would ship with no evidence attached.")
    elif len(signers) > 1:
        problems.append(
            f"more than one job calls {SIGN}: {', '.join(signers)}. "
            f"Exactly one job may hold the signing key.")
    else:
        signer = signers[0]
        body = jobs[signer]
        tags = body.get("tags")
        if not isinstance(tags, list) or SIGNING_TAG not in tags:
            problems.append(
                f"{signer}: calls {SIGN} but its `tags:` do not include "
                f"`{SIGNING_TAG}`. The key is fenced by the runner, not by "
                f"this file, so without the tag it would run on an "
                f"ordinary runner and fail confusingly -- or worse, "
                f"succeed somewhere it should not.")
        for ship_script in (PUBLISH_CHANNEL, PROMOTE_RELEASE, PUBLISH_IMAGE):
            if calls(body, ship_script):
                problems.append(
                    f"{signer}: signs the image with {SIGN} but also "
                    f"calls {ship_script}. It signs; it does not ship.")
        if calls(body, DOCKER_PUSH):
            problems.append(
                f"{signer}: signs the image with {SIGN} but also runs "
                f"`{DOCKER_PUSH}`. It signs; it does not ship.")
        if calls(body, DOCKER_IMAGETOOLS):
            problems.append(
                f"{signer}: signs the image with {SIGN} but also runs "
                f"`{DOCKER_IMAGETOOLS}`. It signs; it does not ship.")

    for name, body in sorted(jobs.items()):
        if calls(body, SIGN) and calls(body, VERIFY):
            problems.append(
                f"{name}: calls both {SIGN} and {VERIFY}. Minting "
                f"evidence and judging it are different jobs by design.")

    for name, body in sorted(jobs.items()):
        if calls(body, PUBLISH_CHANNEL) or calls(body, PROMOTE_RELEASE):
            if calls(body, SIGN):
                problems.append(
                    f"{name}: ships the release but also calls {SIGN}. "
                    f"It ships; it must not also hold the signing key.")

    for name, body in sorted(release_jobs.items()):
        if body.get("interruptible") is not False:
            problems.append(
                f"{name}: is not `interruptible: false`. A cancelled "
                f"release can leave a pushed digest with no evidence, or "
                f"a validated digest with no name.")
        if body.get("allow_failure") is True:
            problems.append(
                f"{name}: allow_failure is true. A release step allowed "
                f"to fail is not a gate.")

    if problems:
        print("ci-release-guard: the release stage does not hold the "
              "line:\n", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print("\nSee issue #90. If a release job genuinely has to change "
              "shape, change this guard deliberately and say why.",
              file=sys.stderr)
        return 1

    signer = signers[0]
    print(f"ci-release-guard: {len(release_jobs)} job(s) in the `{STAGE}` "
          f"stage, signed exactly once by {signer} (tagged "
          f"{SIGNING_TAG}), no job both judges and ships.")
    return 0


if __name__ == "__main__":
    raise SystemExit(check(sys.argv[1] if len(sys.argv) > 1 else ".gitlab-ci.yml"))
