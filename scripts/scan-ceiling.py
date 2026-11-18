#!/usr/bin/env python3
"""Finding-count ceilings for the code scanners (#199).

The ratchet idea of scripts/coverage-floor.py turned round: each scanner and
rule group has a ceiling in supply-chain/scan-ceilings.yml, the count of
findings that existed when the scanner was switched on. A ceiling only goes
down, and zero is the aim.

  scan-ceiling.py check   --key KEY (--count N | --report FILE --format FMT
                          [--severity a,b]) [--ceilings FILE]
  scan-ceiling.py count   --report FILE --format FMT [--severity a,b]
  scan-ceiling.py compare --ceilings FILE (--base FILE | --base-ref REF)

check fails (exit 1) when the count is above the ceiling (a new finding), when
it is more than RATCHET_SLACK below it (a stale ratchet: lower the ceiling to
lock the gain in), or when KEY is not in the file. compare fails (exit 1) when
any ceiling is higher than in the base. Exit 2: an input could not be read or
parsed. Report formats for --report: golangci-json, shellcheck-json1,
ruff-json, zizmor-json, actionlint-json.
"""
import argparse
import json
import os
import re
import subprocess
import sys

# Same slack as scripts/coverage-floor.py: loose on purpose, so fixing one or
# two findings does not turn the build red; only a real gain left unlocked does.
RATCHET_SLACK = 5
DEFAULT_CEILINGS = "supply-chain/scan-ceilings.yml"
LINE = re.compile(r"^\s+([A-Za-z0-9][A-Za-z0-9_.-]*):\s*(\S+)\s*(?:#.*)?$")


class InputError(Exception):
    pass


def parse_text(text, label):
    """Parse the flat `ceilings:` mapping of `key: integer  # comment`."""
    out = {}
    seen_header = False
    for n, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not seen_header:
            if raw.rstrip() == "ceilings:":
                seen_header = True
                continue
            raise InputError(f"{label}:{n}: expected 'ceilings:', got {raw!r}")
        m = LINE.match(raw)
        if not m:
            raise InputError(f"{label}:{n}: not a 'key: integer' line: {raw!r}")
        key, val = m.group(1), m.group(2)
        if not re.fullmatch(r"\d+", val):
            raise InputError(f"{label}:{n}: ceiling for {key} is not an integer: {val!r}")
        if key in out:
            raise InputError(f"{label}:{n}: duplicate key {key}")
        out[key] = int(val)
    if not seen_header:
        raise InputError(f"{label}: no 'ceilings:' mapping")
    return out


def parse_file(path):
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as e:
        raise InputError(f"cannot read {path}: {e.strerror}")
    return parse_text(text, path)


def read_ref(ref, path):
    rel = os.path.relpath(path) if os.path.isabs(path) else path
    try:
        # Fixed argv, no shell; git is found on PATH like everywhere in scripts/.
        res = subprocess.run(  # noqa: S603  # fixed argv, no shell, ref comes from CI or the caller
            ["git", "show", f"{ref}:{rel}"],  # noqa: S607  # git on PATH, as in every script here
            capture_output=True, text=True, check=False,
        )
    except OSError as e:
        raise InputError(f"cannot run git: {e.strerror}")
    if res.returncode != 0:
        raise InputError(f"cannot read {rel} at {ref}: {res.stderr.strip()}")
    return parse_text(res.stdout, f"{ref}:{rel}")


def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except OSError as e:
        raise InputError(f"cannot read report {path}: {e.strerror}")
    except ValueError as e:
        raise InputError(f"report {path} is not JSON: {e}")


def count_report(path, fmt, severities):
    """Findings in a tool's machine-readable report, optionally by severity."""
    data = load_json(path)
    want = {s.strip().lower() for s in severities.split(",") if s.strip()} if severities else None

    def keep(sev):
        return want is None or str(sev or "").lower() in want

    try:
        if fmt == "golangci-json":
            return sum(1 for i in (data.get("Issues") or []) if keep(i.get("Severity")))
        if fmt == "shellcheck-json1":
            return sum(1 for c in data["comments"] if keep(c.get("level")))
        if fmt == "ruff-json":
            return len(data)
        if fmt == "zizmor-json":
            return sum(1 for f in data if keep(f["determinations"]["severity"]))
        if fmt == "actionlint-json":
            return len(data or [])
    except (KeyError, TypeError, AttributeError) as e:
        raise InputError(f"report {path} does not look like {fmt}: {e!r}")
    raise InputError(f"unknown report format: {fmt}")


def cmd_check(a):
    if (a.count is None) == (a.report is None):
        raise InputError("give exactly one of --count and --report")
    if a.count is not None:
        if not re.fullmatch(r"\d+", a.count):
            raise InputError(f"--count is not an integer: {a.count!r}")
        count = int(a.count)
    else:
        if not a.format:
            raise InputError("--report needs --format")
        count = count_report(a.report, a.format, a.severity)
    ceilings = parse_file(a.ceilings)
    if a.key not in ceilings:
        print(f"scan-ceiling: FAIL {a.key}: no ceiling for this key in {a.ceilings}")
        return 1
    ceiling = ceilings[a.key]
    if count > ceiling:
        print(
            f"scan-ceiling: FAIL {a.key}: {count} findings, ceiling {ceiling}. "
            "A new finding: fix it, or suppress it with a reason. Never raise the ceiling."
        )
        return 1
    if count < ceiling - RATCHET_SLACK:
        print(
            f"scan-ceiling: FAIL {a.key}: {count} findings, ceiling {ceiling}, more than "
            f"{RATCHET_SLACK} below it. Stale ratchet: lower the ceiling in {a.ceilings} "
            f"to {count} to lock the gain in."
        )
        return 1
    print(f"scan-ceiling: ok {a.key}: {count} findings, ceiling {ceiling}")
    return 0


def cmd_count(a):
    print(count_report(a.report, a.format, a.severity))
    return 0


def cmd_compare(a):
    new = parse_file(a.ceilings)
    base = parse_file(a.base) if a.base else read_ref(a.base_ref, a.ceilings)
    bad = [(k, base[k], v) for k, v in sorted(new.items()) if k in base and v > base[k]]
    for k, old, v in bad:
        print(f"scan-ceiling: FAIL {k}: ceiling raised from {old} to {v}. A ceiling only goes down.")
    if bad:
        return 1
    print("scan-ceiling: ok no ceiling was raised")
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--key", required=True)
    c.add_argument("--count")
    c.add_argument("--report")
    c.add_argument("--format")
    c.add_argument("--severity")
    c.add_argument("--ceilings", default=DEFAULT_CEILINGS)
    c.set_defaults(fn=cmd_check)
    n = sub.add_parser("count")
    n.add_argument("--report", required=True)
    n.add_argument("--format", required=True)
    n.add_argument("--severity")
    n.set_defaults(fn=cmd_count)
    p = sub.add_parser("compare")
    p.add_argument("--ceilings", required=True)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--base")
    g.add_argument("--base-ref")
    p.set_defaults(fn=cmd_compare)
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    try:
        return args.fn(args)
    except InputError as e:
        print(f"scan-ceiling: error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
