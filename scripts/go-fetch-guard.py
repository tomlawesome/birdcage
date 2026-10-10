#!/usr/bin/env python3
"""Refuse an image build that could look the owner's Go modules up on the
public proxy, or that installs git where it should not.

ADR-0016 decision 1: github.com/tomlawesome/gauntlet is fetched from its
Git host, never through proxy.golang.org or sum.golang.org, because the
first lookup there records a version for good -- which is publishing it.
CI jobs carry GOPRIVATE for that; this is the same rule for every
Dockerfile under build/, as a red job (owner answer 3a on #8,
2026-10-10).

What it refuses, and why each one matters:

  - a Go build stage (one that runs `go build`, `go mod download`, or any
    other go command that can fetch modules) where GOPRIVATE, set with
    ENV, does not cover github.com/tomlawesome/* by the time the first
    such command runs -- without it, a fetch of gauntlet goes to the
    public proxy and sum database;
  - GONOPROXY or GONOSUMDB set in any stage (ENV, ARG or RUN) -- either
    one replaces what GOPRIVATE says for that half of the lookup, so a
    stage could carry a correct GOPRIVATE and still ask the proxy;
  - git installed (apk, apt-get, apt, dnf, yum) in any Dockerfile but
    build/birdcage's, or in birdcage's final, shipped stage. The owner
    approved git in birdcage's Go build stage only, because only
    cmd/birdcage links gauntlet; everywhere else a fetch of an owner
    module should fail for want of git rather than find a way round.

A stage that starts `FROM <earlier stage>` inherits that stage's ENV,
as Docker does. Coverage follows Go's own GOPRIVATE matching: a
comma-separated list of path globs, each matched against as many leading
path elements of the module path as it has.

Usage: scripts/go-fetch-guard.py [build-dir]   (default: build)
Exit codes: 0 fine; 1 a rule above is broken; 2 the directory could not
be read or holds no Dockerfiles (fail red, never quietly green).
"""
import fnmatch
import os
import re
import shlex
import sys

# Both must be covered: the module that exists today, and any other the
# owner publishes later, which is what `github.com/tomlawesome/*` means.
PROBES = ("github.com/tomlawesome/gauntlet",
          "github.com/tomlawesome/any-later-module")
WANT = "github.com/tomlawesome/*"
GIT_ALLOWED = "birdcage"  # build/<this>/Dockerfile, build stages only

GO_FETCHING = re.compile(
    r"(?<![\w./-])go\s+(build|install|get|mod|run|test|list|generate|vet)\b")
INSTALLER = re.compile(
    r"\b(apk\s+add|apt-get\s+install|apt\s+install|dnf\s+install|"
    r"yum\s+install)\b")
GIT_PACKAGE = re.compile(r"^git([=~<>].*)?$")
OVERRIDES = ("GONOPROXY", "GONOSUMDB")


def logical_lines(text):
    """Dockerfile instructions, one per entry, continuations joined.

    Docker drops comment lines even inside a continued instruction, so
    they are dropped here too.
    """
    out, cur = [], ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#"):
            continue
        if not line and not cur:
            continue
        if line.endswith("\\"):
            cur += line[:-1] + " "
            continue
        cur += line
        if cur.strip():
            out.append(cur.strip())
        cur = ""
    if cur.strip():
        out.append(cur.strip())
    return out


def parse_env(rest):
    """ENV's two forms: `K=V [K2=V2 ...]` and the legacy `K V`."""
    try:
        words = shlex.split(rest)
    except ValueError:
        return {}
    if not words:
        return {}
    if "=" not in words[0]:
        return {words[0]: " ".join(words[1:])}
    env = {}
    for w in words:
        if "=" in w:
            k, v = w.split("=", 1)
            env[k] = v
    return env


def covers(goprivate):
    """True if this GOPRIVATE value matches every probe, as Go matches it."""
    def match(target):
        for pat in (goprivate or "").split(","):
            pat = pat.strip().strip("/")
            if not pat:
                continue
            n = pat.count("/") + 1
            elems = target.split("/")
            if len(elems) < n:
                continue
            if all(fnmatch.fnmatchcase(t, p)
                   for t, p in zip(elems[:n], pat.split("/"))):
                return True
        return False
    return all(match(p) for p in PROBES)


def installs_git(run):
    if not INSTALLER.search(run):
        return False
    try:
        words = shlex.split(run)
    except ValueError:
        words = run.split()
    return any(GIT_PACKAGE.match(w) for w in words)


def stages(lines):
    """Split instructions into stages: (from-args, alias, [(kw, rest)])."""
    out = []
    for line in lines:
        kw, _, rest = line.partition(" ")
        kw = kw.upper()
        if kw == "FROM":
            words = rest.split()
            words = [w for w in words if not w.startswith("--")]
            alias = None
            if len(words) >= 3 and words[1].lower() == "as":
                alias = words[2].lower()
            out.append((words[0] if words else "", alias, []))
        elif out:
            out[-1][2].append((kw, rest.strip()))
    return out


def check_dockerfile(path, name, problems):
    """Append this file's problems; return how many Go stages it has."""
    with open(path) as f:
        parsed = stages(logical_lines(f.read()))
    final_env = {}
    go_stages = 0
    for index, (base, alias, instrs) in enumerate(parsed):
        label = f"build/{name}/Dockerfile stage {index + 1}" + (
            f" ({alias})" if alias else "")
        env = dict(final_env.get(base.lower(), {}))
        is_go = False
        reported = False
        for kw, rest in instrs:
            if kw == "ENV":
                env.update(parse_env(rest))
            if kw in ("ENV", "ARG", "RUN"):
                for var in OVERRIDES:
                    if re.search(rf"\b{var}\b", rest):
                        problems.append(
                            f"{label}: sets {var}. It replaces what "
                            f"GOPRIVATE says for that half of the lookup, "
                            f"so {WANT} could still go to the public "
                            f"proxy or sum database.")
            if kw != "RUN":
                continue
            if GO_FETCHING.search(rest):
                is_go = True
                if not covers(env.get("GOPRIVATE")) and not reported:
                    reported = True
                    have = env.get("GOPRIVATE")
                    problems.append(
                        f"{label}: runs `{rest[:60]}` with GOPRIVATE "
                        f"{'unset' if have is None else repr(have)}. Set "
                        f"`ENV GOPRIVATE={WANT}` before the first go "
                        f"command, or gauntlet is looked up on "
                        f"proxy.golang.org and recorded there for good "
                        f"(ADR-0016 decision 1).")
            if installs_git(rest):
                if name != GIT_ALLOWED:
                    problems.append(
                        f"{label}: installs git. Only build/{GIT_ALLOWED}'s "
                        f"Go build stage may (owner, 2026-10-10, #8 answer "
                        f"3a); here a fetch of an owner module should fail "
                        f"rather than find a way round.")
                elif index == len(parsed) - 1:
                    problems.append(
                        f"{label}: installs git in the final, shipped "
                        f"stage. git is approved for the Go build stage "
                        f"only and must never reach a user's image.")
        if is_go:
            go_stages += 1
        if alias:
            final_env[alias] = env
    return go_stages


def check(build_dir):
    try:
        names = sorted(os.listdir(build_dir))
    except OSError as err:
        print(f"go-fetch-guard: cannot read {build_dir}: {err}",
              file=sys.stderr)
        return 2
    files = [(n, os.path.join(build_dir, n, "Dockerfile")) for n in names
             if os.path.isfile(os.path.join(build_dir, n, "Dockerfile"))]
    if not files:
        print(f"go-fetch-guard: no {build_dir}/*/Dockerfile found; "
              f"nothing to check is a failure, not a pass.",
              file=sys.stderr)
        return 2

    problems = []
    go_stages = 0
    for name, path in files:
        try:
            go_stages += check_dockerfile(path, name, problems)
        except OSError as err:
            print(f"go-fetch-guard: cannot read {path}: {err}",
                  file=sys.stderr)
            return 2

    if problems:
        print("go-fetch-guard: an image build could reach the public Go "
              "proxy, or carries git where it should not:\n",
              file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print("\nSee ADR-0016 decision 1 and #8. If this genuinely has to "
              "change, change this guard deliberately and say why.",
              file=sys.stderr)
        return 1

    print(f"go-fetch-guard: {go_stages} Go build stage(s) across "
          f"{len(files)} Dockerfile(s) keep {WANT} off the public proxy; "
          f"git is installed only in build/{GIT_ALLOWED}'s build stage.")
    return 0


if __name__ == "__main__":
    raise SystemExit(check(sys.argv[1] if len(sys.argv) > 1 else "build"))
