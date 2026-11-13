#!/usr/bin/env python3
"""Refuse an image build that could look the owner's Go modules up on the
public proxy, or that installs git where it should not.

ADR-0016 decision 1: github.com/tomlawesome/* is fetched from its Git
host, never through proxy.golang.org or sum.golang.org, because the
first lookup there records a version for good -- which is publishing it.
CI jobs carry GOPRIVATE for that; this is the same rule for every
Dockerfile in the repository, as a red job (owner answer 3a on #8,
2026-10-10; spec in #8 note 58219).

Which files: every tracked file named `Dockerfile`, `Dockerfile.*` or
`*.Dockerfile`, at any depth.

What it refuses, and why each one matters:

  - a stage that runs the go command -- `go` or any path ending in
    `/go`, in shell form, exec form (`RUN ["go", ...]`), a heredoc body
    (`RUN <<EOF`), after `&&`/`;`/`|`, behind `VAR=x`, `env` or
    `sh -c` -- where GOPRIVATE, set with ENV in that stage or inherited
    from the stage it is built FROM, does not cover
    github.com/tomlawesome/* by the first such RUN. Without it a fetch
    of an owner module goes to the public proxy and sum database;
  - GOPRIVATE, GONOPROXY, GONOSUMDB, GOPROXY, GOSUMDB or GOFLAGS set any
    other way: named anywhere in a RUN (inline `X= go build`, `export`,
    `go env -w`, `unset`), declared as an ARG, or GONOPROXY / GONOSUMDB /
    GOPROXY / GOSUMDB / GOFLAGS set by ENV. Each one can replace or undo
    what GOPRIVATE says. The one allowed form is `ENV GOPRIVATE=...`;
  - git installed (apk add, apt-get/apt install, dnf/yum/microdnf
    install; flags anywhere; `git=<version>` counts, git-lfs and
    gitleaks do not) anywhere except build/birdcage/Dockerfile, and
    there only in a stage that is not the final stage and that no later
    stage is built FROM, directly or through another stage. `COPY
    --from=` that stage is fine: it copies files, not git. The owner
    approved git in birdcage's Go build stage only, because only
    cmd/birdcage links gauntlet; everywhere else a fetch of an owner
    module should fail for want of git rather than find a way round.

Coverage follows Go's own GOPRIVATE matching: a comma-separated list of
path globs, each matched against as many leading path elements of the
module path as it has.

Usage: scripts/go-fetch-guard.py [dir]
  no argument  scan the tracked files of the git repository holding the
               current directory; paths are reported from its root
               (this is what CI runs).
  dir          scan every Dockerfile-named file under dir, tracked or
               not, treating dir's parent as the repository root -- so
               `build` from the root reports `build/birdcage/Dockerfile`.
Exit codes: 0 fine; 1 a rule above is broken; 2 nothing could be read or
there are no Dockerfiles (fail red, never quietly green).
"""
import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys

# Both must be covered: the module that exists today, and any other the
# owner publishes later, which is what `github.com/tomlawesome/*` means.
PROBES = ("github.com/tomlawesome/gauntlet",
          "github.com/tomlawesome/any-later-module")
WANT = "github.com/tomlawesome/*"
GIT_ALLOWED = "build/birdcage/Dockerfile"  # its non-final build stage only

GO_VARS = ("GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GOPROXY", "GOSUMDB",
           "GOFLAGS")
GO_VAR_WORD = re.compile(r"\b(" + "|".join(GO_VARS) + r")\b")
# Package managers and the subcommand that installs with each.
INSTALLERS = {"apk": "add", "apt-get": "install", "apt": "install",
              "dnf": "install", "yum": "install", "microdnf": "install"}
GIT_PACKAGE = re.compile(r"^git([=~<>:].*)?$")
SHELLS = {"sh", "bash", "ash", "dash", "zsh"}
# Words that may stand before the real command in a simple command.
PREFIXES = {"env", "exec", "command", "time", "nice", "nohup", "sudo",
            "if", "then", "else", "elif", "do", "while", "until", "!",
            "{"}
SEPARATORS = {"&&", "||", ";", ";;", "|", "|&", "&", "(", ")"}
HEREDOC = re.compile(r"(?<!<)<<(?!<)(-?)([\"']?)([A-Za-z_][\w.-]*)\2")
ASSIGNMENT = re.compile(r"^[A-Za-z_]\w*=")


def is_dockerfile(path):
    base = os.path.basename(path)
    return (base == "Dockerfile" or base.startswith("Dockerfile.")
            or base.endswith(".Dockerfile"))


def logical_lines(text):
    """Dockerfile instructions, one per entry, continuations joined and
    heredoc bodies (`RUN <<EOF ... EOF`) appended after a newline.

    Docker drops comment lines even inside a continued instruction, so
    they are dropped here too -- but not inside a heredoc body.
    """
    out, cur = [], ""
    raw = text.splitlines()
    i = 0
    while i < len(raw):
        line = raw[i].strip()
        i += 1
        if line.startswith("#"):
            continue
        if not line and not cur:
            continue
        if line.endswith("\\"):
            cur += line[:-1] + " "
            continue
        cur = (cur + line).strip()
        if not cur:
            continue
        kw = cur.split(None, 1)[0].upper()
        if kw in ("RUN", "COPY", "ADD"):
            for strip_tabs, _, word in HEREDOC.findall(cur):
                body = []
                while i < len(raw):
                    b = raw[i]
                    i += 1
                    if (b.lstrip("\t") if strip_tabs else b) == word:
                        break
                    body.append(b)
                cur += "\n" + "\n".join(body)
        out.append(cur)
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


def tokens(script):
    """Shell words and separators. Newlines and backticks separate
    commands; unbalanced quotes (heredoc prose) fall back to a plain
    split rather than failing."""
    script = HEREDOC.sub(" ", script).replace("`", " ; ").replace(
        "\n", " ; ")
    try:
        lex = shlex.shlex(script, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        return list(lex)
    except ValueError:
        return re.sub(r"(&&|\|\||[;&|()])", r" \1 ", script).split()


def simple_commands(script):
    """Each simple command's argv: leading `VAR=x` and wrapper words such
    as `env`, `exec` or `then` dropped, `sh -c '...'` opened up."""
    cur = []
    for tok in tokens(script) + [";"]:
        if tok not in SEPARATORS:
            cur.append(tok)
            continue
        yield from argv_commands(cur)
        cur = []


def argv_commands(argv):
    words = list(argv)
    while words and (ASSIGNMENT.match(words[0]) or words[0] in PREFIXES
                     or (words[0].startswith("-") and len(words) > 1)):
        words.pop(0)
    if not words:
        return
    if os.path.basename(words[0]) in SHELLS and "-c" in words[1:]:
        at = words.index("-c")
        if at + 1 < len(words):
            yield from simple_commands(words[at + 1])
            return
    yield words


def run_commands(rest):
    """Every simple command a RUN executes, shell or exec form."""
    rest = re.sub(r"^(--\S+\s+)*", "", rest)  # --mount=..., --network=...
    if rest.startswith("["):
        first, _, body = rest.partition("\n")
        try:
            argv = json.loads(first)
        except ValueError:
            argv = None
        if isinstance(argv, list) and all(isinstance(a, str) for a in argv):
            yield from argv_commands(argv)
            if body:
                yield from simple_commands(body)
            return
    yield from simple_commands(rest)


def runs_go(rest):
    return any(os.path.basename(c[0]) == "go" for c in run_commands(rest))


def installs_git(rest):
    for cmd in run_commands(rest):
        sub = INSTALLERS.get(os.path.basename(cmd[0]))
        if sub and sub in cmd[1:]:
            after = cmd[cmd.index(sub) + 1:]
            if any(GIT_PACKAGE.match(w) for w in after
                   if not w.startswith("-")):
                return True
    return False


def stages(lines):
    """Split instructions into stages: (from-image, alias, [(kw, rest)]).
    Instructions before the first FROM (global ARGs) form stage None."""
    pre, out = [], []
    for line in lines:
        kw, _, rest = line.partition(" ")
        kw = kw.upper()
        if kw == "FROM":
            words = [w for w in rest.split() if not w.startswith("--")]
            alias = None
            if len(words) >= 3 and words[1].lower() == "as":
                alias = words[2].lower()
            out.append(((words[0] if words else "").lower(), alias, []))
        else:
            (out[-1][2] if out else pre).append((kw, rest.strip()))
    return pre, out


def var_problems(label, kw, rest, problems):
    if kw == "RUN" or kw == "ARG":
        names = sorted(set(GO_VAR_WORD.findall(rest)))
        where = "a RUN" if kw == "RUN" else "an ARG"
    elif kw == "ENV":
        names = [k for k in parse_env(rest)
                 if k in GO_VARS and k != "GOPRIVATE"]
        where = "an ENV"
    else:
        return
    for var in names:
        problems.append(
            f"{label}: sets {var} in {where}. The only allowed way to "
            f"touch the Go fetch variables is `ENV GOPRIVATE={WANT}`; "
            f"anything else can send {WANT} to the public proxy or sum "
            f"database.")


def check_dockerfile(text, path, problems):
    """Append this file's problems; return how many Go stages it has."""
    pre, parsed = stages(logical_lines(text))
    for kw, rest in pre:
        var_problems(f"{path} (before the first FROM)", kw, rest, problems)

    by_alias, parent, end_env = {}, [], []
    for index, (base, alias, _) in enumerate(parsed):
        parent.append(by_alias.get(base))
        if alias:
            by_alias[alias] = index

    def label(index):
        alias = parsed[index][1]
        return f"{path} stage {index + 1}" + (f" ({alias})" if alias else "")

    go_stages = 0
    git_stages = []
    for index, (_, _, instrs) in enumerate(parsed):
        here = label(index)
        p = parent[index]
        env = dict(end_env[p]) if p is not None else {}
        is_go = reported = git = False
        for kw, rest in instrs:
            if kw == "ENV":
                env.update(parse_env(rest))
            var_problems(here, kw, rest, problems)
            if kw != "RUN":
                continue
            if runs_go(rest):
                is_go = True
                if not covers(env.get("GOPRIVATE")) and not reported:
                    reported = True
                    have = env.get("GOPRIVATE")
                    shown = rest.split("\n", 1)[0][:60]
                    problems.append(
                        f"{here}: runs `{shown}` with GOPRIVATE "
                        f"{'unset' if have is None else repr(have)}. Set "
                        f"`ENV GOPRIVATE={WANT}` before the first go "
                        f"command, in this stage or the one it is built "
                        f"FROM, or an owner module is looked up on "
                        f"proxy.golang.org and recorded there for good "
                        f"(ADR-0016 decision 1).")
            if not git and installs_git(rest):
                git = True
                git_stages.append(index)
        go_stages += is_go
        end_env.append(env)

    for index in git_stages:
        here = label(index)
        if path != GIT_ALLOWED:
            problems.append(
                f"{here}: installs git. Only {GIT_ALLOWED}'s Go build "
                f"stage may (owner, 2026-10-10, #8 answer 3a); here a "
                f"fetch of an owner module should fail rather than find "
                f"a way round.")
            continue
        if index == len(parsed) - 1:
            problems.append(
                f"{here}: installs git in the final, shipped stage. git "
                f"is approved for the Go build stage only and must never "
                f"reach a user's image.")
        for later in range(index + 1, len(parsed)):
            p = parent[later]
            while p is not None and p != index:
                p = parent[p]
            if p == index:
                problems.append(
                    f"{here}: installs git, and {label(later)} is built "
                    f"FROM it, so git is carried into that image. Copy "
                    f"what it built with `COPY --from=` instead.")
    return go_stages


def tracked_dockerfiles():
    """(root, [repo-relative path]) for the repository at the cwd."""
    top = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True)
    if top.returncode != 0:
        raise OSError(top.stderr.strip() or "not a git repository")
    root = top.stdout.strip()
    ls = subprocess.run(["git", "-C", root, "ls-files", "-z"],
                        capture_output=True, text=True)
    if ls.returncode != 0:
        raise OSError(ls.stderr.strip() or "git ls-files failed")
    return root, sorted(p for p in ls.stdout.split("\0")
                        if p and is_dockerfile(p))


def dir_dockerfiles(directory):
    """(root, [root-relative path]) for every Dockerfile under directory,
    root being directory's parent."""
    directory = os.path.abspath(directory)
    if not os.path.isdir(directory):
        raise OSError(f"{directory} is not a readable directory")
    root = os.path.dirname(directory)
    found = []
    for dirpath, _, files in os.walk(directory):
        for f in files:
            if is_dockerfile(f):
                found.append(os.path.relpath(os.path.join(dirpath, f), root))
    return root, sorted(found)


def check(argv):
    where = argv[0] if argv else "the tracked files of this repository"
    try:
        root, files = dir_dockerfiles(argv[0]) if argv else \
            tracked_dockerfiles()
    except OSError as err:
        print(f"go-fetch-guard: cannot read {where}: {err}", file=sys.stderr)
        return 2
    if not files:
        print(f"go-fetch-guard: no Dockerfile found in {where}; nothing to "
              f"check is a failure, not a pass.", file=sys.stderr)
        return 2

    problems = []
    go_stages = 0
    for rel in files:
        try:
            with open(os.path.join(root, rel)) as f:
                text = f.read()
        except OSError as err:
            print(f"go-fetch-guard: cannot read {rel}: {err}",
                  file=sys.stderr)
            return 2
        go_stages += check_dockerfile(text, rel.replace(os.sep, "/"),
                                      problems)

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
          f"git is installed, if at all, only in a build stage of "
          f"{GIT_ALLOWED} that nothing is built FROM.")
    return 0


if __name__ == "__main__":
    raise SystemExit(check(sys.argv[1:]))
