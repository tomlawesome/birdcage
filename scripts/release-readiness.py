#!/usr/bin/env python3
"""Release-readiness check: runs first on every promotion (#215).

Everything the repository and the registries can show before step 1 of
docs/releasing.md, checked in one go on a promotion merge request into
`preview` or `main` (the `release_readiness` CI job, which every other job
of that pipeline waits on) and locally before the merge request is opened.
A green run never replaces the owner's approval of a promotion.

Usage:
  scripts/release-readiness.py --target preview|main [--source REF]
      [--remote NAME] [--description-file PATH] [--cooldown-days N]

  --source            the commit being promoted (default HEAD)
  --remote            where preview, main and the tags are read (default
                      origin in CI, else the GitLab remote of this checkout)
  --description-file  the main-leg MR description, for M9 locally (CI reads
                      CI_MERGE_REQUEST_DESCRIPTION)
  --cooldown-days     a pin counts as behind once its oldest newer version
                      is N days old (default 14, owner answer 49b); a newer
                      image: version always counts (Docker Hub dates move)

It runs every check, never stopping at the first failure, and prints one
line per check -- `PASS|FAIL|UNCHECKED|INFO <id> <name>: <message>` --
then a `Failed:` list repeating each FAIL with what to do.

Checks, preview leg (dev or hotfix/<name> -> preview): P1 version valid,
P2 version new, P3 version not burnt, P4 change log, P5 review closed,
P6 contains preview, P7 hop allowed, S1 pins current, S2 apk pins
buildable, K1 signing key, R1 release record. Main leg (preview -> main):
M1 hop, M2 lands preview exactly, M3 version (P1-P3), M4 preview
published, M5 evidence fresh, M6 change log, M7 review closed, M8 release
record, M9 manual test recorded, S1 (INFO only on this leg, 49b), S2, K1.
The spec, with every message, is the #215 final specification.

Exit codes: 0 every check passed; 1 at least one FAIL; 3 no FAIL but
something UNCHECKED (a local run without a credential -- does not clear a
promotion); 2 usage or internal error. In CI (CI=true) anything that could
not be checked is a FAIL, so CI never exits 3.

Time limits: 10 s per network call and per git command, an overall
deadline of 8 minutes (inside the job's 10), staleness-check's own
--deadline 300. A lookup that runs out of time is UNCHECKED locally and
FAIL in CI, never a hang. Two child processes get longer, fixed limits
because each makes several network calls: installing cosign (120 s, once)
and verifying one image's evidence (30 s).

Secrets: BIRDCAGE_READ_TOKEN (CI; read_api, masked and protected) is sent
from inside Python as a request header and never printed, put in a URL or
on a command line; the job says only "review token: present" or "absent".
Locally issue state and the GitLab registry are read with `glab api` (the
developer's own login), so no token is needed.

Test seam: every lookup except git goes through one object. The test-only
flag --stub PATH replaces it with answers from a JSON file (shape in
scripts/release-readiness.test.sh). Git always runs for real.
"""
import argparse
import base64
import datetime
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGES = ["birdcage", "mockingbird", "opencanary", "nightjar", "smb-lure", "holder"]
GHCR_NAMESPACE = "ghcr.io/tomlawesome"   # the mirrors, as in .gitlab-ci.yml
CALL_TIMEOUT = 10
RUN_DEADLINE = 480
STALENESS_DEADLINE = 300
COSIGN_INSTALL_TIMEOUT = 120
EVIDENCE_TIMEOUT = 30
EVIDENCE_MAX_AGE_DAYS = 7
EVIDENCE_MIN_LEFT = datetime.timedelta(days=1)
GUIDE = "docs/releasing.md"
KEEP_A_CHANGELOG = {"Added", "Changed", "Deprecated", "Removed", "Fixed", "Security"}
MANIFEST_ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])


# The most any one HTTP answer may be (#215 review): issue and token answers
# are a few KiB. A bigger one is a failure and is not read past the limit.
MAX_BODY = 1024 * 1024
_CREDENTIAL_HEADERS = ("authorization", "private-token")


def read_capped(resp, limit=MAX_BODY):
    length = resp.headers.get("Content-Length")
    if length and length.isdigit() and int(length) > limit:
        raise LookupFailed(f"an answer of {length} bytes is over the {limit}-byte limit")
    body = resp.read(limit + 1)
    if len(body) > limit:
        raise LookupFailed(f"an answer is over the {limit}-byte limit")
    return body


class _SameHostCredentials(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but never carry a credential header to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and (urllib.parse.urlsplit(newurl).netloc.lower()
                                != urllib.parse.urlsplit(req.full_url).netloc.lower()):
            for bag in (new.headers, new.unredirected_hdrs):
                for name in list(bag):
                    if name.lower() in _CREDENTIAL_HEADERS:
                        del bag[name]
        return new


_OPENER = urllib.request.build_opener(_SameHostCredentials())


def urlopen(req, timeout):
    """Every HTTP call in this file goes through here."""
    return _OPENER.open(req, timeout=timeout)


# What a child process may inherit (#215 review). Variables named like a
# credential, and the CI and forge namespaces, are never passed on; a child
# that needs one is given it by name.
_CREDENTIAL_NAME = re.compile(r"TOKEN|PASSWORD|PASSWD|SECRET|KEY|AUTH|CREDENTIAL|COOKIE|PRIVATE",
                              re.I)
_FORGE_PREFIXES = ("CI_", "GITLAB_", "GITHUB_", "GH_", "GLAB_", "RUNNER_", "DOCKER_", "FF_")


def child_env(pass_names=(), **set_vars):
    env = {}
    for name, value in os.environ.items():
        if _CREDENTIAL_NAME.search(name):
            continue
        if name.upper().startswith(_FORGE_PREFIXES):
            continue
        env[name] = value
    for name in pass_names:
        if name in os.environ:
            env[name] = os.environ[name]
    env.update(set_vars)
    return env


class LookupFailed(Exception):
    """A lookup that gave no answer: UNCHECKED locally, FAIL in CI."""


class Unauthorized(Exception):
    """The GitLab read token was refused: always FAIL."""


class Deadline:
    def __init__(self, seconds):
        self.end = time.monotonic() + seconds

    def left(self):
        return self.end - time.monotonic()

    def limit(self, want=CALL_TIMEOUT):
        left = self.left()
        if left <= 0:
            raise LookupFailed("the run's 8-minute deadline was reached")
        return max(0.5, min(want, left))


DEADLINE = Deadline(RUN_DEADLINE)


def run(cmd, timeout=None, **kw):
    """subprocess.run with a time limit; a timeout is LookupFailed."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=DEADLINE.limit(timeout or CALL_TIMEOUT), **kw)
    except subprocess.TimeoutExpired:
        raise LookupFailed(f"{os.path.basename(cmd[0])} timed out") from None
    except FileNotFoundError:
        raise LookupFailed(f"{cmd[0]} is not installed") from None


# ---------------------------------------------------------------------------
# Git (always real)
# ---------------------------------------------------------------------------

def git(*args, check=True):
    out = run(["git", *args])
    if check and out.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {out.stderr.strip()}")
    return out


def git_ok(*args):
    return git(*args, check=False).returncode == 0


class Tree:
    """Files and history of the commit being promoted."""

    def __init__(self, sha):
        self.sha = sha

    def show(self, path):
        out = git("show", f"{self.sha}:{path}", check=False)
        return out.stdout if out.returncode == 0 else None

    def blob(self, path, commit=None):
        out = git("rev-parse", "--verify", "-q", f"{commit or self.sha}:{path}", check=False)
        return out.stdout.strip() if out.returncode == 0 else None


# ---------------------------------------------------------------------------
# Lookups: the one injectable object (real, or --stub)
# ---------------------------------------------------------------------------

class RealLookups:
    def __init__(self, ci, remote_url):
        self.ci = ci
        self.gitlab_host, self.project_path = gitlab_project(remote_url)
        self._tokens = {}
        self._glab_repos = None
        self._cosign = None

    def now(self):
        return datetime.datetime.now(datetime.timezone.utc)

    # -- version ----------------------------------------------------------
    def release_version(self, version_text):
        with tempfile.NamedTemporaryFile("w", suffix=".VERSION", delete=False) as f:
            f.write(version_text if version_text is not None else "")
            path = f.name
        try:
            if version_text is None:
                return {"exit": 1, "stdout": "", "stderr": "VERSION is missing from the tree"}
            out = run(["bash", os.path.join(HERE, "release-version.sh"), "--file", path],
                      env=child_env())
            return {"exit": out.returncode, "stdout": out.stdout, "stderr": out.stderr}
        finally:
            os.unlink(path)

    # -- registries -------------------------------------------------------
    def registry_digest(self, registry, image, tag):
        """The digest `tag` names in that registry, or None if absent."""
        if registry == "ghcr":
            host, repo = "ghcr.io", f"{GHCR_NAMESPACE.split('/', 1)[1]}/{image}"
            return self._v2_digest(host, repo, tag, None)
        if self.ci:
            reg = os.environ.get("CI_REGISTRY")
            base = os.environ.get("CI_REGISTRY_IMAGE")
            user = os.environ.get("CI_REGISTRY_USER")
            password = os.environ.get("CI_REGISTRY_PASSWORD")
            if not (reg and base and user and password):
                raise LookupFailed("CI_REGISTRY, CI_REGISTRY_IMAGE or the registry login is not set")
            repo = base.split("/", 1)[1] + "/" + image
            return self._v2_digest(reg, repo, tag, (user, password))
        return self._glab_digest(image, tag)

    def _v2_digest(self, host, repo, tag, basic):
        token = self._token(host, repo, basic)
        url = f"https://{host}/v2/{repo}/manifests/{urllib.parse.quote(tag)}"
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"Accept": MANIFEST_ACCEPT,
                                              "Authorization": f"Bearer {token}"})
        try:
            with urlopen(req, timeout=DEADLINE.limit()) as resp:
                return resp.headers.get("Docker-Content-Digest") or None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise LookupFailed(f"{host} answered HTTP {e.code} for {repo}:{tag}") from None
        except (urllib.error.URLError, OSError) as e:
            raise LookupFailed(f"{host} did not answer: {getattr(e, 'reason', e)}") from None

    def _token(self, host, repo, basic):
        key = (host, repo)
        if key in self._tokens:
            return self._tokens[key]
        challenge = None
        try:
            urlopen(urllib.request.Request(f"https://{host}/v2/"), timeout=DEADLINE.limit()).close()
        except urllib.error.HTTPError as e:
            challenge = e.headers.get("WWW-Authenticate")
        except (urllib.error.URLError, OSError) as e:
            raise LookupFailed(f"{host} did not answer: {getattr(e, 'reason', e)}") from None
        m = re.search(r'realm="([^"]+)"', challenge or "")
        if not m:
            raise LookupFailed(f"{host} sent no auth challenge")
        service = re.search(r'service="([^"]+)"', challenge)
        query = {"scope": f"repository:{repo}:pull"}
        if service:
            query["service"] = service.group(1)
        req = urllib.request.Request(m.group(1) + "?" + urllib.parse.urlencode(query))
        if basic:
            req.add_header("Authorization", "Basic " + base64.b64encode(
                f"{basic[0]}:{basic[1]}".encode()).decode())
        try:
            with urlopen(req, timeout=DEADLINE.limit()) as resp:
                data = json.loads(read_capped(resp))
        except urllib.error.HTTPError as e:
            raise LookupFailed(f"{host} refused a pull token (HTTP {e.code})") from None
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise LookupFailed(f"{host} token request failed: {getattr(e, 'reason', e)}") from None
        token = data.get("token") or data.get("access_token")
        if not token:
            raise LookupFailed(f"{host} sent no token")
        self._tokens[key] = token
        return token

    def _glab(self, path):
        """GET a GitLab API path with the developer's own glab login."""
        if not shutil.which("glab"):
            raise LookupFailed("glab is not installed (needed locally to read GitLab)")
        args = ["glab", "api"]
        if self.gitlab_host:
            args += ["--hostname", self.gitlab_host]
        out = run(args + [path])
        if out.returncode == 0:
            try:
                return json.loads(out.stdout)
            except ValueError:
                raise LookupFailed(f"glab api {path}: not JSON") from None
        err = out.stderr.strip()
        if "404" in err:
            return None
        raise LookupFailed(f"glab api failed (logged in?): {err[:200]}")

    def _glab_digest(self, image, tag):
        project = urllib.parse.quote(self.project_path, safe="")
        if self._glab_repos is None:
            repos = self._glab(f"projects/{project}/registry/repositories?per_page=100") or []
            self._glab_repos = {r.get("path"): r.get("id") for r in repos if isinstance(r, dict)}
        rid = self._glab_repos.get(f"{self.project_path}/{image}")
        if rid is None:
            return None
        data = self._glab(f"projects/{project}/registry/repositories/{rid}/tags/"
                          f"{urllib.parse.quote(tag, safe='')}")
        return (data or {}).get("digest")

    # -- issues -----------------------------------------------------------
    def issue_state(self, iid):
        if self.ci:
            token = os.environ.get("BIRDCAGE_READ_TOKEN", "")
            api = os.environ.get("CI_API_V4_URL", "")
            project = os.environ.get("CI_PROJECT_ID", "")
            if not (api and project):
                raise LookupFailed("CI_API_V4_URL or CI_PROJECT_ID is not set")
            req = urllib.request.Request(f"{api}/projects/{project}/issues/{int(iid)}",
                                         headers={"PRIVATE-TOKEN": token})
            try:
                with urlopen(req, timeout=DEADLINE.limit()) as resp:
                    return json.loads(read_capped(resp)).get("state")
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    raise Unauthorized() from None
                if e.code == 404:
                    return None
                raise LookupFailed(f"the GitLab API answered HTTP {e.code}") from None
            except (urllib.error.URLError, OSError, ValueError) as e:
                raise LookupFailed(f"the GitLab API did not answer: {getattr(e, 'reason', e)}") from None
        project = urllib.parse.quote(self.project_path, safe="")
        data = self._glab(f"projects/{project}/issues/{int(iid)}")
        return None if data is None else data.get("state")

    # -- evidence ---------------------------------------------------------
    def evidence(self, image, digest, commit):
        base = os.environ.get("CI_REGISTRY_IMAGE") if self.ci else None
        if not base:
            base = f"{registry_host(self.gitlab_host)}/{self.project_path}"
        if self._cosign is None:
            out = run(["bash", os.path.join(HERE, "ensure-cosign.sh")],
                      timeout=COSIGN_INSTALL_TIMEOUT, env=child_env())
            if out.returncode != 0:
                raise LookupFailed("scripts/ensure-cosign.sh could not install cosign")
            self._cosign = out.stdout.strip().splitlines()[-1]
        env = child_env(BIRDCAGE_IMAGE=f"{base}/{image}", BIRDCAGE_DIGEST=digest,
                        BIRDCAGE_COMMIT=commit, BIRDCAGE_REF="preview",
                        BIRDCAGE_COSIGN=self._cosign)
        docker_config = None
        if self.ci and os.environ.get("CI_REGISTRY_USER"):
            # cosign reads registry credentials from a Docker config; write a
            # private one for this run only, never the job's environment.
            docker_config = tempfile.mkdtemp(prefix="readiness-docker-")
            auth = base64.b64encode(f"{os.environ['CI_REGISTRY_USER']}:"
                                    f"{os.environ.get('CI_REGISTRY_PASSWORD', '')}".encode()).decode()
            path = os.path.join(docker_config, "config.json")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump({"auths": {os.environ.get("CI_REGISTRY", ""): {"auth": auth}}}, f)
            env["DOCKER_CONFIG"] = docker_config
        try:
            out = run(["bash", os.path.join(HERE, "verify-validation-evidence.sh")],
                      timeout=EVIDENCE_TIMEOUT, env=env)
        finally:
            if docker_config:
                shutil.rmtree(docker_config, ignore_errors=True)
        m = re.search(r"recorded (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", out.stdout)
        if out.returncode == 0 and m:
            recorded = parse_when(m.group(1))
            return {"ok": True, "recorded": m.group(1),
                    "expires": iso(recorded + datetime.timedelta(days=EVIDENCE_MAX_AGE_DAYS))}
        reason = (out.stderr.strip().splitlines() or ["no output"])[-1]
        if not self.ci and out.returncode == 11 and re.search(
                r"(?i)unauthori[sz]ed|401|denied|authentication", out.stderr):
            raise LookupFailed("cosign could not log in to the registry from here")
        return {"ok": False, "reason": reason.replace("verify-validation-evidence: ", "")}

    # -- staleness --------------------------------------------------------
    def staleness(self, tree):
        work = tempfile.mkdtemp(prefix="readiness-tree-")
        try:
            archive = subprocess.run(["git", "archive", "--format=tar", tree.sha],
                                     capture_output=True, timeout=DEADLINE.limit(60))
            if archive.returncode != 0:
                raise LookupFailed("git archive of the source tree failed")
            with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tf:
                try:
                    tf.extractall(work, filter="data")
                except TypeError:  # Python without extraction filters
                    tf.extractall(work)
            rows_path = os.path.join(work, ".staleness-rows.json")
            limit = max(10, min(STALENESS_DEADLINE, int(DEADLINE.left()) - 60))
            out = run([sys.executable, os.path.join(HERE, "staleness-check.py"),
                       "--root", work, "--json", rows_path, "--timeout", str(CALL_TIMEOUT),
                       "--deadline", str(limit)], timeout=limit + 30,
                      env=child_env(("CI", "CI_REGISTRY", "CI_REGISTRY_USER",
                                     "CI_REGISTRY_PASSWORD", "GITHUB_TOKEN")))
            if out.returncode not in (0, 1) or not os.path.isfile(rows_path):
                raise LookupFailed("staleness-check could not run: "
                                   + (out.stderr.strip().splitlines() or ["no output"])[-1])
            with open(rows_path) as f:
                return json.load(f)["rows"]
        except subprocess.TimeoutExpired:
            raise LookupFailed("git archive timed out") from None
        finally:
            shutil.rmtree(work, ignore_errors=True)


class StubLookups:
    """Answers from a JSON file (test-only --stub)."""

    def __init__(self, path):
        with open(path) as f:
            self.s = json.load(f)

    @staticmethod
    def _value(v, what):
        if v == "timeout":
            raise LookupFailed(f"{what} timed out")
        if v == "no-credential":
            raise LookupFailed(f"{what}: glab is missing or not logged in")
        if v == "unauthorized":
            raise Unauthorized()
        return v

    def now(self):
        return parse_when(self.s["now"])

    def release_version(self, version_text):
        return self.s["release_version"]

    def registry_digest(self, registry, image, tag):
        repo = self._value(self.s["registry"].get(registry, {}).get(image, {}),
                           f"{registry} {image}")
        return repo.get(tag)

    def issue_state(self, iid):
        issues = self._value(self.s["issues"], "the issue lookup")
        return issues.get(str(iid))

    def evidence(self, image, digest, commit):
        ev = self._value(self.s["evidence"], "the evidence lookup")
        return ev.get(image)

    def staleness(self, tree):
        return self._value(self.s["staleness"], "staleness-check")["rows"]


def gitlab_project(url):
    """(host, project path) of a GitLab remote URL, best effort."""
    m = re.match(r"^(?:https?://(?:[^@/]+@)?|ssh://(?:[^@/]+@)?|[^@/]+@)([^/:]+)(?::\d+)?[/:](.+?)(?:\.git)?/?$",
                 url or "")
    if not m:
        return None, os.environ.get("CI_PROJECT_PATH", "ai/birdcage")
    return m.group(1), m.group(2)


def registry_host(gitlab_host):
    return os.environ.get("CI_REGISTRY") or f"registry.{gitlab_host or 'localhost'}"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def parse_when(text):
    text = str(text).strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        return datetime.datetime.fromisoformat(text).replace(tzinfo=datetime.timezone.utc)
    when = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    return when if when.tzinfo else when.replace(tzinfo=datetime.timezone.utc)


def iso(when):
    return when.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def semver(v):
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", v)
    return tuple(int(x) for x in m.groups()) if m else None


PASS, FAIL, UNCHECKED, INFO = "PASS", "FAIL", "UNCHECKED", "INFO"
RANK = {PASS: 0, INFO: 0, UNCHECKED: 1, FAIL: 2}


class Result:
    def __init__(self, status, message):
        self.status, self.message = status, message


def worst(results):
    return max(results, key=lambda r: RANK[r.status])


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------

class Ctx:
    pass


def version_info(ctx):
    """(V, problem-or-None) from scripts/release-version.sh on the tree."""
    if not hasattr(ctx, "_version"):
        rv = ctx.lookups.release_version(ctx.tree.show("VERSION"))
        v = (rv.get("stdout") or "").strip()
        if rv.get("exit") != 0 or not semver(v):
            why = (rv.get("stderr") or "").strip() or f"printed {v!r}"
            ctx._version = (None, why)
        else:
            ctx._version = (v, None)
    return ctx._version


def needs_version(ctx):
    v, _ = version_info(ctx)
    if v is None:
        return None, Result(FAIL, "cannot be checked while VERSION is invalid: fix VERSION first "
                                  "(see the version-valid check)")
    return v, None


def check_version_valid(ctx):
    v, why = version_info(ctx)
    if v is None:
        return Result(FAIL, f"VERSION is not a plain MAJOR.MINOR.PATCH ({why}): fix it through "
                            f"a batch (docs/releasing.md 'The version').")
    return Result(PASS, f"VERSION is {v}")


def check_version_new(ctx):
    v, bad = needs_version(ctx)
    if bad:
        return bad
    out = git("ls-remote", "--tags", ctx.remote, check=False)
    if out.returncode != 0:
        return Result(UNCHECKED, f"could not list tags on {ctx.remote}: "
                                 f"{out.stderr.strip()[:200]}")
    tags = set()
    for line in out.stdout.splitlines():
        ref = line.split("\t")[-1]
        if ref.startswith("refs/tags/"):
            tags.add(ref[len("refs/tags/"):].removesuffix("^{}"))
    t = f"v{v}"
    released = sorted((semver(x), x) for x in tags if semver(x))
    newest = released[-1][1] if released else None
    if t in tags:
        return Result(FAIL, f"{t} is already released (tag {t} exists on {ctx.remote}): "
                            f"bump VERSION through a batch.")
    if newest and semver(v) <= semver(newest):
        return Result(FAIL, f"{t} is not newer than {newest}, the newest release: "
                            f"bump VERSION through a batch.")
    return Result(PASS, f"{t} is new (newest release {newest or 'none'})")


def check_version_unburnt(ctx):
    v, bad = needs_version(ctx)
    if bad:
        return bad
    t = f"v{v}"
    burnt, unknown = [], []
    for registry, label in (("gitlab", "GitLab"), ("ghcr", "GHCR")):
        for image in IMAGES:
            try:
                if ctx.lookups.registry_digest(registry, image, t):
                    burnt.append(f"{label} {image}:{t}")
            except LookupFailed as e:
                unknown.append(f"{label} {image} ({e})")
    if burnt:
        return Result(FAIL, f"{', '.join(burnt)} exists, so {t} is burnt: take the next patch "
                            f"version, or ask the owner to delete the unused tags (as #171).")
    if unknown:
        return Result(UNCHECKED, "could not read " + "; ".join(unknown))
    return Result(PASS, f"no image repository carries {t} (six on GitLab, six on GHCR)")


def check_version(ctx):
    """M3: P1-P3 on the preview tip."""
    parts = [check_version_valid(ctx), check_version_new(ctx), check_version_unburnt(ctx)]
    w = worst(parts)
    if w.status == PASS:
        return Result(PASS, "; ".join(p.message for p in parts))
    return Result(w.status, " ".join(p.message for p in parts if p.status != PASS))


def check_changelog(ctx):
    v, _ = version_info(ctx)
    want = f"## [{v or 'X.Y.Z'}] - <date>"
    todo = (f"Rename the Unreleased section to `{want}` in the release/v{v or 'X.Y.Z'} MR "
            f"into dev before promoting.")
    text = ctx.tree.show("CHANGELOG.md")
    if text is None:
        return Result(FAIL, f"CHANGELOG.md is missing: create it (Keep a Changelog). {todo}")
    if v is None:
        return Result(FAIL, "cannot find this release's section while VERSION is invalid: "
                            "fix VERSION first")
    sections, current = {}, None
    order = []
    for line in text.splitlines():
        m = re.match(r"^##\s+\[([^\]]+)\](.*)$", line)
        if m:
            current = m.group(1)
            sections.setdefault(current, {"rest": m.group(2).strip(), "lines": []})
            order.append(current)
            continue
        if re.match(r"^##\s", line):
            current = None
            continue
        if current:
            sections[current]["lines"].append(line)
    problems = []
    unrel = sections.get("Unreleased")
    if unrel and any(l.strip() and not l.startswith("### ") for l in unrel["lines"]):
        problems.append("the Unreleased section still holds entries")
    sec = sections.get(v)
    if sec is None:
        problems.append(f"there is no `## [{v}] - YYYY-MM-DD` section")
    else:
        if not re.fullmatch(r"-\s+\d{4}-\d{2}-\d{2}", sec["rest"]):
            problems.append(f"the [{v}] heading's date is not YYYY-MM-DD ({sec['rest'] or 'none'})")
        entries = [l for l in sec["lines"] if re.match(r"^\s*[-*]\s+\S", l)]
        if not entries:
            problems.append(f"the [{v}] section is empty")
        for l in sec["lines"]:
            h = re.match(r"^###\s+(.*?)\s*$", l)
            if h and h.group(1) not in KEEP_A_CHANGELOG:
                problems.append(f"the [{v}] section has a heading `{h.group(1)}`; only "
                                + ", ".join(sorted(KEEP_A_CHANGELOG)) + " are allowed")
    if problems:
        return Result(FAIL, "CHANGELOG.md: " + "; ".join(problems) + ". " + todo)
    return Result(PASS, f"CHANGELOG.md has a dated, non-empty [{v}] section and an empty Unreleased")


def read_record(ctx):
    """(path, parsed-or-None). The whole file is read: the record is
    immutable and ends at its sign-off (#215 design note 63905)."""
    v, _ = version_info(ctx)
    path = f"docs/releases/v{v}.md" if v else None
    text = ctx.tree.show(path) if path else None
    if text is None:
        return path, None
    rec = {"fields": {}, "steps": [], "signoffs": [], "text": text}
    for line in text.splitlines():
        m = re.match(r"^(version|guide-commit|guide-blob|review):(.*)$", line)
        if m and m.group(1) not in rec["fields"]:
            rec["fields"][m.group(1)] = m.group(2).strip()
            continue
        m = re.match(r"^step\s+(\d+):(.*)$", line)
        if m:
            rec["steps"].append((int(m.group(1)), m.group(2).strip()))
            continue
        if line.startswith("Signed-off-by:"):
            rec["signoffs"].append(line[len("Signed-off-by:"):].strip())
    return path, rec


def review_issues(rec):
    return re.findall(r"#(\d+)", rec["fields"].get("review", "")) if rec else []


def check_review(ctx):
    path, rec = read_record(ctx)
    if rec is None:
        return Result(FAIL, f"no release record {path or 'docs/releases/vX.Y.Z.md'}, so no "
                            f"review: line naming the review issue: commit the record first "
                            f"(see the release-record check).")
    iids = review_issues(rec)
    if not iids:
        return Result(FAIL, f"the review: line in {path} is missing or names no issue: name the "
                            f"closed review issue(s) of this release, e.g. `review: #206`.")
    if ctx.ci and not os.environ.get("BIRDCAGE_READ_TOKEN"):
        return Result(FAIL, "BIRDCAGE_READ_TOKEN is not available to this pipeline (protected "
                            "variables reach only protected branches): owner setup, "
                            "docs/releasing.md 'The read token'.")
    open_, missing = [], []
    try:
        for iid in iids:
            state = ctx.lookups.issue_state(iid)
            if state is None:
                missing.append(iid)
            elif state != "closed":
                open_.append(iid)
    except Unauthorized:
        return Result(FAIL, "the read token is expired or lacks read_api: owner renews it "
                            "(BIRDCAGE_READ_TOKEN, Reporter, read_api only).")
    except LookupFailed as e:
        return Result(UNCHECKED, f"could not read the review issues: {e}")
    msgs = [f"Review issue #{i} is open: close it with evidence first (delivery rule 'No "
            f"promotion without a closed review issue')." for i in open_]
    msgs += [f"Review issue #{i} was not found: fix the review: line in {path}." for i in missing]
    if msgs:
        return Result(FAIL, " ".join(msgs))
    return Result(PASS, "review issue(s) " + ", ".join("#" + i for i in iids) + " closed")


def check_contains_preview(ctx):
    base = f"{ctx.remote}/preview"
    if not git_ok("rev-parse", "--verify", "-q", base):
        return Result(FAIL, f"{base} not found: fetch it (git fetch {ctx.remote} preview).")
    if git_ok("merge-base", "--is-ancestor", base, ctx.tree.sha):
        return Result(PASS, f"{ctx.branch} contains {base}")
    return Result(FAIL, f"{ctx.branch} is behind preview: back-merge preview into dev first "
                        f"(docs/releasing.md step 6).")


def check_hop_preview(ctx):
    b = ctx.branch
    if b == "dev":
        return Result(PASS, "dev -> preview")
    if b.startswith("hotfix/"):
        if re.fullmatch(r"hotfix/[A-Za-z0-9._-]+", b):
            return Result(PASS, f"{b} -> preview")
        return Result(FAIL, "hotfix branch name must be hotfix/<name> using A-Z a-z 0-9 . _ -")
    return Result(FAIL, f"preview only accepts merge requests from dev or hotfix/<name> "
                        f"({b} is neither).")


def check_hop_main(ctx):
    if ctx.branch == "preview":
        return Result(PASS, "preview -> main")
    return Result(FAIL, f"main only accepts merge requests from preview ({ctx.branch} is not).")


def check_lands_exactly(ctx):
    base = f"{ctx.remote}/main"
    todo = ("Merging would change files relative to the tested preview: back-merge main into "
            "dev and promote again (checked by hand on !102).")
    if not git_ok("rev-parse", "--verify", "-q", base):
        return Result(FAIL, f"{base} not found: fetch it (git fetch {ctx.remote} main).")
    if not git_ok("merge-base", "--is-ancestor", base, ctx.tree.sha):
        return Result(FAIL, f"{base} is not contained in the preview tip. {todo}")
    out = git("merge-tree", "--write-tree", base, ctx.tree.sha, check=False)
    merged = out.stdout.split("\n", 1)[0].strip()
    tip_tree = git("rev-parse", f"{ctx.tree.sha}^{{tree}}").stdout.strip()
    if out.returncode != 0 or merged != tip_tree:
        return Result(FAIL, f"the merge result differs from the preview tip's tree. {todo}")
    return Result(PASS, "the merge leaves exactly the preview tip's tree")


def preview_digests(ctx):
    """M4's lookups, kept for M5: {image: digest-or-None}, problems, unknown."""
    if hasattr(ctx, "_published"):
        return ctx._published
    tip = ctx.tree.sha
    digests, problems, unknown = {}, [], []
    for image in IMAGES:
        try:
            d = ctx.lookups.registry_digest("gitlab", image, f"sha-{tip}")
            digests[image] = d
            what = []
            if not d:
                what.append(f"GitLab has no sha-{tip[:12]}")
            else:
                if ctx.lookups.registry_digest("gitlab", image, "preview") != d:
                    what.append("GitLab :preview is another digest")
                if ctx.lookups.registry_digest("ghcr", image, "preview") != d:
                    what.append("GHCR :preview is another digest")
                if not ctx.lookups.registry_digest("ghcr", image, "sha256-" + d.split(":", 1)[-1]):
                    what.append("GHCR lacks the sha256-<digest> attestation tag")
            if what:
                problems.append(f"{image}: preview tip {tip[:12]} was not fully published or "
                                f"mirrored ({', '.join(what)})")
        except LookupFailed as e:
            digests.setdefault(image, None)
            unknown.append(f"{image} ({e})")
    ctx._published = (digests, problems, unknown)
    return ctx._published


def check_published(ctx):
    _, problems, unknown = preview_digests(ctx)
    if problems:
        return Result(FAIL, "; ".join(problems) + ": re-run the preview pipeline or merge to "
                                                 "preview again (#162).")
    if unknown:
        return Result(UNCHECKED, "could not read " + "; ".join(unknown))
    return Result(PASS, "all six images published on GitLab and mirrored to GHCR with attestations")


def check_evidence(ctx):
    digests, _, _ = preview_digests(ctx)
    now = ctx.lookups.now()
    again = ("merge to preview again for a fresh build (docs/releasing.md: 'that is the rule "
             "working').")
    fails, unknown, soonest = [], [], None
    for image in IMAGES:
        d = digests.get(image)
        if not d:
            fails.append(f"{image} has no published preview digest to verify (see M4)")
            continue
        try:
            ev = ctx.lookups.evidence(image, d, ctx.tree.sha)
        except LookupFailed as e:
            unknown.append(f"{image} ({e})")
            continue
        if not ev:
            fails.append(f"no evidence found for {image}")
            continue
        if not ev.get("ok"):
            fails.append(f"Evidence for {image} was rejected ({ev.get('reason', 'no reason given')})")
            continue
        expires = parse_when(ev["expires"])
        if expires - now < EVIDENCE_MIN_LEFT:
            fails.append(f"Evidence for {image} was recorded {ev['recorded']} and expires "
                         f"{ev['expires']}")
        soonest = expires if soonest is None or expires < soonest else soonest
    if fails:
        return Result(FAIL, "; ".join(fails) + ": " + again)
    if unknown:
        return Result(UNCHECKED, "could not verify evidence for " + "; ".join(unknown))
    return Result(PASS, f"evidence verifies for all six; the first expires {iso(soonest)}")


def check_manual_test(ctx):
    todo = ("Write the step 2 production-like test result in the MR description as "
            "'Step 2: ...' within its first 2,700 characters (GitLab cuts the description "
            "it gives the pipeline at 2,700 characters), then re-run the job.")
    if ctx.description is None:
        where = ("CI_MERGE_REQUEST_DESCRIPTION is empty" if ctx.ci else
                 "no --description-file given (locally, pass the MR description with it)")
        return Result(FAIL, f"{where}. {todo}")
    if re.search(r"(?m)^\s*Step 2:[ \t]*\S", ctx.description):
        return Result(PASS, "the MR description records step 2")
    return Result(FAIL, f"the MR description has no 'Step 2: <evidence>' line. {todo}")


def check_signing_key(ctx):
    text = ctx.tree.show("cosign.pub")
    if text is None:
        return Result(FAIL, "cosign.pub missing: owner setup step 2.")
    m = re.search(r"-----BEGIN PUBLIC KEY-----\s*\n(.+?)\n-----END PUBLIC KEY-----", text, re.S)
    ok = False
    if m:
        try:
            ok = len(base64.b64decode("".join(m.group(1).split()), validate=True)) > 0
        except ValueError:
            ok = False
    if not ok:
        return Result(FAIL, "cosign.pub is not a PEM public key: owner setup step 2.")
    return Result(PASS, "cosign.pub is a PEM public key")


def guide_steps(text):
    steps, inside = [], False
    for line in (text or "").splitlines():
        if re.match(r"^##\s", line):
            inside = line.strip() == "## Cutting a release"
            continue
        if inside:
            m = re.match(r"^(\d+)\.\s", line)
            if m:
                steps.append(int(m.group(1)))
    return steps


def check_record(ctx):
    v, bad = needs_version(ctx)
    if bad:
        return bad
    t = f"v{v}"
    path, rec = read_record(ctx)
    if rec is None:
        return Result(FAIL, f"{path} is missing: read docs/releasing.md, copy "
                            f"docs/releases/TEMPLATE.md, one line per step, commit with "
                            f"--trailer 'Signed-off-by: <name>', open the release/{t} MR into dev.")
    f = rec["fields"]
    p = []
    if f.get("version") != t:
        p.append(f"version: is {f.get('version') or 'missing'}, not {t}")
    tree_blob = ctx.tree.blob(GUIDE)
    if not tree_blob:
        p.append(f"{GUIDE} is missing from the tree")
    elif f.get("guide-blob") != tree_blob:
        p.append(f"guide-blob: is not the blob of {GUIDE} in the tree being promoted ({tree_blob}): "
                 "the guide changed: re-read it and redo the record")
    gc = f.get("guide-commit", "")
    if not re.fullmatch(r"[0-9a-f]{40}", gc) or not git_ok("cat-file", "-e", f"{gc}^{{commit}}"):
        p.append("guide-commit: is not the full sha of a commit")
    elif not git_ok("merge-base", "--is-ancestor", gc, ctx.tree.sha):
        p.append(f"guide-commit {gc[:12]} is not an ancestor of the source")
    elif ctx.tree.blob(GUIDE, gc) != f.get("guide-blob"):
        p.append(f"guide-commit {gc[:12]}'s {GUIDE} is not guide-blob:")
    want = guide_steps(ctx.tree.show(GUIDE))
    got = [n for n, _ in rec["steps"]]
    if got != want:
        missing = [n for n in want if n not in got]
        extra = sorted({n for n in got if n not in want})
        doubled = sorted({n for n in got if got.count(n) > 1})
        if missing:
            p.append("missing " + ", ".join(f"step {n}" for n in missing))
        if extra:
            p.append(", ".join(f"step {n}" for n in extra) + " is not a step of the guide")
        if doubled:
            p.append(", ".join(f"step {n}" for n in doubled) + " listed more than once")
        if not (missing or extra or doubled):
            p.append("steps are not in the guide's order (" + ", ".join(map(str, want)) + ")")
    for n, value in rec["steps"]:
        if "<" in value and ">" in value and re.search(r"<[^>]*>", value):
            p.append(f"step {n} still holds a <...> placeholder")
        elif not (value == "after-merge" or re.fullmatch(r"(done|not-needed):\s*\S.*", value)):
            p.append(f"step {n} is not 'done: <evidence>', 'not-needed: <owner decision>' "
                     f"or 'after-merge'")
    signs = rec["signoffs"]
    name = None
    if len(signs) != 1:
        p.append(f"there must be exactly one Signed-off-by: line (found {len(signs)})")
    elif not signs[0] or re.search(r"[@<>]", signs[0]):
        p.append("the Signed-off-by: line must hold a name only, no email")
    else:
        name = signs[0]
    if name:
        out = git("log", "-1", "--format=%an%x00%(trailers:key=Signed-off-by,valueonly)",
                  ctx.tree.sha, "--", path, check=False)
        author, _, trailers = out.stdout.partition("\x00")
        trailers = [x.strip() for x in trailers.splitlines() if x.strip()]
        if author.strip() != name:
            p.append(f"the last commit touching {path} is by {author.strip() or 'nobody'}, "
                     f"not the signer {name}")
        if name not in trailers:
            p.append(f"the last commit touching {path} has no 'Signed-off-by: {name}' trailer "
                     f"(commit with --trailer 'Signed-off-by: {name}')")
    if not review_issues(rec):
        p.append("review: is missing or empty")
    if p:
        return Result(FAIL, f"{path}: " + "; ".join(p) + ". See docs/releases/TEMPLATE.md.")
    return Result(PASS, f"{path} covers steps {', '.join(map(str, want))} of the guide at "
                        f"{tree_blob[:12]}, signed off by {name}")


def staleness_rows(ctx):
    if not hasattr(ctx, "_rows"):
        try:
            ctx._rows = (ctx.lookups.staleness(ctx.tree), None)
        except LookupFailed as e:
            ctx._rows = (None, str(e))
    return ctx._rows


def check_pins_current(ctx):
    rows, err = staleness_rows(ctx)
    stale_status = INFO if ctx.target == "main" else FAIL
    if rows is None:
        return Result(INFO if ctx.target == "main" else UNCHECKED,
                      f"staleness-check gave no answer: {err}")
    if not rows:
        return Result(stale_status, "staleness-check returned no rows at all, so nothing was "
                      "checked: run scripts/staleness-check.py and fix what it cannot read")
    now = ctx.lookups.now()
    cooldown = datetime.timedelta(days=ctx.cooldown_days)
    fails, unchecked, young = [], [], []
    for r in rows:
        rid = r["id"]
        if rid.startswith("apk:"):
            continue
        status = r.get("status")
        hold = r.get("hold")
        if status in ("current", "floating", "accepted"):
            continue
        if hold and hold.get("lapsed") == "expired":
            fails.append(f"the hold on {rid} expired on {hold.get('review_by')}: bump it or "
                         f"renew the hold with a new reason")
            continue
        if hold and hold.get("lapsed") == "held-at-differs":
            fails.append(f"the hold on {rid} is for {hold.get('held_at')}, not the pin "
                         f"{r.get('pinned')}: bump it or renew the hold for this pin")
            continue
        if status == "behind":
            # Docker Hub's tag date moves on every rebuild of an official
            # image, so a newer image version always counts (#215 review).
            released = None if rid.startswith("image:") else r.get("released")
            if released:
                try:
                    if now - parse_when(released) < cooldown:
                        young.append(rid)
                        continue
                except ValueError:
                    pass
            fails.append(f"{rid} is pinned at {r.get('pinned')}, upstream has {r.get('latest')} "
                         f"(released {str(released)[:10] if released else 'on an unknown date'}): "
                         f"bump it through a batch, or record a hold in "
                         f"supply-chain/staleness.yml (held-at {r.get('pinned')}, reason, review-by)")
            continue
        if status == "unverifiable" and r.get("credential_missing") and not ctx.ci:
            unchecked.append(f"{rid} needs the CI registry login; the CI job checks it")
            continue
        fails.append(f"{rid} could not be checked ({r.get('note') or 'no answer'}): fix the "
                     f"lookup, or record it under unchecked: in supply-chain/staleness.yml "
                     f"with a reason and review-by")
    note = (f"; {len(young)} newer version(s) inside the {ctx.cooldown_days}-day cooldown: "
            + ", ".join(young)) if young else ""
    if fails:
        return Result(stale_status, "; ".join(fails) + note)
    if unchecked:
        return Result(INFO if ctx.target == "main" else UNCHECKED, "; ".join(unchecked) + note)
    return Result(PASS, f"{len(rows)} pins current, floating or held{note}")


def check_apk_buildable(ctx):
    rows, err = staleness_rows(ctx)
    if rows is None:
        return Result(UNCHECKED, f"staleness-check gave no answer: {err}")
    fails, unknown, n = [], [], 0
    for r in rows:
        rid = r["id"]
        if not rid.startswith("apk:"):
            continue
        n += 1
        name = rid.rsplit(":", 1)[-1]
        where = r.get("file") or (rid.split(":")[1] if rid.count(":") >= 2 else "its Dockerfile")
        pinned, latest, status = r.get("pinned", ""), r.get("latest", ""), r.get("status")
        if status == "unverifiable" and "not found in" not in (r.get("note") or ""):
            unknown.append(f"{name} in {where} ({r.get('note')})")
            continue
        if status == "current" or (status == "accepted" and apk_matches(pinned, latest)):
            continue
        shown = f"{name}{pinned}" if pinned.startswith("~=") else f"{name}={pinned}"
        fails.append(f"Alpine no longer carries {shown} (has {latest or 'none'}): bump the pin "
                     f"in {where} and supply-chain/dependency-inventory.md (as #165)")
    if n == 0:
        return Result(FAIL, "staleness-check returned no apk: rows, so no Alpine pin was "
                      "checked: the Dockerfiles carry apk pins, so the check is not reading them")
    if fails:
        return Result(FAIL, "; ".join(fails) + ". A hold cannot excuse this: the build would fail.")
    if unknown:
        return Result(UNCHECKED, "could not read Alpine's index for " + "; ".join(unknown))
    return Result(PASS, f"{n} apk pin(s) are in their Alpine branch's index")


def apk_matches(pinned, latest):
    if not latest:
        return False
    if pinned.startswith("~="):
        ver = pinned[2:]
        return latest == ver or (latest.startswith(ver) and not latest[len(ver)].isdigit())
    return pinned == latest


PREVIEW_CHECKS = [
    ("P1", "version valid", check_version_valid),
    ("P2", "version new", check_version_new),
    ("P3", "version not burnt", check_version_unburnt),
    ("P4", "change log", check_changelog),
    ("P5", "review closed", check_review),
    ("P6", "contains preview", check_contains_preview),
    ("P7", "hop allowed", check_hop_preview),
    ("S1", "pins current", check_pins_current),
    ("S2", "apk pins buildable", check_apk_buildable),
    ("K1", "signing key", check_signing_key),
    ("R1", "release record", check_record),
]
MAIN_CHECKS = [
    ("M1", "hop", check_hop_main),
    ("M2", "lands preview exactly", check_lands_exactly),
    ("M3", "version", check_version),
    ("M4", "preview published", check_published),
    ("M5", "evidence fresh", check_evidence),
    ("M6", "change log", check_changelog),
    ("M7", "review closed", check_review),
    ("M8", "release record", check_record),
    ("M9", "manual test recorded", check_manual_test),
    ("S1", "pins current", check_pins_current),
    ("S2", "apk pins buildable", check_apk_buildable),
    ("K1", "signing key", check_signing_key),
]


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"release-readiness: {message}", file=sys.stderr)
        sys.exit(2)


def default_remote():
    remotes = git("remote", check=False).stdout.split()
    if "gitlab" in remotes:
        return "gitlab"
    for r in remotes:
        url = git("remote", "get-url", r, check=False).stdout
        if "github.com" not in url:
            return r
    return "origin"


def source_branch(ci, source):
    if ci and os.environ.get("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"):
        return os.environ["CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"]
    if source == "HEAD":
        out = git("symbolic-ref", "-q", "--short", "HEAD", check=False)
        return out.stdout.strip() or "(detached HEAD)"
    for r in git("remote", check=False).stdout.split():
        if source.startswith(r + "/"):
            return source[len(r) + 1:]
    return source


def main(argv):
    parser = Parser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", required=True, choices=["preview", "main"])
    parser.add_argument("--source", default="HEAD")
    parser.add_argument("--remote")
    parser.add_argument("--description-file")
    parser.add_argument("--cooldown-days", type=int, default=14)
    parser.add_argument("--stub", help=argparse.SUPPRESS)
    args = parser.parse_args(argv[1:])
    if args.cooldown_days < 0:
        parser.error("--cooldown-days must be 0 or more")

    ci = os.environ.get("CI") == "true"
    try:
        if not git_ok("rev-parse", "--git-dir"):
            print("release-readiness: not inside a git repository", file=sys.stderr)
            return 2
        out = git("rev-parse", "--verify", "-q", f"{args.source}^{{commit}}", check=False)
        if out.returncode != 0:
            print(f"release-readiness: --source {args.source} is not a commit", file=sys.stderr)
            return 2
        sha = out.stdout.strip()
        remote = args.remote or ("origin" if ci else default_remote())
        remote_url = git("remote", "get-url", remote, check=False).stdout.strip()
        if not remote_url:
            print(f"release-readiness: no remote named {remote}", file=sys.stderr)
            return 2
        # The target is what the source is compared with; read it fresh.
        fetched = git("fetch", "--quiet", remote,
                      f"+refs/heads/{args.target}:refs/remotes/{remote}/{args.target}",
                      check=False)
    except (RuntimeError, LookupFailed) as e:
        print(f"release-readiness: {e}", file=sys.stderr)
        return 2

    ctx = Ctx()
    ctx.ci, ctx.target, ctx.remote, ctx.tree = ci, args.target, remote, Tree(sha)
    ctx.branch = source_branch(ci, args.source)
    ctx.cooldown_days = args.cooldown_days
    ctx.lookups = StubLookups(args.stub) if args.stub else RealLookups(ci, remote_url)
    if ci:
        ctx.description = os.environ.get("CI_MERGE_REQUEST_DESCRIPTION") or None
    elif args.description_file:
        with open(args.description_file) as f:
            ctx.description = f.read()
    else:
        ctx.description = None

    print(f"release-readiness: {ctx.branch} -> {args.target} at {sha[:12]}, remote {remote}"
          + (" (CI)" if ci else " (local)"))
    if fetched.returncode != 0:
        print(f"note: could not fetch {remote}/{args.target}; using the local copy")
    if ci:
        print("review token: " + ("present" if os.environ.get("BIRDCAGE_READ_TOKEN") else "absent"))

    results = []
    for cid, name, fn in (PREVIEW_CHECKS if args.target == "preview" else MAIN_CHECKS):
        try:
            res = fn(ctx)
        except LookupFailed as e:
            res = Result(UNCHECKED, str(e))
        except Exception as e:  # noqa: BLE001 -- one broken check must not hide the rest
            res = Result(FAIL, f"internal error in this check: {type(e).__name__}: {e}")
        if ci and res.status == UNCHECKED:
            res = Result(FAIL, f"could not be checked, which fails in CI: {res.message}")
        results.append((cid, name, res))
        print(f"{res.status} {cid} {name}: {res.message}", flush=True)

    failed = [(cid, name, r) for cid, name, r in results if r.status == FAIL]
    unchecked = [(cid, name, r) for cid, name, r in results if r.status == UNCHECKED]
    if failed:
        print("\nFailed:")
        for cid, name, r in failed:
            print(f"- {cid} {name}: {r.message}")
        return 1
    if unchecked:
        print("\nUnchecked (does not clear a promotion; CI checks these): "
              + ", ".join(cid for cid, _, _ in unchecked))
        return 3
    print("\nAll checks passed. This does not replace the owner's approval of the promotion.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
