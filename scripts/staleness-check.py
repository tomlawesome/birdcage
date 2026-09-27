#!/usr/bin/env python3
"""Check every pinned dependency and CI tool against its upstream.

Issue #139: nothing in CI checks pinned dependencies and tools for newer
versions, so a stale Go module, a floating-looking container tag that has
quietly drifted, or a checksum-pinned tool sitting behind its own project's
latest release only gets noticed when someone thinks to look. This script
is that look, run on a schedule (`audit:staleness` in .gitlab-ci.yml, never
on a merge request -- see docs/ci-hops.md) rather than on every change: a
network round trip to half a dozen registries has no place gating a merge,
and nothing here can fix a dependency by itself, only report on it.

Every pin is read from the manifest that actually governs it -- go.mod,
frontend/package-lock.json, build/opencanary/requirements.txt, the
Dockerfiles, .gitlab-ci.yml, the ensure-*.sh scripts, .github/workflows/*.yml
-- never from supply-chain/dependency-inventory.md, which is a dated,
hand-written snapshot and would just let this script agree with itself.

Ecosystems covered, and where each pin comes from:

  - Go toolchain: the `go` directive in go.mod, `golang:<ver>` tags found
    anywhere in build/*/Dockerfile and in .gitlab-ci.yml's GOLANG_IMAGE, and
    the go tarball test:smoke fetches -- all compared against
    https://go.dev/dl/?mode=json's newest stable release.
  - Direct Go modules: go.mod's `require` block (skipping `// indirect`),
    plus every `go install <module>@vX.Y.Z` in .gitlab-ci.yml -- compared
    against proxy.golang.org's `@latest` (and, for a module already pinned
    to a pre-release, `@v/list` too).
  - Direct npm packages: names from frontend/package.json, installed
    versions from frontend/package-lock.json -- compared against
    registry.npmjs.org's `/latest`.
  - build/opencanary/requirements.txt's `name==ver` lines -- compared
    against pypi.org's JSON API.
  - Container image tags: every `FROM` in build/*/Dockerfile and every
    `*_IMAGE:` variable in .gitlab-ci.yml (golang: handled above, not
    here) -- compared within the same tag family (same suffix, same
    precision) against Docker Hub or gcr.io's own registry API.
  - `apk add name=ver` pins -- compared against the APKINDEX of the
    pinning Dockerfile's own Alpine branch.
  - Checksum-pinned tools (cosign, gitleaks, grype) -- compared against
    each project's GitHub "latest release". SHA-pinned GitHub Actions
    `uses:` lines -- compared against that repo's newest semver tag.
  - The Responder fixture digest pinned in .gitlab-ci.yml -- compared
    against the registry's current digest for `latest` (needs
    CI_REGISTRY_USER/PASSWORD; unverifiable without them).

Every row gets a status: `current`, `behind`, `floating` (no version
component in the pin at all -- never "behind"), `accepted` (a `behind` or
`unverifiable` row covered by supply-chain/staleness.yml's `accepted:`
list, while the pin still matches `held-at` and today is not after
`review-by`), or `unverifiable` (the upstream could not be reached or
parsed). `behind` and `unverifiable` both fail the run unless covered by
the config -- a check that cannot check must not pass.

Usage:
  scripts/staleness-check.py [--root DIR] [--report PATH]
                              [--upstream FIXTURE.json] [--today YYYY-MM-DD]

--upstream replaces every network fetch: the fixture JSON maps the exact
URL touched to either a response body (a string), `{"status": N}` for a
non-200 response, or `{"error": "..."}` for a transport failure. A URL
this script would touch but that is missing from the fixture is itself an
error -- so the fixture doubles as a list of everything the check reaches
out to. Without --upstream, every fetch is real.

Exit codes: 0 nothing is `behind` or `unverifiable` after the config is
applied; 1 at least one row still is.
"""
import argparse
import datetime
import json
import os
import re
import sys
import tarfile
import io
import urllib.error
import urllib.parse
import urllib.request

try:
    import yaml
except ImportError:
    yaml = None


def require_yaml():
    if yaml is None:
        print("staleness-check: PyYAML is not installed, so .gitlab-ci.yml "
              "and supply-chain/staleness.yml cannot be parsed. Install it "
              "rather than skipping this check.", file=sys.stderr)
        raise SystemExit(2)


def load_gitlab_ci(path):
    """The parsed .gitlab-ci.yml, cached per path within one run."""
    if path not in _GITLAB_CI_CACHE:
        require_yaml()
        with open(path) as f:
            _GITLAB_CI_CACHE[path] = yaml.safe_load(f) or {}
    return _GITLAB_CI_CACHE[path]


_GITLAB_CI_CACHE = {}


# ---------------------------------------------------------------------------
# Fetching, real or replayed from an --upstream fixture
# ---------------------------------------------------------------------------

def _fetch_with_retry(url, headers, attempts=8):
    """GET url for real, retrying a 403/429 with backoff.

    Docker Hub's own web API sits behind bot-detection that occasionally
    -- not deterministically -- 403s a perfectly ordinary anonymous GET
    and then serves the identical request fine a moment later (confirmed
    by hand while building this check: the same URL passed on one try and
    failed on the next, with nothing about the request itself different).
    Treating that as a hard failure would make the report flap between
    runs for no reason connected to any dependency; a same-request retry
    with backoff is what "occasionally" calls for. A small pause before
    every Docker Hub request, not only a retried one, is the other half
    of the fix -- this check makes a couple of dozen paginated calls to
    it in a row (one image family can be over a thousand tags across
    several pages), and spacing them out is what keeps a burst from
    tripping the same protection in the first place.
    """
    import time
    if "hub.docker.com" in url:
        time.sleep(0.4)
    last = (False, None, "never attempted")
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                return (True, resp.read(), None)
        except urllib.error.HTTPError as e:
            last = (False, None, f"HTTP {e.code}")
            if e.code not in (403, 429) or attempt == attempts - 1:
                return last
            time.sleep(min(2.0 * (attempt + 1), 15.0))
        except urllib.error.URLError as e:
            return (False, None, str(e.reason))
        except Exception as e:  # noqa: BLE001 -- report, never crash the run
            return (False, None, str(e))
    return last


class Fetcher:
    """GET (or HEAD, for the registry digest check) a URL.

    Every other function in this file that needs the network goes through
    here, so --upstream can replace all of it in one place, and so a real
    run only ever pays for a given URL once.
    """

    def __init__(self, fixture_path=None):
        self.fixture = None
        if fixture_path:
            with open(fixture_path) as f:
                self.fixture = json.load(f)
        self._cache = {}

    def get(self, url, headers=None):
        """Return (ok, body_bytes_or_None, error_or_None)."""
        if url in self._cache:
            return self._cache[url]
        result = self._get_uncached(url, headers or {})
        self._cache[url] = result
        return result

    def _get_uncached(self, url, headers):
        if self.fixture is not None:
            if url not in self.fixture:
                return (False, None, f"not in --upstream fixture: {url}")
            entry = self.fixture[url]
            if isinstance(entry, dict) and "error" in entry:
                return (False, None, entry["error"])
            if isinstance(entry, dict) and "status" in entry:
                return (False, None, f"HTTP {entry['status']}")
            body = entry if isinstance(entry, str) else json.dumps(entry)
            return (True, body.encode("utf-8"), None)
        return _fetch_with_retry(url, headers)

    def head_digest(self, url, headers=None):
        """HEAD url and return (ok, digest_header_or_None, error).

        Only used by the registry digest check. Under --upstream, the
        fixture's value for this same URL is treated as the digest
        directly -- there is no header to fake, so the body stands in
        for it.
        """
        if self.fixture is not None:
            ok, body, err = self.get(url)
            if not ok:
                return (False, None, err)
            return (True, body.decode("utf-8").strip(), None)
        try:
            req = urllib.request.Request(url, headers=headers or {}, method="HEAD")
            with urllib.request.urlopen(req, timeout=30) as resp:
                digest = resp.headers.get("Docker-Content-Digest")
                if not digest:
                    return (False, None, "no Docker-Content-Digest header in response")
                return (True, digest, None)
        except urllib.error.HTTPError as e:
            return (False, None, f"HTTP {e.code}")
        except urllib.error.URLError as e:
            return (False, None, str(e.reason))
        except Exception as e:  # noqa: BLE001
            return (False, None, str(e))


def github_headers():
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    return {"Accept": "application/vnd.github+json"}


# ---------------------------------------------------------------------------
# Row
# ---------------------------------------------------------------------------

class Row:
    def __init__(self, id, pinned, latest="", status="unverifiable", note=""):
        self.id = id
        self.pinned = pinned
        self.latest = latest
        self.status = status
        self.note = note


def unverifiable(id, pinned, err):
    return Row(id, pinned, "", "unverifiable", err)


# ---------------------------------------------------------------------------
# Version parsing shared by the Go toolchain and container-image checks
# ---------------------------------------------------------------------------

_LEADING_NUM = re.compile(r"^(\d+(?:\.\d+)*)(.*)$")


def split_version(tag):
    """('1.27.0', '-alpine') for '1.27.0-alpine'; (None, tag) if no leading digit."""
    m = _LEADING_NUM.match(tag)
    if not m or not m.group(1):
        return None, tag
    nums = tuple(int(x) for x in m.group(1).split("."))
    return nums, m.group(2)


def padded(nums, length):
    return nums + (0,) * (length - len(nums))


def newest_in_family(candidates, suffix, fixed_prefix):
    """Highest numeric tuple among candidates sharing suffix and fixed_prefix.

    candidates: iterable of (nums, suffix) pairs, as split_version returns.
    Returns None if nothing matches.
    """
    subset = [
        nums
        for nums, sfx in candidates
        if nums is not None
        and sfx == suffix
        and nums[: len(fixed_prefix)] == fixed_prefix
    ]
    if not subset:
        return None
    maxlen = max(len(n) for n in subset)
    return max(subset, key=lambda n: padded(n, maxlen))


def compare_at_precision(pin_nums, target_nums):
    """True if target is strictly newer than pin at pin's own precision."""
    target_here = padded(target_nums, max(len(pin_nums), len(target_nums)))[: len(pin_nums)]
    pin_here = padded(pin_nums, len(target_here))
    return target_here > pin_here


def format_nums(nums, suffix=""):
    return ".".join(str(n) for n in nums) + suffix


def go_family_status(pin_raw, candidates, row_id):
    """Like family_status, but for bare Go versions (no suffix family --
    go.dev has no notion of a Docker tag's "-alpine"; a Dockerfile pin of
    "1.27.0-alpine" is compared as plain "1.27.0", with the Docker suffix
    kept only for display."""
    nums, _ = split_version(pin_raw)
    if nums is None:
        return Row(row_id, pin_raw, "", "floating", "no version component in the pin")

    fixed = nums[:-1]
    target = newest_in_family(candidates, "", fixed)
    if target is None:
        return unverifiable(row_id, pin_raw, "no matching Go release found upstream for this family")

    note = ""
    if len(fixed) >= 1:
        looser = fixed[:-1]
        wider = newest_in_family(candidates, "", looser)
        if wider is not None:
            wider_prefix = padded(wider, len(fixed))[: len(fixed)]
            if wider_prefix != fixed:
                note = f"newer Go line available: {format_nums(wider)}"

    if compare_at_precision(nums, target):
        return Row(row_id, pin_raw, format_nums(target), "behind", note)
    return Row(row_id, pin_raw, format_nums(target), "current", note)


def family_status(pin_tag, candidates, row_id):
    """Shared logic: pin_tag is the full tag/version string as written.

    Returns a Row with status current/behind/floating/unverifiable.
    """
    pin_nums, suffix = split_version(pin_tag)
    if pin_nums is None:
        return Row(row_id, pin_tag, "", "floating", "no version component in the pin")

    fixed = pin_nums[:-1]
    target = newest_in_family(candidates, suffix, fixed)
    if target is None:
        return unverifiable(row_id, pin_tag, "no matching tag found upstream for this family")

    note = ""
    if len(fixed) >= 1:
        # "AND reports if a newer minor exists" -- one level looser than
        # the fixed prefix used for the main comparison above.
        looser = fixed[:-1]
        wider = newest_in_family(candidates, suffix, looser)
        if wider is not None:
            wider_prefix = padded(wider, len(fixed))[: len(fixed)]
            if wider_prefix != fixed:
                note = f"newer line available in the same family: {format_nums(wider, suffix)}"

    if compare_at_precision(pin_nums, target):
        latest = format_nums(target, suffix)
        return Row(row_id, pin_tag, latest, "behind", note)
    return Row(row_id, pin_tag, format_nums(target, suffix), "current", note)


# ---------------------------------------------------------------------------
# Go toolchain
# ---------------------------------------------------------------------------

def go_dev_versions(fetcher):
    ok, body, err = fetcher.get("https://go.dev/dl/?mode=json")
    if not ok:
        return None, err
    try:
        data = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return None, f"bad JSON from go.dev/dl: {e}"
    candidates = []
    for entry in data:
        version = entry.get("version", "")
        if version.startswith("go"):
            version = version[2:]
        nums, suffix = split_version(version)
        if nums is not None:
            candidates.append((nums, ""))  # go.dev has no suffix family
    return candidates, None


def check_go_toolchain(root, fetcher):
    rows = []
    candidates, err = go_dev_versions(fetcher)

    def make(row_id, pin):
        if candidates is None:
            return unverifiable(row_id, pin, err)
        return go_family_status(pin, candidates, row_id)

    go_mod = os.path.join(root, "go.mod")
    if os.path.isfile(go_mod):
        with open(go_mod) as f:
            for line in f:
                m = re.match(r"^go\s+(\d+\.\d+(?:\.\d+)?)", line.strip())
                if m:
                    rows.append(make("go:go.mod", m.group(1)))
                    break

    ci_path = os.path.join(root, ".gitlab-ci.yml")
    seen_tarball = set()
    if os.path.isfile(ci_path):
        with open(ci_path) as f:
            text = f.read()
        m = re.search(r"GOLANG_IMAGE:.*?golang:([0-9][\w.\-]*)", text)
        if m:
            rows.append(make("go:.gitlab-ci.yml#GOLANG_IMAGE", m.group(1)))
        for m in re.finditer(r"go(\d+\.\d+(?:\.\d+)?)\.linux-amd64\.tar\.gz", text):
            if m.group(1) not in seen_tarball:
                seen_tarball.add(m.group(1))
                rows.append(make("go:test:smoke#tarball", m.group(1)))

    dockerfiles = find_dockerfiles(root)
    for path in dockerfiles:
        with open(path) as f:
            text = f.read()
        found = set()
        for m in re.finditer(r"golang:([0-9][\w.\-]*)", text):
            found.add(m.group(1))
        rel = os.path.relpath(path, root)
        for ver in sorted(found):
            rows.append(make(f"go:{rel}", ver))

    return rows


# ---------------------------------------------------------------------------
# Go modules (require block + go install lines)
# ---------------------------------------------------------------------------

def parse_go_mod_requires(path):
    """[(module, version)] for every direct (non-indirect) requirement."""
    out = []
    in_block = False
    with open(path) as f:
        for raw in f:
            line = raw.strip()
            if line.startswith("require ("):
                in_block = True
                continue
            if in_block:
                if line == ")":
                    in_block = False
                    continue
                if "// indirect" in line:
                    continue
                m = re.match(r"^(\S+)\s+(v\S+)", line)
                if m:
                    out.append((m.group(1), m.group(2)))
            else:
                m = re.match(r"^require\s+(\S+)\s+(v\S+)\s*$", line)
                if m and "// indirect" not in line:
                    out.append((m.group(1), m.group(2)))
    return out


def parse_go_installs(ci_text):
    """[(module_as_written, version)] for every `go install X@vY` line."""
    return re.findall(r"go install ([^\s@]+)@(v[0-9][^\s]*)", ci_text)


def go_proxy_latest(fetcher, module):
    """(version, err) from proxy.golang.org, resolving a subpackage path
    down to its containing module the way `go install` itself does."""
    path = module
    last_err = None
    while True:
        url = f"https://proxy.golang.org/{escape_module(path)}/@latest"
        ok, body, err = fetcher.get(url)
        if ok:
            try:
                data = json.loads(body)
                return data.get("Version"), None
            except Exception as e:  # noqa: BLE001
                return None, f"bad JSON from {url}: {e}"
        last_err = err
        if "/" not in path:
            return None, last_err
        path = path.rsplit("/", 1)[0]


def go_proxy_version_list(fetcher, module):
    url = f"https://proxy.golang.org/{escape_module(module)}/@v/list"
    ok, body, err = fetcher.get(url)
    if not ok:
        return None, err
    versions = [v.strip() for v in body.decode("utf-8").splitlines() if v.strip()]
    return versions, None


def escape_module(module):
    """proxy.golang.org's !lower escaping for uppercase letters."""
    return re.sub(r"([A-Z])", lambda m: "!" + m.group(1).lower(), module)


def semver_key(v):
    v = v[1:] if v.startswith("v") else v
    core, _, pre = v.partition("-")
    nums, _ = split_version(core)
    # Stable sorts after any prerelease of the same core version.
    return (nums or (0,), 0 if not pre else -1, pre)


def check_go_modules(root, fetcher):
    rows = []
    go_mod = os.path.join(root, "go.mod")
    modules = []
    if os.path.isfile(go_mod):
        modules.extend(parse_go_mod_requires(go_mod))

    ci_path = os.path.join(root, ".gitlab-ci.yml")
    if os.path.isfile(ci_path):
        with open(ci_path) as f:
            text = f.read()
        modules.extend(parse_go_installs(text))

    seen = set()
    for module, pinned in modules:
        if module in seen:
            continue
        seen.add(module)
        row_id = f"gomod:{module}"
        latest, err = go_proxy_latest(fetcher, module)
        if latest is None:
            rows.append(unverifiable(row_id, pinned, err))
            continue
        if latest == pinned:
            rows.append(Row(row_id, pinned, latest, "current"))
            continue
        if "-" in pinned.lstrip("v"):
            # Pinned to a pre-release: @latest alone may not surface the
            # newest one, so cross-check the full version list.
            versions, verr = go_proxy_version_list(fetcher, module)
            if versions is None:
                rows.append(unverifiable(row_id, pinned, verr))
                continue
            newest = max(versions, key=semver_key) if versions else latest
            if newest == pinned:
                rows.append(Row(row_id, pinned, newest, "current"))
                continue
            rows.append(Row(row_id, pinned, newest, "behind"))
            continue
        rows.append(Row(row_id, pinned, latest, "behind"))
    return rows


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

def check_npm(root, fetcher):
    rows = []
    pkg_json = os.path.join(root, "frontend", "package.json")
    lock_json = os.path.join(root, "frontend", "package-lock.json")
    if not (os.path.isfile(pkg_json) and os.path.isfile(lock_json)):
        return rows

    with open(pkg_json) as f:
        pkg = json.load(f)
    with open(lock_json) as f:
        lock = json.load(f)
    packages = lock.get("packages", {})

    names = list(pkg.get("dependencies", {}).keys()) + list(pkg.get("devDependencies", {}).keys())
    for name in names:
        row_id = f"npm:{name}"
        installed = packages.get(f"node_modules/{name}", {}).get("version")
        if installed is None:
            rows.append(unverifiable(row_id, "(not in package-lock.json)",
                                      "no node_modules/<name> entry in package-lock.json"))
            continue
        url = f"https://registry.npmjs.org/{name}/latest"
        ok, body, err = fetcher.get(url)
        if not ok:
            rows.append(unverifiable(row_id, installed, err))
            continue
        try:
            latest = json.loads(body).get("version")
        except Exception as e:  # noqa: BLE001
            rows.append(unverifiable(row_id, installed, f"bad JSON from {url}: {e}"))
            continue
        if latest == installed:
            rows.append(Row(row_id, installed, latest, "current"))
            continue
        installed_nums, _ = split_version(installed)
        latest_nums, _ = split_version(latest)
        if installed_nums is not None and latest_nums is not None and latest_nums > installed_nums:
            rows.append(Row(row_id, installed, latest, "behind"))
        else:
            rows.append(Row(row_id, installed, latest, "current",
                             "differs from latest but does not parse as newer"))
    return rows


# ---------------------------------------------------------------------------
# PyPI (build/opencanary/requirements.txt)
# ---------------------------------------------------------------------------

def check_pypi(root, fetcher):
    rows = []
    req_path = os.path.join(root, "build", "opencanary", "requirements.txt")
    if not os.path.isfile(req_path):
        return rows
    with open(req_path) as f:
        text = f.read()
    for name, version in re.findall(r"^([A-Za-z0-9_.\-]+)==([A-Za-z0-9_.\-]+)", text, re.M):
        row_id = f"pypi:{name}"
        url = f"https://pypi.org/pypi/{name}/json"
        ok, body, err = fetcher.get(url)
        if not ok:
            rows.append(unverifiable(row_id, version, err))
            continue
        try:
            latest = json.loads(body).get("info", {}).get("version")
        except Exception as e:  # noqa: BLE001
            rows.append(unverifiable(row_id, version, f"bad JSON from {url}: {e}"))
            continue
        if not latest:
            rows.append(unverifiable(row_id, version, f"no info.version in response from {url}"))
            continue
        if latest == version:
            rows.append(Row(row_id, version, latest, "current"))
            continue
        pinned_nums, _ = split_version(version)
        latest_nums, _ = split_version(latest)
        if pinned_nums is not None and latest_nums is not None and latest_nums > pinned_nums:
            rows.append(Row(row_id, version, latest, "behind"))
        else:
            rows.append(Row(row_id, version, latest, "current",
                             "differs from latest but does not parse as newer"))
    return rows


# ---------------------------------------------------------------------------
# Container image tags
# ---------------------------------------------------------------------------

def find_dockerfiles(root):
    out = []
    build_dir = os.path.join(root, "build")
    if not os.path.isdir(build_dir):
        return out
    for name in sorted(os.listdir(build_dir)):
        path = os.path.join(build_dir, name, "Dockerfile")
        if os.path.isfile(path):
            out.append(path)
    return out


def dockerfile_from_lines(path):
    """[(image_ref, stage_alias_or_None)] for every literal FROM line.

    Skips `FROM ${...}` (an ARG substitution -- BASE_IMAGE and friends;
    no literal tag sits at this line for this check to compare) and `FROM
    <earlier-stage-name>` (not an external image at all).
    """
    aliases = set()
    out = []
    with open(path) as f:
        for raw in f:
            m = re.match(r"^\s*FROM\s+(\S+)(?:\s+[Aa][Ss]\s+(\S+))?", raw)
            if not m:
                continue
            ref, alias = m.group(1), m.group(2)
            if ref.startswith("${") or ref in aliases:
                if alias:
                    aliases.add(alias)
                continue
            if alias:
                aliases.add(alias)
            out.append(ref)
    return out


def image_ci_vars(ci_doc):
    """{'NODE_IMAGE': 'node:22-trixie', ...} for every literal `*_IMAGE:` var
    in the file's top-level `variables:` block.

    Deliberately scoped to that one block, not every `*_IMAGE:`-shaped key
    anywhere in the file: a job's own `variables:` carries things like
    `E2E_POISONER_FIXTURE_IMAGE: poisoner-fixture:pinned`, a purely local
    retag name (scripts/ci-ensure-image.sh's own bookkeeping), not an
    upstream pin -- it looks exactly like one from a bare regex over the
    raw text, and querying Docker Hub for a repository named
    "poisoner-fixture" is how that was found. Excludes GOLANG_IMAGE
    (routed to the Go toolchain check instead) and any `*_IMAGE:`
    variable whose value is itself another CI variable
    (E2E_BIRDCAGE_IMAGE: $BIRDCAGE_BUILD_IMAGE and friends, also at job
    level and also not real pins).
    """
    out = {}
    prefix = "${CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX}/"
    variables = ci_doc.get("variables") if isinstance(ci_doc, dict) else None
    if not isinstance(variables, dict):
        return out
    for var, value in variables.items():
        if not (isinstance(var, str) and var.endswith("_IMAGE") and isinstance(value, str)):
            continue
        if var == "GOLANG_IMAGE":
            continue
        if value.startswith(prefix):
            value = value[len(prefix):]
        if value.startswith("library/"):
            value = value[len("library/"):]
        if "$" in value or ":" not in value:
            continue
        out[var] = value
    return out


def docker_hub_tag_exists(fetcher, repo, tag):
    """(True/False, err). err is set only when the check itself failed --
    a confirmed absence (404) is a clean False, not an error."""
    url = f"https://hub.docker.com/v2/repositories/{repo}/tags/{urllib.parse.quote(tag)}"
    ok, body, err = fetcher.get(url)
    if ok:
        return True, None
    if err == "HTTP 404":
        return False, None
    return None, err


def docker_hub_walk(fetcher, repo, fixed, start_last, suffix, cap=300):
    """The highest value V such that fixed+(V,) (with suffix) exists,
    starting from a value already confirmed to exist and probing
    upward one release at a time.

    Docker Hub's own tag *listing* endpoint refuses to page past its
    1000th result (a 403, not a 429 -- confirmed by hand while building
    this check: harmless-looking anonymous pagination into a large
    repository's tag list, like node's or python's own "-alpine" family,
    hits it deterministically), which a broad cross-major search like
    this one runs into every time. The single-tag existence endpoint
    used here has no such wall, and probing "does the next release
    exist yet" is also just a better fit for what this check actually
    needs: not the whole list, only whether anything is newer than the
    pin. Software version numbers in every family this check covers
    increment by exactly one at the level being walked (no skipped
    majors, minors or patches), so this never has to guess how far to
    look -- it stops at the first gap.
    """
    v = start_last
    for _ in range(cap):
        tag = format_nums(fixed + (v + 1,), suffix)
        exists, err = docker_hub_tag_exists(fetcher, repo, tag)
        if exists is None:
            return None, err
        if not exists:
            return fixed + (v,), None
        v += 1
    return fixed + (v,), None


def gcr_tag_list(fetcher, repo):
    url = f"https://gcr.io/v2/{repo}/tags/list"
    ok, body, err = fetcher.get(url)
    if not ok:
        return None, err
    try:
        data = json.loads(body)
    except Exception as e:  # noqa: BLE001
        return None, f"bad JSON from {url}: {e}"
    return data.get("tags", []), None


def hub_repo_path(repo):
    return repo if "/" in repo else f"library/{repo}"


def check_one_image(fetcher, repo, tag):
    row_id = f"image:{repo}:{tag}"
    pin_nums, suffix = split_version(tag)

    if repo.startswith("gcr.io/"):
        gcr_repo = repo[len("gcr.io/"):]
        tags, err = gcr_tag_list(fetcher, gcr_repo)
        if tags is None:
            return unverifiable(row_id, tag, err)
        if pin_nums is None:
            note = "" if tag in tags else "not present in current tag listing"
            return Row(row_id, tag, "", "floating", note)
        candidates = [split_version(t) for t in tags]
        return family_status(tag, candidates, row_id)

    hub_repo = hub_repo_path(repo)

    if pin_nums is None:
        exists, err = docker_hub_tag_exists(fetcher, hub_repo, tag)
        if exists is None:
            return unverifiable(row_id, tag, err)
        note = "" if exists else "not present in current tag listing"
        return Row(row_id, tag, "", "floating", note)

    fixed = pin_nums[:-1]
    exists, err = docker_hub_tag_exists(fetcher, hub_repo, tag)
    if exists is None:
        return unverifiable(row_id, tag, err)
    if not exists:
        return unverifiable(
            row_id, tag,
            f"{tag} is not currently a tag of {hub_repo} on Docker Hub -- cannot walk forward from it")

    target, err = docker_hub_walk(fetcher, hub_repo, fixed, pin_nums[-1], suffix)
    if target is None:
        return unverifiable(row_id, tag, err)

    note = ""
    if len(fixed) >= 1:
        # "AND reports if a newer minor exists" (see the module
        # docstring): one probe, one level looser, filling the newly
        # freed component with 0 -- a new release line's own first
        # version. Informational only, so a miss here never fails the row.
        looser_next = fixed[:-1] + (fixed[-1] + 1,) + (0,) * (len(pin_nums) - len(fixed))
        wider_tag = format_nums(looser_next, suffix)
        wexists, _ = docker_hub_tag_exists(fetcher, hub_repo, wider_tag)
        if wexists:
            note = f"newer line available in the same family: {wider_tag}"

    if compare_at_precision(pin_nums, target):
        return Row(row_id, tag, format_nums(target, suffix), "behind", note)
    return Row(row_id, tag, format_nums(target, suffix), "current", note)


def check_images(root, fetcher):
    rows = []
    seen = set()

    dockerfiles = find_dockerfiles(root)
    for path in dockerfiles:
        for ref in dockerfile_from_lines(path):
            if ref.startswith("golang:") or ":" not in ref:
                continue
            repo, tag = ref.rsplit(":", 1)
            if (repo, tag) in seen:
                continue
            seen.add((repo, tag))
            rows.append(check_one_image(fetcher, repo, tag))

    ci_path = os.path.join(root, ".gitlab-ci.yml")
    if os.path.isfile(ci_path):
        for var, ref in image_ci_vars(load_gitlab_ci(ci_path)).items():
            repo, tag = ref.rsplit(":", 1)
            if (repo, tag) in seen:
                continue
            seen.add((repo, tag))
            rows.append(check_one_image(fetcher, repo, tag))

    return rows


# ---------------------------------------------------------------------------
# apk pins
# ---------------------------------------------------------------------------

def dockerfile_alpine_branch(path):
    """'v3.24' from this Dockerfile's own literal `FROM alpine:X.Y`, or None."""
    with open(path) as f:
        for raw in f:
            m = re.match(r"^\s*FROM\s+alpine:(\d+\.\d+)", raw)
            if m:
                return "v" + m.group(1)
    return None


def apkindex_versions(fetcher, branch, repo):
    url = f"https://dl-cdn.alpinelinux.org/alpine/{branch}/{repo}/x86_64/APKINDEX.tar.gz"
    ok, body, err = fetcher.get(url)
    if not ok:
        return None, err
    try:
        tf = tarfile.open(fileobj=io.BytesIO(body), mode="r:gz")
        data = tf.extractfile("APKINDEX").read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return None, f"could not read APKINDEX from {url}: {e}"
    versions = {}
    name = None
    for line in data.splitlines():
        if line == "":
            name = None
            continue
        if line.startswith("P:"):
            name = line[2:]
        elif line.startswith("V:") and name:
            versions[name] = line[2:]
    return versions, None


def logical_lines(text):
    """Join backslash line continuations, so a multi-line `RUN apk add \\`
    is seen as the one line it actually is."""
    out = []
    buf = ""
    for line in text.splitlines():
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
        else:
            out.append(buf + line)
            buf = ""
    if buf:
        out.append(buf)
    return out


def check_apk(root, fetcher, alpine_branch_config):
    rows = []
    for path in find_dockerfiles(root):
        rel = os.path.relpath(path, root)
        with open(path) as f:
            text = f.read()
        pins = []
        for line in logical_lines(text):
            if "apk add" not in line:
                continue
            pins.extend(re.findall(
                r"\b([a-zA-Z0-9][a-zA-Z0-9_+.\-]*)=([0-9][\w.\-]*)", line))
        if not pins:
            continue

        branch = dockerfile_alpine_branch(path) or alpine_branch_config.get(rel)
        for name, version in pins:
            row_id = f"apk:{name}"
            if branch is None:
                rows.append(unverifiable(
                    row_id, version,
                    f"{rel} has no literal FROM alpine:X.Y and no alpine-branch: "
                    f"entry for it in supply-chain/staleness.yml"))
                continue

            found_version = None
            found_err = None
            for repo_name in ("main", "community"):
                versions, err = apkindex_versions(fetcher, branch, repo_name)
                if versions is None:
                    found_err = err
                    continue
                if name in versions:
                    found_version = versions[name]
                    break
            if found_version is None:
                rows.append(unverifiable(row_id, version, found_err or
                                          f"{name} not found in {branch} main/community APKINDEX"))
                continue
            if found_version == version:
                rows.append(Row(row_id, version, found_version, "current"))
            else:
                rows.append(Row(row_id, version, found_version, "behind"))
    return rows


# ---------------------------------------------------------------------------
# Checksum-pinned tools: cosign, gitleaks, grype
# ---------------------------------------------------------------------------

def github_latest_release(fetcher, owner_repo):
    url = f"https://api.github.com/repos/{owner_repo}/releases/latest"
    ok, body, err = fetcher.get(url, headers=github_headers())
    if not ok:
        return None, err
    try:
        return json.loads(body).get("tag_name"), None
    except Exception as e:  # noqa: BLE001
        return None, f"bad JSON from {url}: {e}"


def github_newest_semver_tag(fetcher, owner_repo):
    url = f"https://api.github.com/repos/{owner_repo}/tags?per_page=100"
    ok, body, err = fetcher.get(url, headers=github_headers())
    if not ok:
        return None, err
    try:
        tags = [t["name"] for t in json.loads(body)]
    except Exception as e:  # noqa: BLE001
        return None, f"bad JSON from {url}: {e}"
    semver = [t for t in tags if re.match(r"^v?\d+\.\d+\.\d+$", t)]
    if not semver:
        return None, f"no full semver tag found in {url}"
    return max(semver, key=semver_key), None


def read_version_var(path, var):
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        m = re.search(rf'^{var}="?([^"\n]+)"?', f.read(), re.M)
    return m.group(1) if m else None


def check_tools(root, fetcher):
    rows = []

    cosign_pin = read_version_var(os.path.join(root, "scripts", "ensure-cosign.sh"), "COSIGN_VERSION")
    if cosign_pin:
        latest, err = github_latest_release(fetcher, "sigstore/cosign")
        rows.append(_tool_row("tool:cosign", cosign_pin, latest, err))

    gitleaks_pin = read_version_var(os.path.join(root, "scripts", "ensure-gitleaks.sh"), "GITLEAKS_VERSION")
    if gitleaks_pin:
        latest, err = github_latest_release(fetcher, "gitleaks/gitleaks")
        rows.append(_tool_row("tool:gitleaks", gitleaks_pin, latest, err))

    nightjar_dockerfile = os.path.join(root, "build", "nightjar", "Dockerfile")
    if os.path.isfile(nightjar_dockerfile):
        with open(nightjar_dockerfile) as f:
            m = re.search(r"^ARG GRYPE_VERSION=([\w.\-]+)", f.read(), re.M)
        if m:
            grype_pin = "v" + m.group(1)
            latest, err = github_latest_release(fetcher, "anchore/grype")
            rows.append(_tool_row("tool:grype", grype_pin, latest, err))

    return rows


def _tool_row(row_id, pinned, latest, err):
    if latest is None:
        return unverifiable(row_id, pinned, err)
    if latest == pinned:
        return Row(row_id, pinned, latest, "current")
    return Row(row_id, pinned, latest, "behind")


# ---------------------------------------------------------------------------
# SHA-pinned GitHub Actions
# ---------------------------------------------------------------------------

def check_actions(root, fetcher):
    rows = []
    workflows_dir = os.path.join(root, ".github", "workflows")
    if not os.path.isdir(workflows_dir):
        return rows

    seen_repo = {}
    for name in sorted(os.listdir(workflows_dir)):
        if not name.endswith((".yml", ".yaml")):
            continue
        with open(os.path.join(workflows_dir, name)) as f:
            text = f.read()
        for m in re.finditer(
            r"uses:\s*([\w.\-]+/[\w.\-]+(?:/[\w.\-]+)*)@([0-9a-fA-F]{40})\s*#\s*(v[0-9][\w.\-]*)",
            text,
        ):
            uses_path, sha, comment_version = m.group(1), m.group(2), m.group(3)
            row_id = f"action:{uses_path}"
            owner_repo = "/".join(uses_path.split("/")[:2])
            if owner_repo not in seen_repo:
                seen_repo[owner_repo] = github_newest_semver_tag(fetcher, owner_repo)
            latest, err = seen_repo[owner_repo]
            if latest is None:
                rows.append(unverifiable(row_id, comment_version, err))
                continue
            latest_norm = latest if latest.startswith("v") else "v" + latest
            pinned_norm = comment_version if comment_version.startswith("v") else "v" + comment_version
            if latest_norm == pinned_norm:
                rows.append(Row(row_id, pinned_norm, latest_norm, "current"))
            else:
                rows.append(Row(row_id, pinned_norm, latest_norm, "behind"))
    return rows


# ---------------------------------------------------------------------------
# The Responder fixture digest
# ---------------------------------------------------------------------------

def check_registry_fixture(root, fetcher):
    ci_path = os.path.join(root, ".gitlab-ci.yml")
    if not os.path.isfile(ci_path):
        return []
    with open(ci_path) as f:
        text = f.read()
    m = re.search(r"E2E_POISONER_FIXTURE_DIGEST:\s*(\S+)@(sha256:[0-9a-f]+)", text)
    if not m:
        return []
    repo_ref, pinned_digest = m.group(1), m.group(2)
    row_id = "fixture:poisoner"

    registry, repo = repo_ref.split("/", 1)
    if not (os.environ.get("CI_REGISTRY_USER") and os.environ.get("CI_REGISTRY_PASSWORD")):
        if fetcher.fixture is None:
            return [unverifiable(row_id, pinned_digest,
                                  "CI_REGISTRY_USER/CI_REGISTRY_PASSWORD not set -- "
                                  "cannot authenticate to the registry from here")]

    manifest_url = f"https://{registry}/v2/{repo}/manifests/latest"

    if fetcher.fixture is not None:
        ok, digest, err = fetcher.head_digest(manifest_url)
        if not ok:
            return [unverifiable(row_id, pinned_digest, err)]
        return [Row(row_id, pinned_digest, digest, "current" if digest == pinned_digest else "behind")]

    ok, body, err = fetcher.get(f"https://{registry}/v2/")
    challenge = None
    if not ok and err and err.startswith("HTTP 401"):
        # urllib's HTTPError swallows the body/headers by the time we get
        # here via Fetcher.get; redo the request directly to read the
        # WWW-Authenticate challenge.
        try:
            req = urllib.request.Request(f"https://{registry}/v2/")
            urllib.request.urlopen(req, timeout=30)
        except urllib.error.HTTPError as e:
            challenge = e.headers.get("WWW-Authenticate")
    if not challenge:
        return [unverifiable(row_id, pinned_digest, "could not read the registry's auth challenge")]

    m2 = re.search(r'realm="([^"]+)".*service="([^"]+)"', challenge)
    if not m2:
        return [unverifiable(row_id, pinned_digest, f"unrecognised auth challenge: {challenge}")]
    realm, service = m2.group(1), m2.group(2)
    user = os.environ.get("CI_REGISTRY_USER")
    password = os.environ.get("CI_REGISTRY_PASSWORD")
    if not (user and password):
        return [unverifiable(row_id, pinned_digest,
                              "CI_REGISTRY_USER/CI_REGISTRY_PASSWORD not set -- "
                              "cannot authenticate to the registry from here")]

    token_url = f"{realm}?service={urllib.parse.quote(service)}&scope=repository:{repo}:pull"
    try:
        req = urllib.request.Request(token_url)
        auth = f"{user}:{password}".encode()
        import base64
        req.add_header("Authorization", "Basic " + base64.b64encode(auth).decode())
        with urllib.request.urlopen(req, timeout=30) as resp:
            token = json.loads(resp.read()).get("token")
    except Exception as e:  # noqa: BLE001
        return [unverifiable(row_id, pinned_digest, f"could not get a registry token: {e}")]
    if not token:
        return [unverifiable(row_id, pinned_digest, "no token in registry auth response")]

    accept = ("application/vnd.oci.image.index.v1+json, "
              "application/vnd.oci.image.manifest.v1+json, "
              "application/vnd.docker.distribution.manifest.list.v2+json, "
              "application/vnd.docker.distribution.manifest.v2+json")
    ok, digest, err = fetcher.head_digest(
        manifest_url, headers={"Authorization": f"Bearer {token}", "Accept": accept})
    if not ok:
        return [unverifiable(row_id, pinned_digest, err)]
    return [Row(row_id, pinned_digest, digest, "current" if digest == pinned_digest else "behind")]


# ---------------------------------------------------------------------------
# Config: supply-chain/staleness.yml
# ---------------------------------------------------------------------------

def load_config(root):
    path = os.path.join(root, "supply-chain", "staleness.yml")
    if not os.path.isfile(path):
        return {"accepted": [], "unchecked": [], "alpine-branch": {}}
    require_yaml()
    with open(path) as f:
        doc = yaml.safe_load(f) or {}
    return {
        "accepted": doc.get("accepted") or [],
        "unchecked": doc.get("unchecked") or [],
        "alpine-branch": doc.get("alpine-branch") or {},
    }


def apply_config(rows, config, today):
    accepted_by_id = {}
    for entry in config["accepted"]:
        accepted_by_id.setdefault(entry["pin"], []).append(entry)
    unchecked_by_id = {entry["pin"]: entry for entry in config["unchecked"]}

    ok = True
    for row in rows:
        for entry in accepted_by_id.get(row.id, []):
            if row.pinned != entry.get("held-at"):
                continue
            review_by = datetime.date.fromisoformat(str(entry["review-by"]))
            if today > review_by:
                continue
            row.status = "accepted"
            row.note = (f"accepted: {entry['reason']} "
                        f"(held at {entry['held-at']}, review by {entry['review-by']})")
            break

        if row.status == "unverifiable" and row.id in unchecked_by_id:
            entry = unchecked_by_id[row.id]
            extra = f"unchecked: {entry['reason']}"
            row.note = f"{row.note}; {extra}" if row.note else extra
        elif row.status in ("behind", "unverifiable"):
            ok = False
    return ok


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def render_table(rows):
    lines = ["| row | pinned | latest | status | note |",
             "| --- | --- | --- | --- | --- |"]
    for row in sorted(rows, key=lambda r: r.id):
        cells = [row.id, row.pinned, row.latest, row.status, row.note]
        cells = [c.replace("|", "\\|").replace("\n", " ") for c in cells]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def summary_line(rows):
    counts = {}
    for row in rows:
        counts[row.status] = counts.get(row.status, 0) + 1
    parts = ", ".join(f"{n} {status}" for status, n in sorted(counts.items()))
    return f"staleness-check: {len(rows)} row(s) -- {parts}"


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv):
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=".")
    parser.add_argument("--report")
    parser.add_argument("--upstream")
    parser.add_argument("--today")
    args = parser.parse_args(argv[1:])

    root = args.root
    fetcher = Fetcher(args.upstream)
    today = (datetime.date.fromisoformat(args.today) if args.today
             else datetime.date.today())
    config = load_config(root)

    rows = []
    rows += check_go_toolchain(root, fetcher)
    rows += check_go_modules(root, fetcher)
    rows += check_npm(root, fetcher)
    rows += check_pypi(root, fetcher)
    rows += check_images(root, fetcher)
    rows += check_apk(root, fetcher, config["alpine-branch"])
    rows += check_tools(root, fetcher)
    rows += check_actions(root, fetcher)
    rows += check_registry_fixture(root, fetcher)

    ok = apply_config(rows, config, today)

    table = render_table(rows)
    summary = summary_line(rows)
    output = table + "\n\n" + summary + "\n"

    print(output)
    if args.report:
        with open(args.report, "w") as f:
            f.write(output)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
