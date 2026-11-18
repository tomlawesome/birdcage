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
    to a pre-release, `@v/list` too). The owner's own modules
    (`github.com/tomlawesome/*`) are the exception, per ADR-0016 decision
    1: a lookup through proxy.golang.org or sum.golang.org records the
    version there permanently, which is publishing it, so these are
    never sent to the proxy. They are compared against the newest `vX.Y.Z`
    tag (of the module's own major) in GitHub's tags API instead, and
    go_proxy_latest/go_proxy_version_list refuse an owner module outright.
  - Direct npm packages: names from frontend/package.json, installed
    versions from frontend/package-lock.json -- compared against
    registry.npmjs.org's `/latest`.
  - build/opencanary/requirements.txt's `name==ver` lines -- compared
    against pypi.org's JSON API.
  - Container image tags: every `FROM` in build/*/Dockerfile and every
    `*_IMAGE:` variable and literal `services:` image in .gitlab-ci.yml
    (golang: handled above, not here; `name:tag@digest` and
    `name@digest` pins read too) -- compared within the same tag family (same suffix, same
    precision) against Docker Hub or gcr.io's own registry API.
  - `apk add name=ver` pins -- compared against the APKINDEX of the
    pinning Dockerfile's own Alpine branch.
  - Checksum-pinned tools (cosign, gitleaks, grype) -- compared against
    each project's GitHub "latest release". SHA-pinned GitHub Actions
    `uses:` lines -- compared against that repo's newest semver tag.
  - The Responder fixture digest pinned in .gitlab-ci.yml -- the private
    fixtures project publishes it only under a version tag (no
    `latest`), so this lists the repository's tags, picks the newest
    `vN.N...` one, and compares that tag's own manifest digest against
    the pin (needs CI_REGISTRY_USER/PASSWORD; unverifiable without
    them).

Every row gets a status: `current`, `behind`, `floating` (no version
component in the pin at all -- never "behind"), `accepted` (a `behind` or
`unverifiable` row covered by supply-chain/staleness.yml's `accepted:`
list, while the pin still matches `held-at` and today is not after
`review-by`), or `unverifiable` (the upstream could not be reached or
parsed). `behind` and `unverifiable` both fail the run unless covered by
the config -- a check that cannot check must not pass.

Usage:
  scripts/staleness-check.py [--root DIR] [--report PATH] [--json PATH]
                              [--timeout SECONDS] [--deadline SECONDS]
                              [--upstream FIXTURE.json] [--today YYYY-MM-DD]

--timeout is the limit on each network call (default 30 s). --deadline is
the limit on the whole run: retries never sleep past it, and a fetch after
it returns "deadline reached", so that row is `unverifiable` (#215: the
release-readiness check passes 10 and 300).

--json PATH writes every row as JSON for scripts/release-readiness.py:
id, pinned, latest, status, note, and where known `released` (the date
the oldest version newer than the pin was published -- read from the
registry's own answer, or for Go and GitHub tags from the Git host's commit
date, never from the Go proxy; a row dated only by its latest version
carries a date only when that is the pin's next patch; an image row never
carries one, since Docker Hub's tag date moves on every rebuild), `file` (the Dockerfile of an apk pin), `credential_missing`
(unverifiable only because a CI credential is absent) and `hold` (a hold
in supply-chain/staleness.yml that names this row but no longer applies:
{lapsed: expired | held-at-differs, review_by, held_at}). A release date
is looked up only for a `behind` row; a lookup that fails leaves it out,
and the readiness check counts a missing date as old.

`apk add` pins may be exact (`name=ver`) or fuzzy (`name~=ver`, shown
pinned as `~=ver`): a fuzzy pin is current when the index version starts
with `ver` at a version-component boundary.

An `unchecked:` entry excuses its row only with a `review-by` date that
has not passed, like an `accepted:` hold (#215, D11).

--upstream replaces every network fetch: the fixture JSON maps the exact
URL touched to either a response body (a string), `{"status": N}` for a
non-200 response, or `{"error": "..."}` for a transport failure. A URL
this script would touch but that is missing from the fixture is itself an
error -- so the fixture doubles as a list of everything the check reaches
out to. Without --upstream, every fetch is real. A fixture entry
`{"delay": SECONDS, "body": ...}` answers after that delay (the body is
optional; without one it is an HTTP 200 with `{}`), so a test can drive
--deadline.

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


def _ci_loader():
    """SafeLoader that accepts GitLab's `!reference [job, key]` tag."""
    class Loader(yaml.SafeLoader):
        pass
    Loader.add_constructor(
        "!reference", lambda l, n: {"!reference": l.construct_sequence(n)})
    return Loader


def load_gitlab_ci(path):
    """The parsed .gitlab-ci.yml, cached per path within one run."""
    if path not in _GITLAB_CI_CACHE:
        require_yaml()
        with open(path) as f:
            _GITLAB_CI_CACHE[path] = yaml.load(f, Loader=_ci_loader()) or {}
    return _GITLAB_CI_CACHE[path]


_GITLAB_CI_CACHE = {}


# ---------------------------------------------------------------------------
# Fetching, real or replayed from an --upstream fixture
# ---------------------------------------------------------------------------

# Per-call and whole-run time limits (--timeout, --deadline). Every network
# call in this file asks _call_timeout() for its limit, so nothing can wait
# past the run's deadline.
_LIMITS = {"timeout": 30.0, "deadline_at": None}


class DeadlineReached(Exception):
    pass


# The most any one response may be (#215 review): the largest documents
# read are full npm package documents (vite's was 39 MB on 2026-11-18). A
# bigger answer is a failure, and is not read past the limit.
MAX_BODY = 64 * 1024 * 1024
# Headers that carry a credential: never sent to a host the request was not
# addressed to (#215 review). urllib copies request headers onto a redirect.
_CREDENTIAL_HEADERS = ("authorization", "private-token")


class ResponseTooLarge(Exception):
    pass


def _read_capped(resp, limit=None):
    """resp.read(), refusing (ResponseTooLarge) anything over the limit
    without reading the rest."""
    limit = MAX_BODY if limit is None else limit
    length = resp.headers.get("Content-Length")
    if length and length.isdigit() and int(length) > limit:
        raise ResponseTooLarge(f"response of {length} bytes is over the {limit}-byte limit")
    body = resp.read(limit + 1)
    if len(body) > limit:
        raise ResponseTooLarge(f"response is over the {limit}-byte limit")
    return body


class _SameHostCredentials(urllib.request.HTTPRedirectHandler):
    """Follow redirects, dropping credential headers when the host changes."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and (urllib.parse.urlsplit(newurl).netloc.lower()
                                != urllib.parse.urlsplit(req.full_url).netloc.lower()):
            for name in list(new.headers):
                if name.lower() in _CREDENTIAL_HEADERS:
                    del new.headers[name]
            for name in list(new.unredirected_hdrs):
                if name.lower() in _CREDENTIAL_HEADERS:
                    del new.unredirected_hdrs[name]
        return new


_OPENER = urllib.request.build_opener(_SameHostCredentials())


def urlopen(req, timeout):
    """The one way this file opens a URL: the redirect rule above applies."""
    return _OPENER.open(req, timeout=timeout)


def _remaining():
    """Seconds left before the run's deadline, or None without one."""
    import time
    if _LIMITS["deadline_at"] is None:
        return None
    return _LIMITS["deadline_at"] - time.monotonic()


def _call_timeout():
    """The time limit for the next network call; raises DeadlineReached
    once the run's deadline has passed."""
    left = _remaining()
    if left is None:
        return _LIMITS["timeout"]
    if left <= 0:
        raise DeadlineReached()
    return max(0.1, min(_LIMITS["timeout"], left))


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
            timeout = _call_timeout()
        except DeadlineReached:
            return (False, None, "deadline reached")
        try:
            req = urllib.request.Request(url, headers=headers)
            with urlopen(req, timeout=timeout) as resp:
                return (True, _read_capped(resp), None)
        except urllib.error.HTTPError as e:
            last = (False, None, f"HTTP {e.code}")
            if e.code not in (403, 429) or attempt == attempts - 1:
                return last
            pause = min(2.0 * (attempt + 1), 15.0)
            left = _remaining()
            if left is not None and left <= pause:
                return (False, None, f"{last[2]}; deadline reached before a retry")
            time.sleep(pause)
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
            try:
                _call_timeout()
            except DeadlineReached:
                return (False, None, "deadline reached")
            if url not in self.fixture:
                return (False, None, f"not in --upstream fixture: {url}")
            entry = self.fixture[url]
            if isinstance(entry, dict) and "delay" in entry:
                import time
                left = _remaining()
                delay = float(entry["delay"])
                if left is not None and delay >= left:
                    time.sleep(max(0.0, left))
                    return (False, None, "deadline reached")
                time.sleep(delay)
                entry = entry.get("body", "{}")
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
            with urlopen(req, timeout=_call_timeout()) as resp:
                digest = resp.headers.get("Docker-Content-Digest")
                if not digest:
                    return (False, None, "no Docker-Content-Digest header in response")
                return (True, digest, None)
        except DeadlineReached:
            return (False, None, "deadline reached")
        except urllib.error.HTTPError as e:
            return (False, None, f"HTTP {e.code}")
        except urllib.error.URLError as e:
            return (False, None, str(e.reason))
        except Exception as e:  # noqa: BLE001
            return (False, None, str(e))

    def get_tags_list(self, first_url, headers=None):
        """GET a Docker Registry `tags/list` endpoint. Returns (ok, tags, err).

        Follows the registry's own Link-header pagination (`<url>;
        rel="next"`), one page at a time, for a real run.

        Under --upstream there is exactly one page: the fixture's value
        for this URL is treated as the whole tags/list response body --
        there is no Link header to fake, so a fixture-replayed run never
        exercises pagination, the same simplification head_digest makes
        for the Docker-Content-Digest header.
        """
        if self.fixture is not None:
            ok, body, err = self.get(first_url)
            if not ok:
                return (False, None, err)
            try:
                data = json.loads(body)
            except Exception as e:  # noqa: BLE001
                return (False, None, f"bad JSON from {first_url}: {e}")
            return (True, data.get("tags", []), None)

        tags = []
        url = first_url
        seen = set()
        while url:
            if url in seen:
                return (False, None, f"pagination loop reading tags/list from {first_url}")
            seen.add(url)
            try:
                req = urllib.request.Request(url, headers=headers or {})
                with urlopen(req, timeout=_call_timeout()) as resp:
                    body = _read_capped(resp)
                    link = resp.headers.get("Link")
            except DeadlineReached:
                return (False, None, "deadline reached")
            except urllib.error.HTTPError as e:
                return (False, None, f"HTTP {e.code}")
            except urllib.error.URLError as e:
                return (False, None, str(e.reason))
            except Exception as e:  # noqa: BLE001
                return (False, None, str(e))
            try:
                data = json.loads(body)
            except Exception as e:  # noqa: BLE001
                return (False, None, f"bad JSON from {url}: {e}")
            tags.extend(data.get("tags", []))
            url = _next_page_url(url, link)
        return (True, tags, None)


def _next_page_url(current_url, link_header):
    """Absolute URL of the next tags/list page named in a registry
    `Link` response header (`<...>; rel="next"`), or None."""
    if not link_header:
        return None
    m = re.match(r'^\s*<([^>]+)>\s*;\s*rel="next"', link_header)
    if not m:
        return None
    return urllib.parse.urljoin(current_url, m.group(1))


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
        # --json extras (#215); see the module docstring.
        self.released = None
        self.date_hint = None   # how to look up `released` for a behind row
        self.file = None
        self.credential_missing = False
        self.hold = None

    def as_json(self):
        out = {"id": self.id, "pinned": self.pinned, "latest": self.latest,
               "status": self.status, "note": self.note}
        if self.released:
            out["released"] = self.released
        if self.file:
            out["file"] = self.file
        if self.credential_missing:
            out["credential_missing"] = True
        if self.hold:
            out["hold"] = self.hold
        return out


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
        row = go_family_status(pin, candidates, row_id)
        lo, _ = split_version(pin)
        hi, _ = split_version(row.latest or "")
        if row.status == "behind" and lo and hi:
            # go.dev/dl carries no dates; the Go repository's own tag does.
            # The oldest version newer than the pin (#215, 49b).
            newer = sorted(n for n, _ in candidates if lo < n <= hi)
            if newer:
                row.date_hint = ("github_commit", "golang/go",
                                 "go" + ".".join(str(n) for n in newer[0]))
        return row

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


OWNER_MODULE_PREFIX = "github.com/tomlawesome/"


def is_owner_module(module):
    """True for a module path under the owner's GitHub account.

    Matches the way GOPRIVATE does: the prefix `github.com/tomlawesome/`
    followed by a path element. Compared case-insensitively, so a
    differently-cased spelling can never slip through to the proxy.
    """
    m = module.lower()
    return m.startswith(OWNER_MODULE_PREFIX) and len(m) > len(OWNER_MODULE_PREFIX)


def _refuse_owner_module(module):
    # An explicit raise, not `assert`, so `python -O` cannot strip it.
    if is_owner_module(module):
        raise RuntimeError(
            f"refusing to look up owner module {module} through proxy.golang.org "
            "(ADR-0016 decision 1: a proxy lookup publishes the version permanently)"
        )


def owner_module_repo_and_major(module):
    """('gauntlet', 2) for github.com/tomlawesome/gauntlet/v2/sub.

    The repository is the path element right after the owner prefix; a
    subpackage path never changes it. A trailing `/vN` (N >= 2) element is
    the module's major version; without one the module is v0/v1 (None).
    """
    parts = module[len(OWNER_MODULE_PREFIX):].split("/")
    major = None
    for el in parts[1:]:
        m = re.match(r"^v([2-9]|[1-9][0-9]+)$", el)
        if m:
            major = int(m.group(1))
    return parts[0], major


def owner_module_latest(fetcher, module):
    """(version, err): newest `vX.Y.Z` tag of the module's major, read from
    GitHub's tags API -- never from the Go proxy (ADR-0016 decision 1)."""
    repo, major = owner_module_repo_and_major(module)
    url = f"https://api.github.com/repos/tomlawesome/{repo}/tags?per_page=100"
    ok, body, err = fetcher.get(url, headers=github_headers())
    if not ok:
        return None, err
    try:
        tags = [t["name"] for t in json.loads(body)]
    except Exception as e:  # noqa: BLE001
        return None, f"bad JSON from {url}: {e}"
    want = (0, 1) if major is None else (major,)
    semver = []
    for t in tags:
        m = re.match(r"^v(\d+)\.\d+\.\d+$", t)
        if m and int(m.group(1)) in want:
            semver.append(t)
    if not semver:
        return None, f"no full vX.Y.Z tag for {module} found in {url}"
    return max(semver, key=semver_key), None


def go_proxy_latest(fetcher, module):
    """(version, err) from proxy.golang.org, resolving a subpackage path
    down to its containing module the way `go install` itself does.

    Refuses an owner module (see is_owner_module)."""
    _refuse_owner_module(module)
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
    _refuse_owner_module(module)
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
        if is_owner_module(module):
            # ADR-0016 decision 1: never the proxy. Git host tags only.
            latest, err = owner_module_latest(fetcher, module)
            if latest is None:
                rows.append(unverifiable(row_id, pinned, err))
            elif latest == pinned:
                rows.append(Row(row_id, pinned, latest, "current"))
            else:
                row = Row(row_id, pinned, latest, "behind")
                repo, _ = owner_module_repo_and_major(module)
                if is_patch_successor(pinned, latest):
                    row.date_hint = ("github_commit", f"tomlawesome/{repo}", latest)
                rows.append(row)
            continue
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
            row = Row(row_id, pinned, newest, "behind")
            if is_patch_successor(pinned, newest):
                row.date_hint = go_module_git_tag(module, newest)
            rows.append(row)
            continue
        row = Row(row_id, pinned, latest, "behind")
        if is_patch_successor(pinned, latest):
            row.date_hint = go_module_git_tag(module, latest)
        rows.append(row)
    return rows


def go_module_git_tag(module, version):
    """("github_commit", owner/repo, tag) naming the Git host tag of a
    module version, for its release date (#215) -- the Git host, never the
    Go proxy -- or None where the host is not GitHub. golang.org/x/<name>
    is mirrored at github.com/golang/<name>. A module in a subdirectory of
    its repository tags as <subdir>/<version>; a /vN suffix is not a
    directory."""
    parts = module.split("/")
    if module.startswith("golang.org/x/") and len(parts) >= 3:
        owner_repo, rest = f"golang/{parts[2]}", parts[3:]
    elif module.startswith("github.com/") and len(parts) >= 3:
        owner_repo, rest = f"{parts[1]}/{parts[2]}", parts[3:]
    else:
        return None
    if rest and re.match(r"^v[2-9][0-9]*$|^v[1-9][0-9]+$", rest[-1]):
        rest = rest[:-1]
    tag = "/".join(rest + [version]) if rest else version
    return ("github_commit", owner_repo, tag)


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
            row = Row(row_id, installed, latest, "behind")
            row.date_hint = ("npm", name, installed, latest)
            rows.append(row)
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
            data = json.loads(body)
            latest = data.get("info", {}).get("version")
        except Exception as e:  # noqa: BLE001
            rows.append(unverifiable(row_id, version, f"bad JSON from {url}: {e}"))
            continue
        releases = data.get("releases") or {}
        dates = {}
        for v, files in releases.items():
            stamps = sorted(f.get("upload_time_iso_8601") for f in (files or [])
                            if isinstance(f, dict) and f.get("upload_time_iso_8601"))
            dates[v] = stamps[0] if stamps else None
        if not latest:
            rows.append(unverifiable(row_id, version, f"no info.version in response from {url}"))
            continue
        if latest == version:
            rows.append(Row(row_id, version, latest, "current"))
            continue
        pinned_nums, _ = split_version(version)
        latest_nums, _ = split_version(latest)
        if pinned_nums is not None and latest_nums is not None and latest_nums > pinned_nums:
            row = Row(row_id, version, latest, "behind")
            released = oldest_newer_date(dates, version, latest)
            if released:
                row.date_hint = ("value", released)
            rows.append(row)
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
    # Docker Hub images are named plainly (the runner's Docker mirrors Docker
    # Hub through the image cache, ai/agent-infra#14); the one prefix still
    # understood is the Docker Hub cache host. $CI_IMAGE_CACHE_GHCR / _MCR
    # names are not Docker Hub images and fall to the "$" skip below.
    variables = ci_doc.get("variables") if isinstance(ci_doc, dict) else None
    if not isinstance(variables, dict):
        return out
    for var, value in variables.items():
        if not (isinstance(var, str) and var.endswith("_IMAGE") and isinstance(value, str)):
            continue
        if var == "GOLANG_IMAGE":
            continue
        value = strip_hub_cache(value)
        if "$" in value or ":" not in value:
            continue
        out[var] = value
    return out


def strip_hub_cache(value):
    """value without a leading Docker Hub cache prefix or `library/`."""
    for prefix in ("${CI_IMAGE_CACHE_DOCKERHUB}/", "$CI_IMAGE_CACHE_DOCKERHUB/"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    if value.startswith("library/"):
        value = value[len("library/"):]
    return value


def image_ci_services(ci_doc):
    """Literal image refs named by any job's (or `default:`'s) `services:`
    list -- a plain string or a mapping's `name:` -- with the Docker Hub
    cache prefix stripped. Refs still holding a `$` are other CI variables
    (`$POSTGRES18_IMAGE`), already covered by image_ci_vars, and skipped.
    """
    out = []
    if not isinstance(ci_doc, dict):
        return out
    for job in ci_doc.values():
        services = job.get("services") if isinstance(job, dict) else None
        if not isinstance(services, list):
            continue
        for entry in services:
            name = entry.get("name") if isinstance(entry, dict) else entry
            if not isinstance(name, str):
                continue
            name = strip_hub_cache(name)
            if "$" in name or ":" not in name:
                continue
            out.append(name)
    return out


def split_image_ref(ref):
    """(repo, tag_or_None, digest_or_None) for `repo:tag`, `repo:tag@digest`
    or `repo@digest` (#226: the digest's own `sha256:` colon is not the
    tag separator). A `:` before the last `/` is a registry port."""
    ref, _, digest = ref.partition("@")
    repo, tag = ref, None
    if ":" in ref.rsplit("/", 1)[-1]:
        repo, tag = ref.rsplit(":", 1)
    return repo, tag, digest or None


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


def docker_hub_walk(fetcher, repo, fixed, start_last, suffix, cap=300, gap=3):
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
    pin.

    The walk tolerates `gap` consecutive missing numbers before it
    stops, because a family's numbers are not always contiguous: the
    version increments by one, but a tag only exists where that version
    and that suffix overlapped in time. `node:23-trixie` never existed
    (Node 23 reached end of life before Debian trixie shipped) while
    `node:24-trixie`, `25-trixie` and `26-trixie` all do, so a walk
    that stopped at the first miss reported `node:22-trixie` as current
    -- found on the first live run of this check, 2026-09-27, and the
    reason this paragraph exists. Every extra probe is one cheap HEAD-
    sized GET, so the tolerance costs `gap` requests per row, once.
    """
    best = start_last
    v = start_last
    misses = 0
    for _ in range(cap):
        v += 1
        tag = format_nums(fixed + (v,), suffix)
        exists, err = docker_hub_tag_exists(fetcher, repo, tag)
        if exists is None:
            return None, err
        if exists:
            best = v
            misses = 0
            continue
        misses += 1
        if misses > gap:
            break
    return fixed + (best,), None


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


def check_one_image(fetcher, repo, tag, digest=None):
    if tag is None:
        # Pinned by digest alone: nothing to compare a version against.
        return Row(f"image:{repo}", digest, "", "floating", "pinned by digest only")
    row = _check_one_image(fetcher, repo, tag)
    if digest:
        row.pinned = f"{tag}@{digest}"
    return row


def _check_one_image(fetcher, repo, tag):
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
        row = Row(row_id, tag, format_nums(target, suffix), "behind", note)
        # No date_hint: Docker Hub's tag date moves on every rebuild of an
        # official image, so it is not a release date (#215 review). A newer
        # image version always counts as newer.
        return row
    return Row(row_id, tag, format_nums(target, suffix), "current", note)


def check_images(root, fetcher):
    rows = []
    seen = set()

    def add(ref):
        repo, tag, digest = split_image_ref(ref)
        if (repo, tag) in seen:
            return
        seen.add((repo, tag))
        rows.append(check_one_image(fetcher, repo, tag, digest))

    dockerfiles = find_dockerfiles(root)
    for path in dockerfiles:
        for ref in dockerfile_from_lines(path):
            if ref.startswith("golang:") or ":" not in ref:
                continue
            add(ref)

    ci_path = os.path.join(root, ".gitlab-ci.yml")
    if os.path.isfile(ci_path):
        ci_doc = load_gitlab_ci(ci_path)
        for ref in image_ci_vars(ci_doc).values():
            add(ref)
        for ref in image_ci_services(ci_doc):
            add(ref)

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
            # `name=ver` exact, `name~=ver` fuzzy (#215: git~=2.54 in
            # build/birdcage/Dockerfile produced no row before).
            pins.extend(re.findall(
                r"\b([a-zA-Z0-9][a-zA-Z0-9_+.\-]*)(~?=)([0-9][\w.\-]*)", line))
        if not pins:
            continue

        branch = dockerfile_alpine_branch(path) or alpine_branch_config.get(rel)
        for name, op, version in pins:
            row_id = f"apk:{name}"
            shown = version if op == "=" else "~=" + version

            def add(row):
                row.file = rel
                rows.append(row)

            if branch is None:
                add(unverifiable(
                    row_id, shown,
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
                add(unverifiable(row_id, shown, found_err or
                                 f"{name} not found in {branch} main/community APKINDEX"))
                continue
            if apk_pin_matches(op, version, found_version):
                add(Row(row_id, shown, found_version, "current"))
            else:
                add(Row(row_id, shown, found_version, "behind"))
    return rows


def apk_pin_matches(op, pinned, found):
    """An exact pin matches only itself; a fuzzy `~=` pin matches a version
    that starts with it at a component boundary (2.54 matches 2.54.1-r0,
    not 2.541)."""
    if op == "=" or found == pinned:
        return found == pinned
    if not found.startswith(pinned):
        return False
    return not found[len(pinned)].isdigit()


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
        rows.append(_tool_row("tool:cosign", cosign_pin, latest, err, "sigstore/cosign"))

    gitleaks_pin = read_version_var(os.path.join(root, "scripts", "ensure-gitleaks.sh"), "GITLEAKS_VERSION")
    if gitleaks_pin:
        latest, err = github_latest_release(fetcher, "gitleaks/gitleaks")
        rows.append(_tool_row("tool:gitleaks", gitleaks_pin, latest, err, "gitleaks/gitleaks"))

    nightjar_dockerfile = os.path.join(root, "build", "nightjar", "Dockerfile")
    if os.path.isfile(nightjar_dockerfile):
        with open(nightjar_dockerfile) as f:
            m = re.search(r"^ARG GRYPE_VERSION=([\w.\-]+)", f.read(), re.M)
        if m:
            grype_pin = "v" + m.group(1)
            latest, err = github_latest_release(fetcher, "anchore/grype")
            rows.append(_tool_row("tool:grype", grype_pin, latest, err, "anchore/grype"))

    return rows


def _tool_row(row_id, pinned, latest, err, owner_repo=None):
    if latest is None:
        return unverifiable(row_id, pinned, err)
    if latest == pinned:
        return Row(row_id, pinned, latest, "current")
    row = Row(row_id, pinned, latest, "behind")
    if owner_repo and is_patch_successor(pinned, latest):
        row.date_hint = ("github_release", owner_repo)
    return row


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
            row_id = f"action:{uses_path}#{name}"
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
                row = Row(row_id, pinned_norm, latest_norm, "behind")
                if is_patch_successor(pinned_norm, latest_norm):
                    row.date_hint = ("github_commit", owner_repo, latest)
                rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# The Responder fixture digest
# ---------------------------------------------------------------------------

_VERSION_TAG = re.compile(r"^v(\d+(?:\.\d+)*)$")


def parse_version_tag(tag):
    """Numeric tuple for a tag shaped like v1.2.3(.4...), any number of
    components, or None for a tag with any other shape -- this
    repository's tags are a released tool's own version strings, not
    always a version (e.g. a build tag), and only version tags order
    meaningfully."""
    m = _VERSION_TAG.match(tag)
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def newest_version_tag(tags):
    """(tag_name, nums) for the highest-numbered version tag among
    `tags`, or (None, None) if none of them parse as one."""
    parsed = [(tag, parse_version_tag(tag)) for tag in tags]
    parsed = [(tag, nums) for tag, nums in parsed if nums is not None]
    if not parsed:
        return None, None
    maxlen = max(len(nums) for _, nums in parsed)
    return max(parsed, key=lambda tn: padded(tn[1], maxlen))


def _credential_missing(row):
    """Mark a row unverifiable only because a CI credential is absent here:
    the readiness check reports it UNCHECKED locally, FAIL in CI."""
    row.credential_missing = True
    return row


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

    # The pin names the registry as $CI_REGISTRY, which GitLab expands in
    # the job; expand it the same way here (set in every CI job).
    m3 = re.match(r"\$(?:\{CI_REGISTRY\}|CI_REGISTRY(?![A-Za-z0-9_]))", repo_ref)
    if m3:
        ci_registry = os.environ.get("CI_REGISTRY")
        if not ci_registry:
            return [_credential_missing(unverifiable(
                row_id, pinned_digest,
                "CI_REGISTRY not set -- cannot tell which registry the pin names"))]
        repo_ref = ci_registry + repo_ref[m3.end():]

    registry, repo = repo_ref.split("/", 1)
    if not (os.environ.get("CI_REGISTRY_USER") and os.environ.get("CI_REGISTRY_PASSWORD")):
        if fetcher.fixture is None:
            return [_credential_missing(unverifiable(
                row_id, pinned_digest,
                "CI_REGISTRY_USER/CI_REGISTRY_PASSWORD not set -- "
                "cannot authenticate to the registry from here"))]

    accept = ("application/vnd.oci.image.index.v1+json, "
              "application/vnd.oci.image.manifest.v1+json, "
              "application/vnd.docker.distribution.manifest.list.v2+json, "
              "application/vnd.docker.distribution.manifest.v2+json")

    if fetcher.fixture is not None:
        auth_headers = {}
    else:
        ok, body, err = fetcher.get(f"https://{registry}/v2/")
        challenge = None
        if not ok and err and err.startswith("HTTP 401"):
            # urllib's HTTPError swallows the body/headers by the time we get
            # here via Fetcher.get; redo the request directly to read the
            # WWW-Authenticate challenge.
            try:
                req = urllib.request.Request(f"https://{registry}/v2/")
                urlopen(req, timeout=_call_timeout()).close()
            except urllib.error.HTTPError as e:
                challenge = e.headers.get("WWW-Authenticate")
            except Exception:  # noqa: BLE001 -- deadline or transport: no challenge
                challenge = None
        if not challenge:
            return [unverifiable(row_id, pinned_digest, "could not read the registry's auth challenge")]

        m2 = re.search(r'realm="([^"]+)".*service="([^"]+)"', challenge)
        if not m2:
            return [unverifiable(row_id, pinned_digest, f"unrecognised auth challenge: {challenge}")]
        realm, service = m2.group(1), m2.group(2)
        user = os.environ.get("CI_REGISTRY_USER")
        password = os.environ.get("CI_REGISTRY_PASSWORD")
        if not (user and password):
            return [_credential_missing(unverifiable(
                row_id, pinned_digest,
                "CI_REGISTRY_USER/CI_REGISTRY_PASSWORD not set -- "
                "cannot authenticate to the registry from here"))]

        token_url = f"{realm}?service={urllib.parse.quote(service)}&scope=repository:{repo}:pull"
        try:
            req = urllib.request.Request(token_url)
            auth = f"{user}:{password}".encode()
            import base64
            req.add_header("Authorization", "Basic " + base64.b64encode(auth).decode())
            with urlopen(req, timeout=_call_timeout()) as resp:
                token = json.loads(_read_capped(resp, 1024 * 1024)).get("token")
        except Exception as e:  # noqa: BLE001
            return [unverifiable(row_id, pinned_digest, f"could not get a registry token: {e}")]
        if not token:
            return [unverifiable(row_id, pinned_digest, "no token in registry auth response")]
        auth_headers = {"Authorization": f"Bearer {token}"}

    tags_url = f"https://{registry}/v2/{repo}/tags/list"
    ok, tags, err = fetcher.get_tags_list(tags_url, headers=auth_headers)
    if not ok:
        return [unverifiable(row_id, pinned_digest, err)]

    newest_tag, _ = newest_version_tag(tags or [])
    if newest_tag is None:
        return [unverifiable(row_id, pinned_digest,
                              f"no version tag (vN.N...) found among this repository's tags: {tags_url}")]

    manifest_url = f"https://{registry}/v2/{repo}/manifests/{newest_tag}"
    ok, digest, err = fetcher.head_digest(
        manifest_url, headers={**auth_headers, "Accept": accept})
    if not ok:
        return [unverifiable(row_id, pinned_digest, err)]
    # The upstream column shows the newest tag name, not the raw digest,
    # so a human reading the report knows what to move the pin to --
    # whichever way this compares.
    return [Row(row_id, pinned_digest, newest_tag, "current" if digest == pinned_digest else "behind")]


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


def _add_note(row, extra):
    row.note = f"{row.note}; {extra}" if row.note else extra


def apply_config(rows, config, today):
    accepted_by_id = {}
    for entry in config["accepted"]:
        accepted_by_id.setdefault(entry["pin"], []).append(entry)
    unchecked_by_id = {entry["pin"]: entry for entry in config["unchecked"]}

    ok = True
    for row in rows:
        lapsed = None
        for entry in accepted_by_id.get(row.id, []):
            review_by = datetime.date.fromisoformat(str(entry["review-by"]))
            if row.pinned != entry.get("held-at"):
                lapsed = lapsed or {"lapsed": "held-at-differs",
                                    "review_by": str(entry["review-by"]),
                                    "held_at": str(entry.get("held-at"))}
                continue
            if today > review_by:
                lapsed = {"lapsed": "expired", "review_by": str(entry["review-by"]),
                          "held_at": str(entry.get("held-at"))}
                continue
            row.status = "accepted"
            row.note = (f"accepted: {entry['reason']} "
                        f"(held at {entry['held-at']}, review by {entry['review-by']})")
            lapsed = None
            break
        if lapsed and row.status in ("behind", "unverifiable"):
            # Said out loud (#215): a hold that stopped applying used to be
            # skipped without a word.
            row.hold = lapsed
            if lapsed["lapsed"] == "expired":
                _add_note(row, f"hold expired on {lapsed['review_by']}")
            else:
                _add_note(row, f"hold is for {lapsed['held_at']}, not this pin")

        if row.status == "unverifiable" and row.id in unchecked_by_id:
            entry = unchecked_by_id[row.id]
            review_by = entry.get("review-by")
            if not review_by:
                # 42c/D11: anything excused needs a reason and a date.
                _add_note(row, "unchecked entry has no review-by, so it excuses nothing")
                ok = False
            elif today > datetime.date.fromisoformat(str(review_by)):
                _add_note(row, f"unchecked entry expired on {review_by}")
                ok = False
            else:
                _add_note(row, f"unchecked: {entry['reason']} (review by {review_by})")
        elif row.status in ("behind", "unverifiable"):
            ok = False
    return ok


# ---------------------------------------------------------------------------
# Release dates of the newer versions (#215 cooldown)
# ---------------------------------------------------------------------------

def _date_from(body, *keys):
    try:
        data = json.loads(body)
    except Exception:  # noqa: BLE001
        return None
    for key in keys:
        cur = data
        for part in key.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        if isinstance(cur, str) and re.match(r"^\d{4}-\d{2}-\d{2}", cur):
            return cur
    return None


def release_date(fetcher, hint):
    """The publish date of a row's `latest`, or None when it cannot be
    read. Best effort by design: a missing date counts as old in the
    readiness check, so a failed lookup can only make it stricter."""
    kind = hint[0]
    if kind == "value":
        return hint[1]
    if kind == "github_commit":
        _, owner_repo, tag = hint
        url = (f"https://api.github.com/repos/{owner_repo}/commits/"
               f"{urllib.parse.quote(tag, safe='')}")
        ok, body, _ = fetcher.get(url, headers=github_headers())
        return _date_from(body, "commit.committer.date") if ok else None
    if kind == "github_release":
        url = f"https://api.github.com/repos/{hint[1]}/releases/latest"
        ok, body, _ = fetcher.get(url, headers=github_headers())
        return _date_from(body, "published_at") if ok else None
    if kind == "npm":
        # ("npm", name, version): that version's date; ("npm", name,
        # pinned, latest): the oldest version newer than the pin.
        name = hint[1]
        ok, body, _ = fetcher.get(f"https://registry.npmjs.org/{name}")
        if not ok:
            return None
        try:
            doc = json.loads(body)
        except Exception:  # noqa: BLE001
            return None
        times = doc.get("time") or {}
        if len(hint) == 3:
            when = times.get(hint[2])
            return when if isinstance(when, str) else None
        _, _, pinned, latest = hint
        versions = set(times) | set(doc.get("versions") or {})
        return oldest_newer_date({v: times.get(v) for v in versions}, pinned, latest)
    return None


def oldest_newer_date(dates, pinned, latest):
    """The date of the oldest stable version newer than `pinned`, up to
    `latest` (#215, 49b: the pin is behind once any newer version is 14+
    days old). dates maps version -> ISO date or None. A newer version
    with no date makes the answer None, which the readiness check counts
    as old."""
    lo, _ = split_version(pinned)
    hi, _ = split_version(latest)
    if lo is None or hi is None:
        return None
    found = []
    for v, when in dates.items():
        nums, suffix = split_version(v)
        if nums is None or suffix or not (lo < nums <= hi):
            continue
        if not (isinstance(when, str) and re.match(r"^\d{4}-\d{2}-\d{2}", when)):
            return None
        found.append(when)
    return min(found) if found else None


def is_patch_successor(pinned, latest):
    """True when latest is the next patch of pinned (1.2.3 -> 1.2.4), the one
    case where latest is known to be the only newer version, so its date is
    the oldest newer one's. Otherwise a row dated only by its latest version
    carries no date: undated counts as old (#215, 49b)."""
    a, _ = split_version(pinned.lstrip("v"))
    b, _ = split_version(latest.lstrip("v"))
    return (a is not None and b is not None and len(a) == len(b) == 3
            and a[:2] == b[:2] and b[2] == a[2] + 1)


def add_release_dates(rows, fetcher):
    for row in rows:
        if row.status == "behind" and row.date_hint:
            row.released = release_date(fetcher, row.date_hint)


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
    parser.add_argument("--json", dest="json_path")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--deadline", type=float)
    args = parser.parse_args(argv[1:])

    import time
    if args.timeout <= 0 or (args.deadline is not None and args.deadline <= 0):
        parser.error("--timeout and --deadline must be positive")
    _LIMITS["timeout"] = args.timeout
    if args.deadline is not None:
        _LIMITS["deadline_at"] = time.monotonic() + args.deadline

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

    add_release_dates(rows, fetcher)
    ok = apply_config(rows, config, today)

    table = render_table(rows)
    summary = summary_line(rows)
    output = table + "\n\n" + summary + "\n"

    print(output)
    if args.report:
        with open(args.report, "w") as f:
            f.write(output)
    if args.json_path:
        with open(args.json_path, "w") as f:
            json.dump({"today": today.isoformat(),
                       "rows": [r.as_json() for r in sorted(rows, key=lambda r: r.id)]},
                      f, indent=1)
            f.write("\n")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
