#!/usr/bin/env python3
"""Gate the licences of the pip packages installed for the OpenCanary image.

Companion to scripts/licence-check.sh (Go modules linked into the
Birdcage binary) and scripts/licence-check-npm.py (the npm tree under
frontend/node_modules). This one covers build/opencanary/requirements.txt
-- pip packages installed straight into the distroless OpenCanary image
(build/opencanary/Dockerfile's "honeypot" stage; moved out of mockingbird
by issue #132, unchanged otherwise), the one ecosystem that had no
licence gate at all before #95.

requirements.txt itself carries no licence information -- pip-compile's
output is a name, a version and a set of hashes, nothing else -- so there
is no way to gate it without installing the packages and reading what
each one's own metadata says. That is what this script does: it is
handed a directory of already-installed packages (scripts/licence-check-
python.sh runs the actual `pip install --require-hashes`; tests point
this script straight at fixture dist-info directories instead) and reads
each package's *.dist-info/METADATA.

Real installed packages in this exact requirements.txt disagree with each
other about how to say the same thing, so three fields are all read, and
a package passes if ANY of them names an allowed licence:

  - License-Expression: the modern field (PEP 639), an SPDX expression.
    A compound "X OR Y" (e.g. cryptography's "Apache-2.0 OR BSD-3-Clause")
    is split into alternatives -- either satisfies the licence, same as
    OR in any dual-licensed package. A compound "X AND Y" is kept as one
    string and must match the allow-list exactly, deliberately: both
    parts would need to apply, and silently splitting it would treat an
    unreviewed combination as pre-approved (see supply-chain/licence-
    policy.yml's note on why the Go list does not need an x/sys-shaped
    exception).
  - Classifier: lines of the form "License :: OSI Approved :: MIT
    License" -- present on many packages that also carry a useless raw
    License field (automat's raw License: field is literally "Copyright
    (c) 2014"; its classifier correctly says MIT).
  - License: the old free-text field. Sometimes a clean SPDX-shaped
    string (idna: "BSD-3-Clause"), sometimes prose, sometimes the literal
    placeholder "UNKNOWN" that distutils used to fill in for anything
    unspecified -- treated as no licence at all, not as a licence named
    "UNKNOWN".

A package with none of the three is "no licence field", exactly like
npm's checker, not skipped and not passed -- and, when it has one, the
offender message also names any bundled licence file it found (a
License-File: header, or a LICENSE* file at the top of its dist-info
directory or its licenses/ subdirectory), so whoever reviews it next
knows where to read the actual text. That is a better error message
only: this script never reads or interprets what such a file says.

Some real installed packages' own metadata is not something this
project can accept as-is (hpfeeds' bundled LICENSE is GPLv3). Rather
than adding their licence to the allow-list above -- which would accept
it for every package, not just the one reviewed -- supply-chain/licence-policy.yml
also has an allow-python-package-licenses: list of named, version-pinned
exceptions ("<name>@<version> <SPDX-id>"), read by
read_package_allow_list below. A package matching one exactly passes as
that recorded SPDX id regardless of what its own metadata says; bumping
its version stops the entry matching, on purpose, so the gate fires
again and the new version gets its own review. An exception that
matches no installed package is itself a failure, so the list cannot
accumulate stale, unneeded entries silently.

A package's declared licence covers its own code, not everything it
carries (#179). Two things inside a package are checked as well:

  - Vendored packages: a *.dist-info directory found anywhere below the
    top level (setuptools ships twelve under setuptools/_vendor/) is
    checked by exactly the rules above, labelled with the package that
    carries it. Its name@version is what an allow-python-package-licenses
    exception must name.
  - Bundled assets: every image, stylesheet, script, web page, feed or
    font file a package installs (read from its RECORD, so only files
    that package put there) must sit under a reviewed entry in the
    policy's python-bundled-assets: list -- "<name>@<version>
    <path-prefix> <licence>". These files carry no licence field at all,
    which is how OpenCanary's nasLogin skin (Synology images, Sencha Ext
    JS stylesheets) passed as "BSD" for a year. An unreviewed asset fails;
    an entry matching no installed file is stale and fails too. A version
    bump stops the entries matching, on purpose, the same as the
    exceptions above.

Usage: scripts/licence-check-python.py <packages_dir> <policy_file>
Exit codes:
  0 every installed and vendored package's licence is on the allow-list
    or matches a named allow-python-package-licenses exception, and every
    bundled asset is under a reviewed python-bundled-assets entry
  1 a disallowed licence, a missing licence field, an unreadable
    METADATA or missing RECORD file, an empty/unparseable allow-list, an
    unreviewed bundled asset, or a named exception or asset review that
    matched nothing installed
  2 packages_dir does not exist (fail red, never quietly green, if the
    install step never ran)
"""
import csv
import os
import re
import sys


def read_allow_list(policy_file):
    """Pull the `allow-python-licenses:` list out of the policy YAML.

    Same deliberately-not-a-YAML-parser approach as licence-check-npm.py's
    read_allow_list, and the same reason for a distinct key: this must
    not collide with allow-licenses: (matched by a bare prefix in
    licence-check.sh's awk) or allow-npm-licenses:.
    """
    if not os.path.isfile(policy_file):
        return None
    allowed = []
    in_list = False
    with open(policy_file) as f:
        for line in f:
            stripped = line.rstrip("\n")
            if stripped.startswith("allow-python-licenses:"):
                in_list = True
                continue
            if in_list and stripped and not stripped[0].isspace():
                break
            if in_list:
                text = stripped.strip()
                if text.startswith("- "):
                    entry = text[2:].split(" #", 1)[0].strip()
                    if entry:
                        allowed.append(entry)
    return allowed


def read_package_allow_list(policy_file):
    """Pull the `allow-python-package-licenses:` list out of the policy YAML.

    Named, version-pinned exceptions: a specific package at a specific
    version that has been individually reviewed and accepted under a
    specific SPDX licence, rather than that licence being added to
    allow-python-licenses: above for every package. Same hand-rolled
    parsing shape as read_allow_list, and the same collision concern:
    this key must never be matched by the prefix matching another gate
    uses to find its own key. It is safe against all three:
      - read_allow_list above, matched by `startswith("allow-python-
        licenses:")`: "allow-python-package-licenses:" does not start
        with that string -- the two diverge right after "allow-python-"
        ("p" vs "l"), so neither is a prefix of the other.
      - licence-check-npm.py's read_allow_list, matched by
        `startswith("allow-npm-licenses:")`: does not match, same reason
        ("p" vs "n" right after "allow-").
      - licence-check.sh's awk, anchored `/^allow-licenses:/`: does not
        match -- this key does not start with "allow-licenses:" at all.

    Each entry is "<name>@<version> <SPDX-id>" -- name@version is the
    label name_and_version() below builds for an installed package. The
    name matches after PEP 503 normalisation (match_key() below), the
    version only exactly; bumping the package's version is enough to
    stop it matching, which is intended (see the module docstring). Returns a
    dict of name@version -> SPDX id, or None if the policy file itself
    is unreadable.
    """
    if not os.path.isfile(policy_file):
        return None
    allowed = {}
    in_list = False
    with open(policy_file) as f:
        for line in f:
            stripped = line.rstrip("\n")
            if stripped.startswith("allow-python-package-licenses:"):
                in_list = True
                continue
            if in_list and stripped and not stripped[0].isspace():
                break
            if in_list:
                text = stripped.strip()
                if text.startswith("- "):
                    entry = text[2:].split(" #", 1)[0].strip()
                    if entry:
                        name_version, _, spdx_id = entry.partition(" ")
                        spdx_id = spdx_id.strip()
                        if name_version and spdx_id:
                            allowed[name_version] = spdx_id
    return allowed


def find_dist_info_dirs(packages_dir):
    """Find every installed package's dist-info directory.

    `pip install --target` lays every package straight into the target
    directory (unlike node_modules, there is no nesting to walk): each
    installed distribution gets one `<name>-<version>.dist-info` child.
    Only that shape is recognised -- the older `.egg-info` layout is not,
    because nothing in this project's requirements.txt produces it (every
    package here installs from a wheel); a package that somehow did would
    be silently invisible to this check rather than failing it, which is
    worth knowing if this script is ever pointed at a different
    requirements file.
    """
    dirs = []
    if not os.path.isdir(packages_dir):
        return dirs
    for name in sorted(os.listdir(packages_dir)):
        if not name.endswith(".dist-info"):
            continue
        path = os.path.join(packages_dir, name)
        if os.path.isdir(path):
            dirs.append(path)
    return dirs


# File types a package can carry that have no licence field of their own
# and are the usual vehicle for someone else's work: images, web pages,
# stylesheets, scripts, feeds and fonts. Python source, data and config
# files are deliberately not on this list -- they are the package's own
# code far more often than not, and listing them would drown the few
# real findings in reviews of every package's own .txt and .json.
ASSET_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".webp",
    ".css", ".js", ".html", ".htm", ".rss",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".swf", ".mp3", ".wav", ".mp4",
}


def read_asset_reviews(policy_file):
    """Pull the `python-bundled-assets:` list out of the policy YAML.

    Each entry is "<name>@<version> <path-prefix> <licence>": a reviewed
    directory (or file) of bundled assets inside one exact package
    version, with the licence or finding recorded for it. Returns a list
    of (name@version, prefix, licence) tuples, or None if the policy file
    is unreadable. Same hand-rolled parsing as the readers above; the key
    starts with "python-", so none of the three gates' allow-* prefix
    matches can mistake it for their own.
    """
    if not os.path.isfile(policy_file):
        return None
    reviews = []
    in_list = False
    with open(policy_file) as f:
        for line in f:
            stripped = line.rstrip("\n")
            if stripped.startswith("python-bundled-assets:"):
                in_list = True
                continue
            if in_list and stripped and not stripped[0].isspace():
                break
            if in_list:
                text = stripped.strip()
                if text.startswith("- "):
                    entry = text[2:].split(" #", 1)[0].strip()
                    parts = entry.split(None, 2)
                    if len(parts) == 3:
                        reviews.append((parts[0], parts[1], parts[2]))
    return reviews


def find_vendored_dist_info_dirs(packages_dir):
    """Find dist-info directories nested inside installed packages.

    Returns (path, carrier) pairs, carrier being the top-level directory
    the vendored package sits in (e.g. "setuptools"). Top-level
    dist-info directories are find_dist_info_dirs' job, not this one's.
    """
    found = []
    if not os.path.isdir(packages_dir):
        return found
    for top in sorted(os.listdir(packages_dir)):
        top_path = os.path.join(packages_dir, top)
        if top.endswith(".dist-info") or not os.path.isdir(top_path):
            continue
        for root, dirs, _files in os.walk(top_path):
            dirs.sort()
            for d in list(dirs):
                if d.endswith(".dist-info"):
                    found.append((os.path.join(root, d), top))
                    dirs.remove(d)
    return found


def installed_asset_paths(dist_info):
    """Return the asset files a package installed, from its RECORD.

    None if the package has no RECORD -- pip always writes one, so its
    absence means the tree was not installed the way this gate assumes,
    and the caller fails rather than treating it as "no assets".
    """
    record = os.path.join(dist_info, "RECORD")
    if not os.path.isfile(record):
        return None
    paths = []
    with open(record, encoding="utf-8") as f:
        for row in csv.reader(f):
            if not row:
                continue
            path = row[0]
            if ".dist-info/" in path or "__pycache__" in path:
                continue
            if os.path.splitext(path)[1].lower() in ASSET_EXTENSIONS:
                paths.append(path)
    return paths


def parse_metadata(path):
    """Return the header lines of a dist-info METADATA file.

    METADATA is RFC 822-shaped: headers, then a blank line, then the free-
    text long description. Only the header block is relevant here, and
    stopping at the first blank line keeps a licence-shaped line inside
    the long description (a README quoting another project's licence,
    say) from being mistaken for this package's own declaration.
    """
    lines = []
    with open(path, encoding="utf-8", errors="strict") as f:
        for line in f:
            stripped = line.rstrip("\n")
            if stripped == "":
                break
            lines.append(stripped)
    return lines


def candidates_of(header_lines):
    """Return every licence identifier a package's metadata declares.

    Returns an empty list if none of the three fields documented in the
    module docstring carries a usable identifier -- that is "no licence
    field" to the caller, not a licence of some placeholder value.
    """
    candidates = []

    for line in header_lines:
        if line.startswith("License-Expression:"):
            value = line[len("License-Expression:"):].strip()
            if value:
                if " AND " in value:
                    candidates.append(value)
                else:
                    candidates.extend(
                        part.strip() for part in value.split(" OR ") if part.strip()
                    )
        elif line.startswith("Classifier:"):
            value = line[len("Classifier:"):].strip()
            if value.startswith("License ::"):
                parts = [p.strip() for p in value.split("::")]
                # parts[0] is "License"; a specific name needs at least
                # one more segment than the bare "License :: OSI
                # Approved" the trove classifier list also allows.
                if len(parts) > 2 and parts[-1]:
                    candidates.append(parts[-1])
        elif line.startswith("License:"):
            value = line[len("License:"):].strip()
            if value and value != "UNKNOWN":
                candidates.append(value)

    # Preserve order, drop duplicates (e.g. the same string from both the
    # raw License: field and a Classifier).
    seen = set()
    out = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def find_bundled_licence_files(dist_info, header_lines):
    """Return any bundled licence file paths named for a "no licence field" offender.

    A better error message only -- naming the path is the whole feature.
    This deliberately does NOT read, hash, or otherwise inspect what any
    of these files says: no text matching, no fuzzy comparison, nothing
    that might look like it is inferring a licence. Whoever records the
    next allow-python-package-licenses exception still has to open the
    file and read it themselves, exactly as the hpfeeds entry already in
    the policy file was (see that file's comments for what was found,
    and for setuptools and ordereddict, each reviewed the same way and
    later removed as exceptions stopped being needed).

    Two sources, matching how packages actually ship one:
      - License-File: headers in METADATA (PEP 639), each naming a path
        relative to the dist-info directory.
      - Any file directly inside the dist-info directory, or its
        licenses/ subdirectory, whose name starts with "LICENSE" --
        the convention most build backends use even without a
        License-File: header (paths already found via the header are
        not duplicated).
    """
    found = []
    for line in header_lines:
        if line.startswith("License-File:"):
            value = line[len("License-File:"):].strip()
            if value and value not in found:
                found.append(value)

    for subdir in ("", "licenses"):
        directory = os.path.join(dist_info, subdir) if subdir else dist_info
        if not os.path.isdir(directory):
            continue
        try:
            names = os.listdir(directory)
        except OSError:
            continue
        for name in sorted(names):
            if not name.upper().startswith("LICENSE"):
                continue
            rel = os.path.join(subdir, name) if subdir else name
            if rel not in found:
                found.append(rel)

    return found


def match_key(label):
    """The form a "<name>@<version>" label is compared in.

    The name is normalised the way PEP 503 (packaging's
    canonicalize_name) does -- lowercased, any run of "-", "_" or "."
    made one "-" -- since METADATA keeps the project's own spelling
    ("Twisted", "zope.interface") while the policy is written in
    lowercase. The version is left exactly as written.
    """
    name, _, version = label.rpartition("@")
    return f"{re.sub(r'[-_.]+', '-', name).lower()}@{version}"


def name_and_version(header_lines, fallback):
    name = None
    version = None
    for line in header_lines:
        if name is None and line.startswith("Name:"):
            name = line[len("Name:"):].strip()
        elif version is None and line.startswith("Version:"):
            version = line[len("Version:"):].strip()
    return f"{name or fallback}@{version or '0.0.0'}"


def main(argv):
    if len(argv) != 3:
        print(f"usage: {argv[0]} <packages_dir> <policy_file>", file=sys.stderr)
        return 2

    packages_dir, policy_file = argv[1], argv[2]

    if not os.path.isdir(packages_dir):
        print(
            f"licence-check-python: packages directory not found at "
            f"{packages_dir} -- run scripts/licence-check-python.sh, or "
            "pip install --require-hashes into it, first",
            file=sys.stderr,
        )
        return 2

    allowed = read_allow_list(policy_file)
    if not allowed:
        print(
            f"licence-check-python: no allow-python-licenses entries found "
            f"in {policy_file} -- refusing to run with an empty allow-list",
            file=sys.stderr,
        )
        return 1
    allowed_set = set(allowed)

    # Unlike allowed above, an absent or empty allow-python-package-
    # licenses: list is not an error -- it just means no named exception
    # exists yet, which is the normal state until one is needed.
    package_allowed = read_package_allow_list(policy_file) or {}

    print(f"licence-check-python: allowed licences: {', '.join(allowed)}")

    offenders = []
    counts = {}
    exceptions = []  # (label, spdx_id) pairs that passed by named exception
    used_exceptions = set()
    exception_by_key = {match_key(entry): entry for entry in package_allowed}

    asset_reviews = read_asset_reviews(policy_file) or []
    used_reviews = set()
    unreviewed_assets = {}  # (label, directory) -> file count
    reviewed_assets = {}  # (label, prefix, licence) -> file count

    to_check = [(d, None) for d in find_dist_info_dirs(packages_dir)]
    to_check += find_vendored_dist_info_dirs(packages_dir)

    for dist_info, carrier in to_check:
        metadata_path = os.path.join(dist_info, "METADATA")
        label_fallback = os.path.basename(dist_info)[: -len(".dist-info")]
        shown = (lambda l: f"{l} (vendored in {carrier})") if carrier else (lambda l: l)

        if not os.path.isfile(metadata_path):
            offenders.append((shown(label_fallback), "(no METADATA file)", None))
            continue

        try:
            header_lines = parse_metadata(metadata_path)
        except (OSError, UnicodeDecodeError) as e:
            offenders.append((shown(label_fallback), "(unreadable METADATA)", str(e)))
            continue

        label = name_and_version(header_lines, label_fallback)
        key = match_key(label)

        # Bundled assets: only a top-level package's RECORD is read, since
        # it lists every file that package installed, vendored ones
        # included. Checked before the licence verdict below so a package
        # passing by named exception is still held to it.
        if carrier is None:
            assets = installed_asset_paths(dist_info)
            if assets is None:
                offenders.append((label, "(no RECORD file)", None))
            else:
                for path in assets:
                    review = next(
                        (r for r in asset_reviews if match_key(r[0]) == key and path.startswith(r[1])),
                        None,
                    )
                    if review is None:
                        where = (label, os.path.dirname(path))
                        unreviewed_assets[where] = unreviewed_assets.get(where, 0) + 1
                    else:
                        used_reviews.add(review)
                        reviewed_assets[review] = reviewed_assets.get(review, 0) + 1

        # A named, version-pinned exception passes as its recorded SPDX
        # id whatever the package's own metadata says or fails to say --
        # checked before candidates_of() below, so it also overrides a
        # GPL licence or a missing licence field, not just a borderline
        # one. See read_package_allow_list's docstring for why the version
        # must match exactly.
        entry = exception_by_key.get(key)
        if entry is not None:
            exception_licence = package_allowed[entry]
            used_exceptions.add(entry)
            exceptions.append((shown(label), exception_licence))
            continue

        candidates = candidates_of(header_lines)

        if not candidates:
            licence_files = find_bundled_licence_files(dist_info, header_lines)
            detail = (
                "bundled licence file(s): " + ", ".join(licence_files)
                if licence_files
                else None
            )
            offenders.append((shown(label), "(no licence field)", detail))
            continue

        allowed_here = [c for c in candidates if c in allowed_set]
        if not allowed_here:
            offenders.append((shown(label), " OR ".join(candidates), None))
            continue

        matched = allowed_here[0]
        counts[matched] = counts.get(matched, 0) + 1

    if offenders:
        print(
            f"licence-check-python: {len(offenders)} package(s) with a "
            "licence outside the allow-list:",
            file=sys.stderr,
        )
        for label, licence, detail in offenders:
            line = f"  {label} — {licence}"
            if detail:
                line += f" ({detail})"
            print(line, file=sys.stderr)
        return 1

    if unreviewed_assets:
        print(
            f"licence-check-python: {sum(unreviewed_assets.values())} bundled "
            "asset file(s) with no python-bundled-assets review -- images, "
            "pages, stylesheets, scripts or fonts carry no licence field, so "
            "each directory needs reading and recording:",
            file=sys.stderr,
        )
        for (label, directory), count in sorted(unreviewed_assets.items()):
            print(f"  {label} {directory}/ ({count} file(s))", file=sys.stderr)
        return 1

    stale_reviews = [r for r in asset_reviews if r not in used_reviews]
    if stale_reviews:
        print(
            f"licence-check-python: {len(stale_reviews)} stale python-bundled-"
            f"assets review(s) in {policy_file} matched no installed file -- "
            "delete them:",
            file=sys.stderr,
        )
        for name_version, prefix, licence in stale_reviews:
            print(f"  {name_version} {prefix} {licence}", file=sys.stderr)
        return 1

    # An exception matching no installed package is stale: the package
    # was removed or its version moved on, and the entry is now dead
    # weight nobody reviews. Left unchecked, an allow-list like this only
    # grows -- this is what stops it, with a message distinct from the
    # offenders one above so it reads as "delete this", not "fix this".
    stale = sorted(label for label in package_allowed if label not in used_exceptions)
    if stale:
        print(
            f"licence-check-python: {len(stale)} stale allow-python-"
            f"package-licenses exception(s) in {policy_file} matched no "
            "installed package -- delete them:",
            file=sys.stderr,
        )
        for label in stale:
            print(f"  {label} {package_allowed[label]}", file=sys.stderr)
        return 1

    total = sum(counts.values())
    print(f"licence-check-python: {total} package(s) checked, all licences allowed:")
    for licence, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {count:4d}  {licence}")

    # A green gate must not quietly hide that some of these packages only
    # passed because someone recorded an exception for them, not because
    # their own metadata said something acceptable -- named separately,
    # never folded into the counts above.
    if exceptions:
        print(
            f"licence-check-python: {len(exceptions)} package(s) passed by "
            "recorded exception (allow-python-package-licenses), not by "
            "their own declared licence:"
        )
        for label, licence in sorted(exceptions):
            print(f"  {label} — {licence}")

    # Same reason as the exceptions above: say which bundled assets passed
    # only because someone reviewed them.
    if reviewed_assets:
        print(
            f"licence-check-python: {sum(reviewed_assets.values())} bundled "
            "asset file(s) passed by recorded review (python-bundled-assets):"
        )
        for (name_version, prefix, licence), count in sorted(reviewed_assets.items()):
            print(f"  {name_version} {prefix} ({count}) — {licence}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
