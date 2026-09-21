#!/usr/bin/env python3
"""Gate the licences of the pip packages installed for the mockingbird image.

Companion to scripts/licence-check.sh (Go modules linked into the
Birdcage binary) and scripts/licence-check-npm.py (the npm tree under
frontend/node_modules). This one covers build/mockingbird/requirements.txt
-- pip packages installed straight into the distroless mockingbird image
(build/mockingbird/Dockerfile's "honeypot" stage), the one ecosystem that
had no licence gate at all before #95.

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
project can accept as-is (hpfeeds' bundled LICENSE is GPLv3; setuptools
and ordereddict declare no licence field at all, though both ship an MIT
LICENSE file once actually read by hand). Rather than adding their
licence to the allow-list above -- which would accept it for every
package, not just the one reviewed -- supply-chain/licence-policy.yml
also has an allow-python-package-licenses: list of named, version-pinned
exceptions ("<name>@<version> <SPDX-id>"), read by
read_package_allow_list below. A package matching one exactly passes as
that recorded SPDX id regardless of what its own metadata says; bumping
its version stops the entry matching, on purpose, so the gate fires
again and the new version gets its own review. An exception that
matches no installed package is itself a failure, so the list cannot
accumulate stale, unneeded entries silently.

Usage: scripts/licence-check-python.py <packages_dir> <policy_file>
Exit codes:
  0 every installed package's licence is on the allow-list or matches a
    named allow-python-package-licenses exception
  1 a disallowed licence, a missing licence field, an unreadable
    METADATA file, an empty/unparseable allow-list, or a named exception
    that matched no installed package
  2 packages_dir does not exist (fail red, never quietly green, if the
    install step never ran)
"""
import os
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

    Each entry is "<name>@<version> <SPDX-id>" -- name@version is
    exactly the label name_and_version() below builds for an installed
    package, so an entry matches only on an exact, full-string name and
    version; bumping the package's version is enough to stop it
    matching, which is intended (see the module docstring). Returns a
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
    file and read it themselves, exactly as the hpfeeds, setuptools and
    ordereddict entries already in the policy file were each read by
    hand (see that file's comments for what was found).

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

    for dist_info in find_dist_info_dirs(packages_dir):
        metadata_path = os.path.join(dist_info, "METADATA")
        label_fallback = os.path.basename(dist_info)[: -len(".dist-info")]

        if not os.path.isfile(metadata_path):
            offenders.append((label_fallback, "(no METADATA file)", None))
            continue

        try:
            header_lines = parse_metadata(metadata_path)
        except (OSError, UnicodeDecodeError) as e:
            offenders.append((label_fallback, "(unreadable METADATA)", str(e)))
            continue

        label = name_and_version(header_lines, label_fallback)

        # A named, version-pinned exception passes as its recorded SPDX
        # id whatever the package's own metadata says or fails to say --
        # checked before candidates_of() below, so it also overrides a
        # GPL licence or a missing licence field, not just a borderline
        # one. See read_package_allow_list's docstring for why an exact
        # name@version match is the only kind this makes.
        exception_licence = package_allowed.get(label)
        if exception_licence is not None:
            used_exceptions.add(label)
            exceptions.append((label, exception_licence))
            continue

        candidates = candidates_of(header_lines)

        if not candidates:
            licence_files = find_bundled_licence_files(dist_info, header_lines)
            detail = (
                "bundled licence file(s): " + ", ".join(licence_files)
                if licence_files
                else None
            )
            offenders.append((label, "(no licence field)", detail))
            continue

        allowed_here = [c for c in candidates if c in allowed_set]
        if not allowed_here:
            offenders.append((label, " OR ".join(candidates), None))
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

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
