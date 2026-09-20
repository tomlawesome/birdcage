#!/usr/bin/env python3
"""Gate the licences of the npm packages under frontend/node_modules.

Companion to scripts/licence-check.sh, which gates the Go modules linked
into the Birdcage binary. This script covers the other half of the tree
that ships anything: the frontend has no runtime `dependencies` (all 13
direct entries are devDependencies), but Svelte compiles its runtime
helpers into the built bundle, so dependency code reaches web/dist even
though nothing is listed as a runtime dependency. A check that trusted
`dependencies` over `devDependencies` would therefore be wrong here, so
this walks the whole installed tree rather than reasoning from
package.json's dependency lists.

Written in Python rather than jq/awk because a package.json `license`
field has three shapes in the wild (a plain string, a `{type: ...}`
object, and the legacy `licenses: [...]` array), and Python's stdlib
`json` module parses all of them without adding a dependency. A licence
checker installed from npm would itself be an unreviewed dependency,
which is the problem this script exists to catch, not a shortcut to it.

Called by scripts/licence-check-npm.sh, which resolves the default paths
and forwards this script's exit code.

Usage: scripts/licence-check-npm.py <node_modules_dir> <policy_file>
Exit codes:
  0 every installed package's licence is on the allow-list
  1 a disallowed licence, a missing licence field, or an empty/unparseable
    allow-list
  2 node_modules_dir does not exist (fail red, never quietly green, if a
    job forgets `npm ci`)
"""
import json
import os
import sys


def read_allow_list(policy_file):
    """Pull the `allow-npm-licenses:` list out of the policy YAML.

    Deliberately not a YAML parser: the file's shape under this key is a
    fixed, simple list, same as scripts/licence-check.sh's awk extraction
    of `allow-licenses:`. Using a different key name (not a prefix match
    of "allow-licenses:") means this cannot collide with that script's
    parse of the Go list.
    """
    if not os.path.isfile(policy_file):
        return None
    allowed = []
    in_list = False
    with open(policy_file) as f:
        for line in f:
            stripped = line.rstrip("\n")
            if stripped.startswith("allow-npm-licenses:"):
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


def find_package_roots(node_modules_dir):
    """Find every installed package's own directory.

    An installed package is an immediate child of some node_modules
    directory (its own, or `@scope/name` for scoped packages) that has a
    package.json directly inside it. This deliberately does NOT match
    every package.json anywhere under node_modules: some packages ship
    example or fixture package.json files nested deeper inside their own
    tree, and those are not separately installed packages. Nested
    node_modules directories (from npm installing conflicting versions)
    are walked too, so a shadowed version is still checked.
    """
    roots = []
    for dirpath, dirnames, _ in os.walk(node_modules_dir):
        if os.path.basename(dirpath) != "node_modules":
            continue
        for name in dirnames:
            if name.startswith("."):
                continue
            if name.startswith("@"):
                scope_dir = os.path.join(dirpath, name)
                if not os.path.isdir(scope_dir):
                    continue
                for sub in os.listdir(scope_dir):
                    candidate = os.path.join(scope_dir, sub)
                    if os.path.isfile(os.path.join(candidate, "package.json")):
                        roots.append(candidate)
            else:
                candidate = os.path.join(dirpath, name)
                if os.path.isfile(os.path.join(candidate, "package.json")):
                    roots.append(candidate)
    return roots


def licences_of(pkg):
    """Return the list of licence identifiers a package.json declares.

    Handles the current plain-string form, the `{type: ...}` object
    form, and the legacy `licenses: [...]` array (each entry itself
    either a string or a `{type: ...}` object). Returns an empty list if
    none of these is present or none carries a usable identifier --
    that is "no licence field" to the caller, not a licence of `None`.
    """
    lic = pkg.get("license")
    if lic is None:
        lic = pkg.get("licenses")

    if lic is None:
        return []
    if isinstance(lic, str):
        return [lic] if lic.strip() else []
    if isinstance(lic, dict):
        t = lic.get("type")
        return [t] if t else []
    if isinstance(lic, list):
        out = []
        for entry in lic:
            if isinstance(entry, str) and entry.strip():
                out.append(entry)
            elif isinstance(entry, dict) and entry.get("type"):
                out.append(entry["type"])
        return out
    return []


def main(argv):
    if len(argv) != 3:
        print(f"usage: {argv[0]} <node_modules_dir> <policy_file>", file=sys.stderr)
        return 2

    node_modules_dir, policy_file = argv[1], argv[2]

    if not os.path.isdir(node_modules_dir):
        print(
            f"licence-check-npm: node_modules not found at {node_modules_dir} "
            "-- run npm ci first",
            file=sys.stderr,
        )
        return 2

    allowed = read_allow_list(policy_file)
    if not allowed:
        print(
            f"licence-check-npm: no allow-npm-licenses entries found in "
            f"{policy_file} -- refusing to run with an empty allow-list",
            file=sys.stderr,
        )
        return 1
    allowed_set = set(allowed)

    print(f"licence-check-npm: allowed licences: {', '.join(allowed)}")

    roots = find_package_roots(node_modules_dir)
    offenders = []
    counts = {}

    for root in sorted(roots):
        with open(os.path.join(root, "package.json")) as f:
            try:
                pkg = json.load(f)
            except json.JSONDecodeError as e:
                offenders.append((root, "(unparseable package.json)", str(e)))
                continue

        name = pkg.get("name", os.path.basename(root))
        version = pkg.get("version", "0.0.0")
        licences = licences_of(pkg)

        if not licences:
            offenders.append((f"{name}@{version}", "(no licence field)", None))
            continue

        allowed_here = [l for l in licences if l in allowed_set]
        if not allowed_here:
            offenders.append((f"{name}@{version}", " OR ".join(licences), None))
            continue

        matched = allowed_here[0]
        counts[matched] = counts.get(matched, 0) + 1

    if offenders:
        print(
            f"licence-check-npm: {len(offenders)} package(s) with a licence "
            "outside the allow-list:",
            file=sys.stderr,
        )
        for label, licence, detail in offenders:
            line = f"  {label} — {licence}"
            if detail:
                line += f" ({detail})"
            print(line, file=sys.stderr)
        return 1

    total = sum(counts.values())
    print(f"licence-check-npm: {total} package(s) checked, all licences allowed:")
    for licence, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {count:4d}  {licence}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
