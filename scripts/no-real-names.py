#!/usr/bin/env python3
"""CI guard: no real personal names or emails in tracked files (#192).

Tokenises every tracked text file (and every tracked path), hashes each
lowercase word with a salt and fails if any hash is in the committed list.
Only hashes are committed, never the words. Output gives counts and paths,
never the matched word.

usage: no-real-names.py [--root DIR] [--hashes FILE] [--allow FILE]
Exit 0 clean, 1 matches found, 2 usage or config error.
"""
import argparse, hashlib, os, re, subprocess, sys

LOCK_NAMES = {"go.sum", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
              "poetry.lock", "Cargo.lock", "uv.lock"}
WORD = re.compile(r"[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*")  # dotted runs, e.g. a domain
PART = re.compile(r"[A-Za-z0-9]+")


def load_hashes(path):
    salt, hashes = None, set()
    for raw in open(path, encoding="utf-8"):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("salt:"):
            salt = line[5:].strip()
        else:
            hashes.add(line.lower())
    if salt is None:
        sys.exit("hashes file has no salt: line")
    return salt, hashes


def load_allow(path):
    pats = []
    if path and os.path.exists(path):
        for raw in open(path, encoding="utf-8"):
            line = raw.split("#", 1)[0].strip()
            if line:
                pats.append(re.compile(line))
    return pats


def words(text):
    seen = set()
    for m in WORD.finditer(text):
        seen.add(m.group(0).lower())
        for p in PART.findall(m.group(0)):
            seen.add(p.lower())
    return seen


def digest(salt, word):
    return hashlib.sha256((salt + word).encode("utf-8")).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--root", default=os.path.join(here, ".."))
    ap.add_argument("--hashes", default=os.path.join(here, "no-real-names.hashes"))
    ap.add_argument("--allow", default=os.path.join(here, "no-real-names.allow"))
    a = ap.parse_args()
    root = os.path.abspath(a.root)
    salt, hashes = load_hashes(a.hashes)
    allow = load_allow(a.allow)
    files = subprocess.run(["git", "-C", root, "ls-files", "-z"], check=True,
                           capture_output=True).stdout.decode("utf-8", "replace").split("\0")
    bad = []
    for rel in filter(None, files):
        if any(p.search(rel) for p in allow):
            continue
        hit = any(digest(salt, w) in hashes for w in words(rel))
        full = os.path.join(root, rel)
        if (not hit and os.path.basename(rel) not in LOCK_NAMES
                and os.path.isfile(full) and not os.path.islink(full)):
            data = open(full, "rb").read()
            if b"\0" not in data[:8192]:
                hit = any(digest(salt, w) in hashes
                          for w in words(data.decode("utf-8", "replace")))
        if hit:
            bad.append(rel)
    if bad:
        print(f"no-real-names: {len(bad)} tracked file(s) contain a hashed word:")
        for rel in bad:
            print(f"  {rel}")
        print("Replace with invented names/placeholders; for an intended use add the path to"
              " scripts/no-real-names.allow (reviewed).")
        return 1
    print("no-real-names: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
