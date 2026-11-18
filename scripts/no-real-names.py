#!/usr/bin/env python3
"""CI guard: no real personal names or emails in tracked files (#192).

Tokenises every tracked text file (and every tracked path), computes a keyed
hash (HMAC-SHA256, RFC 2104) of each lowercase word and fails if any hash is
in the committed list. Only keyed hashes are committed, never the words; the
words are unrecoverable from the list without the key, which is never
committed. Output gives counts and paths, never the matched word or the key.

The key is the raw bytes of a file (32 random bytes), named by --key-file,
else NO_REAL_NAMES_KEY_FILE (CI: a masked file variable), else
~/.config/birdcage/no-real-names.key. It is never read from argv. A missing
key, an old salted hashes file or a list with no entries is a config error:
the guard fails closed rather than pass on an empty list.

The hashes file carries one "key-check: <64 hex>" line, HMAC-SHA256(key,
b"no-real-names key check"). A wrong key (say a CI file variable with an
extra trailing newline) would match no hash and pass every tree, so a
missing, malformed, duplicated or mismatched key-check is a config error,
checked before the no-entries check. Key bytes are used exactly as stored.
--key-check prints that line for the key in use and nothing else.

--add reads one word from the terminal (no echo) or stdin, never argv, and
prints only its keyed hash, the line to append to the hashes file.

--history scans every blob reachable from any ref (all branches and tags,
not only the checked-out tree) and reports path and commit for each hit,
at every path the blob appears at that is not allowlisted.
Files over MAX_BYTES are skipped and counted, never read.

usage: no-real-names.py [--root DIR] [--hashes FILE] [--allow FILE] [--key-file FILE]
                        [--history | --add | --key-check]
Exit 0 clean, 1 matches found, 2 usage or config error.
"""
import argparse, getpass, hashlib, hmac, os, re, subprocess, sys, threading

MAX_BYTES = 5 * 1024 * 1024
HEADER = "hmac-sha256"
KEY_ENV = "NO_REAL_NAMES_KEY_FILE"
DEFAULT_KEY = os.path.join("~", ".config", "birdcage", "no-real-names.key")
MIN_KEY_BYTES = 16
HEX64 = re.compile(r"[0-9a-f]{64}")
KEY_CHECK = "key-check:"
KEY_CHECK_MSG = b"no-real-names key check"

LOCK_NAMES = {"go.sum", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
              "poetry.lock", "Cargo.lock", "uv.lock"}
WORD = re.compile(r"[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*")  # dotted runs, e.g. a domain
PART = re.compile(r"[A-Za-z0-9]+")


def config_error(msg):
    print(f"no-real-names: {msg}", file=sys.stderr)
    sys.exit(2)


def load_hashes(path):
    """(set of keyed hashes, key-check hex) from path. The first non-comment
    line must be the format header; exactly one later line the key-check;
    every other one a 64-hex entry. Line contents are never echoed, in case a
    word was pasted in by mistake. The key-check and the no-entries rule are
    enforced by verify_hashes, once the key is loaded."""
    header, hashes, check = None, set(), None
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except (OSError, UnicodeDecodeError) as exc:
        config_error(f"cannot read hashes file {path}: {getattr(exc, 'strerror', None) or exc}")
    for n, raw in enumerate(lines, 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("salt:"):
            config_error(f"hashes file {path} is in the old salted format (line {n}); it is "
                         f"no longer accepted: regenerate each entry with --add under the key "
                         f"and start the file with a '{HEADER}' line")
        if header is None:
            if line != HEADER:
                config_error(f"hashes file {path} does not start with the '{HEADER}' header line")
            header = line
            continue
        if line.startswith(KEY_CHECK):
            value = line[len(KEY_CHECK):].strip().lower()
            if check is not None:
                config_error(f"hashes file {path} line {n}: more than one key-check line")
            if not HEX64.fullmatch(value):
                config_error(f"hashes file {path} line {n}: the key-check value is not 64 hex;"
                             f" regenerate it with --key-check")
            check = value
            continue
        if not HEX64.fullmatch(line.lower()):
            config_error(f"hashes file {path} line {n} is not a 64-hex keyed hash")
        hashes.add(line.lower())
    if header is None:
        config_error(f"hashes file {path} does not start with the '{HEADER}' header line")
    if check is None:
        config_error(f"hashes file {path} has no key-check line; without it a wrong key would"
                     f" pass every tree. Add the line --key-check prints for the right key")
    return hashes, check


def key_check(key):
    return f"{KEY_CHECK} {digest_bytes(key, KEY_CHECK_MSG)}"


def verify_hashes(path, hashes, check, key):
    """Fail closed on a key that does not match the file's key-check, then on
    an empty list (in that order)."""
    if not hmac.compare_digest(digest_bytes(key, KEY_CHECK_MSG), check):
        config_error(f"key check failed: the key in use does not match the key-check line in"
                     f" {path}, so no hash could match. Use the key the list was made with"
                     f" (bytes exactly as stored: a trailing newline counts)")
    if not hashes:
        config_error(f"hashes file {path} has no entries; add them with --add, since an "
                     f"empty list would pass every tree")


def load_key(flag):
    """The key bytes from --key-file, else $NO_REAL_NAMES_KEY_FILE, else the
    default path. The key is never printed; a missing or short key fails closed."""
    if flag:
        path, source = flag, "--key-file"
    elif os.environ.get(KEY_ENV):
        path, source = os.environ[KEY_ENV], KEY_ENV
    else:
        path, source = os.path.expanduser(DEFAULT_KEY), "default key path"
    try:
        with open(path, "rb") as fh:
            key = fh.read(4096)
    except OSError as exc:
        config_error(f"no key: cannot read key file {path} ({source}): {exc.strerror}. "
                     f"Set {KEY_ENV} or --key-file to the key file (CI: the masked file "
                     f"variable), or create {DEFAULT_KEY}; the list cannot be checked without it")
    if len(key) < MIN_KEY_BYTES:
        config_error(f"key file {path} ({source}) is shorter than {MIN_KEY_BYTES} bytes; "
                     f"the key must be 32 random bytes")
    return key


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


def digest_bytes(key, data):
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def digest(key, word):
    return digest_bytes(key, word.encode("utf-8"))


def read_word():
    """One word from the terminal without echo, or the first line of stdin."""
    try:
        if sys.stdin.isatty():
            word = getpass.getpass("word (not echoed): ")
        else:
            word = sys.stdin.readline()
    except (EOFError, KeyboardInterrupt):
        config_error("--add: no word read")
    word = word.strip().lower()
    if not word:
        config_error("--add: no word read from the terminal or stdin")
    if not WORD.fullmatch(word):
        config_error("--add: the word must be one run of letters and digits, optionally dotted"
                     " (as the tokeniser splits text)")
    return word


def reject_argv_word(argv):
    """--add never takes its word from argv (shell history, process lists):
    refuse without echoing whatever was given."""
    if any(arg.startswith("--add=") for arg in argv):
        config_error("--add takes no value: the word is read from the terminal or stdin,"
                     " never from the command line")


def text_hit(key, hashes, data):
    if b"\0" in data[:8192]:
        return False
    return any(digest(key, w) in hashes for w in words(data.decode("utf-8", "replace")))


def path_skipped(rel, allow):
    return any(p.search(rel) for p in allow)


def git(root, *args):
    r = subprocess.run(["git", "-C", root, *args], capture_output=True)
    if r.returncode != 0:
        msg = r.stderr.decode("utf-8", "replace").strip().splitlines()
        config_error(f"git {args[0]} failed in {root}: {msg[-1] if msg else 'no message'}")
    return r.stdout


def scan_tree(root, key, hashes, allow):
    files = git(root, "ls-files", "-z").decode("utf-8", "replace").split("\0")
    bad, big = [], 0
    for rel in filter(None, files):
        if path_skipped(rel, allow):
            continue
        hit = any(digest(key, w) in hashes for w in words(rel))
        full = os.path.join(root, rel)
        if (not hit and os.path.basename(rel) not in LOCK_NAMES
                and os.path.isfile(full) and not os.path.islink(full)):
            if os.path.getsize(full) > MAX_BYTES:
                big += 1
                continue
            with open(full, "rb") as fh:
                hit = text_hit(key, hashes, fh.read(MAX_BYTES + 1))
        if hit:
            bad.append(rel)
    return bad, big


def history_blobs(root):
    """{blob: {path: commit}} for every blob any commit on any ref adds,
    with the earliest commit that adds it at each path; merges are diffed
    against each parent. Gitlinks (submodules) are not blobs and are left
    out."""
    out = git(root, "log", "--all", "--reverse", "--raw", "--no-abbrev", "--no-renames",
              "-m", "-z", "--format=%x01%H")
    blobs, commit = {}, None
    fields = iter(out.split(b"\0"))
    for f in fields:
        f = f.lstrip(b"\n")
        if f.startswith(b"\x01"):
            commit = f[1:].decode()
        elif f.startswith(b":"):
            meta = f.split(b" ")
            mode, new = meta[1], meta[3].decode()
            path = next(fields, b"").decode("utf-8", "replace")
            if new.strip("0") and mode != b"160000":
                blobs.setdefault(new, {}).setdefault(path, commit)
    return blobs


def read_blobs(root, shas):
    """Yield (sha, size, data-or-None) via one cat-file process; data is
    None for anything over MAX_BYTES (never read into memory)."""
    p = subprocess.Popen(["git", "-C", root, "cat-file",
                          "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out, _ = p.communicate("".join(s + "\n" for s in shas).encode())
    sizes = {}
    for line in out.decode().splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "blob":
            sizes[parts[0]] = int(parts[2])
    small = [s for s in shas if sizes.get(s, MAX_BYTES + 1) <= MAX_BYTES]
    small_set = set(small)
    for s in shas:
        if s not in small_set:
            yield s, None
    p = subprocess.Popen(["git", "-C", root, "cat-file", "--batch"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def feed():
        for s in small:
            p.stdin.write((s + "\n").encode())
        p.stdin.close()

    t = threading.Thread(target=feed, daemon=True)
    t.start()
    for s in small:
        header = p.stdout.readline().split()
        size = int(header[2])
        data = p.stdout.read(size)
        p.stdout.read(1)
        yield s, data
    t.join()
    p.wait()


def scan_history(root, key, hashes, allow):
    """Each blob's content is read once; every path it appears at that is not
    allowlisted is checked, so content first committed at an allowlisted path
    and later copied elsewhere is still reported, at the later path."""
    bad, big, todo = [], 0, {}
    for sha, paths in history_blobs(root).items():
        content_paths = []
        for path, commit in paths.items():
            if path_skipped(path, allow):
                continue
            if any(digest(key, w) in hashes for w in words(path)):
                bad.append((path, commit))
            elif os.path.basename(path) not in LOCK_NAMES:
                content_paths.append((path, commit))
        if content_paths:
            todo[sha] = content_paths
    for sha, data in read_blobs(root, list(todo)):
        if data is None:
            big += 1
        elif text_hit(key, hashes, data):
            bad.extend(todo[sha])
    return bad, big


def main():
    argv = sys.argv[1:]
    reject_argv_word(argv)
    ap = argparse.ArgumentParser(allow_abbrev=False)
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--root", default=os.path.join(here, ".."))
    ap.add_argument("--hashes", default=os.path.join(here, "no-real-names.hashes"))
    ap.add_argument("--allow", default=os.path.join(here, "no-real-names.allow"))
    ap.add_argument("--key-file", help=f"HMAC key file (default: ${KEY_ENV}, else {DEFAULT_KEY})")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--history", action="store_true",
                      help="scan every blob reachable from any ref, not just the tree")
    mode.add_argument("--add", action="store_true",
                      help="read one word from the terminal or stdin and print its keyed hash")
    mode.add_argument("--key-check", action="store_true",
                      help="print the key-check line for the key in use")
    a, extra = ap.parse_known_args(argv)
    if extra:
        if a.add:
            config_error("--add takes no value: the word is read from the terminal or stdin,"
                         " never from the command line")
        ap.error("unrecognized arguments")
    if a.add:
        key = load_key(a.key_file)
        print(digest(key, read_word()))
        return 0
    if a.key_check:
        print(key_check(load_key(a.key_file)))
        return 0
    root = os.path.abspath(a.root)
    hashes, check = load_hashes(a.hashes)
    key = load_key(a.key_file)
    verify_hashes(a.hashes, hashes, check, key)
    allow = load_allow(a.allow)
    skipped = lambda n: f" ({n} file(s) over {MAX_BYTES // (1024 * 1024)} MB skipped)" if n else ""
    if a.history:
        bad, big = scan_history(root, key, hashes, allow)
        if bad:
            print(f"no-real-names: {len(bad)} blob(s) in history contain a hashed word"
                  f"{skipped(big)}:")
            for path, commit in sorted(bad):
                print(f"  {path} (commit {commit[:12]})")
            print("Rewriting history is an owner-only step; report counts and paths only.")
            return 1
        print(f"no-real-names: history clean{skipped(big)}")
        return 0
    bad, big = scan_tree(root, key, hashes, allow)
    if bad:
        print(f"no-real-names: {len(bad)} tracked file(s) contain a hashed word{skipped(big)}:")
        for rel in bad:
            print(f"  {rel}")
        print("Replace with invented names/placeholders; for an intended use add the path to"
              " scripts/no-real-names.allow (reviewed).")
        return 1
    print(f"no-real-names: clean{skipped(big)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
