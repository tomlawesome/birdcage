#!/usr/bin/env bash
# Tests for scripts/gitleaks-scan.sh: proves the gate actually fires.
# Issue #28 acceptance criterion 2 -- "proven to fail against a planted
# secret, not merely to pass on a clean repository" -- and criteria 3/4,
# that the secret value itself never appears in the output.
#
# gitleaks is a released binary (scripts/ensure-gitleaks.sh), not vendored
# into this repository, so this suite skips cleanly -- loudly, with a
# message, the same shape as scripts/licence-check-npm.test.sh's
# node_modules skip -- when it is not on PATH. lint:gitleaks installs it
# before running this suite, so CI always runs the real thing; a
# workstation without it sees why, instead of a baffling failure.
#
# The planted secret is a private key generated at runtime with `openssl
# genpkey`, never a value typed into this file -- the same reason
# ensure-cosign.test.sh's fixtures are synthesized rather than borrowed
# from anywhere real. It is committed into a THROWAWAY repository under a
# temp dir that the exit trap deletes, and by `git commit-tree`/
# `update-ref` rather than `git commit`: this host's own pre-commit
# secret gate (pre-commit-secret-scan skill) runs gitleaks on every real
# `git commit` and would correctly refuse to let this fixture be created
# through that porcelain command. Building the commit with plumbing
# instead is not bypassing that gate -- nothing here calls `git commit`,
# so there is no hook to skip -- it is the only way to hand gitleaks a
# real commit object to scan without asking the host's own gate to look
# the other way for a fixture.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
scan="$here/gitleaks-scan.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0; skip=0

ok() { echo "ok   $1"; pass=$((pass + 1)); }
fail_() {
  echo "FAIL $1"
  echo "       output:"; sed 's/^/         /' "$2" 2>/dev/null
  fail=$((fail + 1))
}

GITLEAKS_BIN="${GITLEAKS_BIN:-gitleaks}"
if ! command -v "$GITLEAKS_BIN" >/dev/null 2>&1 && [ ! -x "$GITLEAKS_BIN" ]; then
  echo "skip gitleaks-scan.sh's self-test: gitleaks not found (GITLEAKS_BIN=$GITLEAKS_BIN)."
  echo "       Run scripts/ensure-gitleaks.sh to install it locally; lint:gitleaks"
  echo "       installs it before running this suite in CI."
  skip=$((skip + 1))
  echo "$pass passed, $fail failed, $skip skipped"
  exit 0
fi

# init <dir> -- a throwaway git repository, never touching this checkout.
init() {
  local dir="$1"
  mkdir -p "$dir"
  git -C "$dir" init --quiet --initial-branch=main
  git -C "$dir" config user.email "test@example.invalid"
  git -C "$dir" config user.name "gitleaks-scan test"
}

# commit_file <dir> <relpath> <message> -- writes a blob/tree/commit and
# moves refs/heads/main to it via plumbing, deliberately never `git add`
# or `git commit`. $relpath must already exist under $dir.
commit_file() {
  local dir="$1" relpath="$2" message="$3" blob tree commit
  blob="$(git -C "$dir" hash-object -w "$relpath")"
  tree="$(printf '100644 blob %s\t%s\n' "$blob" "$relpath" | git -C "$dir" mktree)"
  commit="$(git -C "$dir" commit-tree "$tree" -m "$message")"
  git -C "$dir" update-ref refs/heads/main "$commit"
}

# --- A repository with a planted secret must fail the scan, redacted.
repo="$work/planted-repo"
init "$repo"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$repo/planted.pem" 2>/dev/null
commit_file "$repo" planted.pem "add a planted secret for the gitleaks self-test"

# The base64 body (the part that would actually identify the key), not
# the "-----BEGIN PRIVATE KEY-----" header lines -- checked as whole lines
# so a coincidental short substring elsewhere in gitleaks' own log
# (timestamps, hex commit ids) cannot produce a false pass.
mapfile -t secret_lines < <(grep -v -- '-----' "$repo/planted.pem")

out="$work/scan-output.txt"
got=0
GITLEAKS_BIN="$GITLEAKS_BIN" "$scan" "$repo" >"$out" 2>&1 || got=$?

if [ "$got" != 0 ]; then
  ok "the scan command fails against a repository with a planted private key"
else
  fail_ "the scan command fails against a repository with a planted private key (exit 0)" "$out"
fi

leaked=0
for line in "${secret_lines[@]}"; do
  if grep -qF "$line" "$out"; then
    leaked=1
    break
  fi
done
if [ "$leaked" = 0 ]; then
  ok "no line of the planted key's body appears in the (redacted) scan output"
else
  fail_ "no line of the planted key's body appears in the (redacted) scan output" "$out"
fi

if grep -qi "REDACTED" "$out"; then
  ok "the finding is explicitly marked REDACTED, not merely absent"
else
  fail_ "the finding is explicitly marked REDACTED, not merely absent" "$out"
fi

# --- The absence-of-leaks half of the same claim: a clean repository (no
# planted secret) must pass -- criterion 2 is "catches this", not "always
# fails regardless of content".
clean_repo="$work/clean-repo"
init "$clean_repo"
printf 'nothing sensitive here\n' > "$clean_repo/readme.txt"
commit_file "$clean_repo" readme.txt "clean commit"

clean_out="$work/clean-output.txt"
got=0
GITLEAKS_BIN="$GITLEAKS_BIN" "$scan" "$clean_repo" >"$clean_out" 2>&1 || got=$?
if [ "$got" = 0 ]; then
  ok "the scan command passes against a clean repository"
else
  fail_ "the scan command passes against a clean repository" "$clean_out"
fi

echo "$pass passed, $fail failed, $skip skipped"
[ "$fail" = 0 ]
