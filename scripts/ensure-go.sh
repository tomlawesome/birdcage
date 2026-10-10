#!/usr/bin/env bash
# Installs a checksum-pinned Go toolchain into a directory, verifying it
# before any caller trusts it. Same shape as scripts/ensure-gitleaks.sh --
# exactly one place Go gets installed from for the smoke jobs, so they
# cannot drift onto two different toolchains, and nothing here should ever
# be duplicated into a second copy.
#
# #160: the plain `curl | tar` the smoke jobs used to run sometimes dropped
# mid-stream (curl exit 92, HTTP/2 INTERNAL_ERROR) and failed the job, and
# the bytes it did get were never checksum-verified before being unpacked
# into /usr/local. This script retries the download and checks the archive
# hash before extraction, refusing and leaving nothing extracted on a
# mismatch.
set -euo pipefail

# --- The pin. Bump these together for a new Go release; nothing else in
# this file should need to change. Deliberately not overridable by
# environment variable, for the same reason ensure-gitleaks.sh gives: a
# protected CI/CD variable is settable outside the repository entirely.
# --version/--sha256/--url are flags, written at the call site, and every
# call site lives in .gitlab-ci.yml or a test under scripts/.
GO_VERSION="go1.27.2"
# SHA-256 of go1.27.2.linux-amd64.tar.gz, copied from
#   https://go.dev/dl/?mode=json
# fetched 2026-10-10; archive size 70590635 bytes. Cross-checked the same
# day by separately downloading the archive and hashing it locally -- the
# two matched.
GO_ARCHIVE_SHA256="ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5"

GO_URL=""

sha256_of() {
  sha256sum "$1" | awk '{print $1}'
}

# Thin wrapper around the actual byte transfer, kept as its own function so
# scripts/ensure-go.test.sh can point it at a local fixture (file://)
# without touching the network, the same shape as ensure-gitleaks.sh.
#
# --retry 3 --retry-all-errors --retry-delay 2: #160's mid-stream drops.
# A retried download is still checksum-checked below, so retrying cannot
# let bad bytes through -- it only gives a flaky connection another chance
# before the job fails.
fetch() {
  local url="$1" dest="$2"
  curl -fsSL --retry 3 --retry-all-errors --retry-delay 2 "$url" -o "$dest"
}

# install_parent_dir='' | resolved from $1, else /usr/local -- extracts to
# <install_parent_dir>/go, matching the layout the archive itself uses and
# the path the smoke jobs already put on PATH.
main() {
  local install_parent_dir target archive_name tmp tmpdir actual installed_version

  while [ $# -gt 0 ]; do
    case "$1" in
      --version) [ $# -ge 2 ] || { echo "ensure-go: --version needs a value" >&2; exit 2; }
        GO_VERSION="$2"; shift 2 ;;
      --sha256) [ $# -ge 2 ] || { echo "ensure-go: --sha256 needs a value" >&2; exit 2; }
        GO_ARCHIVE_SHA256="$2"; shift 2 ;;
      --url) [ $# -ge 2 ] || { echo "ensure-go: --url needs a value" >&2; exit 2; }
        GO_URL="$2"; shift 2 ;;
      --*) echo "ensure-go: unknown option: $1" >&2; exit 2 ;;
      *) break ;;
    esac
  done

  archive_name="${GO_VERSION}.linux-amd64.tar.gz"
  if [ -z "$GO_URL" ]; then
    GO_URL="https://go.dev/dl/${archive_name}"
  fi

  install_parent_dir="${1:-/usr/local}"
  mkdir -p "$install_parent_dir"
  install_parent_dir="$(cd "$install_parent_dir" && pwd)"
  target="$install_parent_dir/go"

  if [ -e "$target" ]; then
    if [ -r "$target/VERSION" ] && installed_version="$(head -n1 "$target/VERSION" 2>/dev/null)" \
       && [ "$installed_version" = "$GO_VERSION" ]; then
      echo "ensure-go: $target already has $GO_VERSION, skipping download" >&2
      echo "$target/bin/go"
      return 0
    fi
    # Do NOT trust it just because it is already there -- that is exactly
    # the silent-drift case this script exists to close.
    echo "ensure-go: $target exists but is not $GO_VERSION -- refusing to overwrite it" >&2
    echo "  expected VERSION: $GO_VERSION" >&2
    echo "  got:              ${installed_version:-<unreadable>}" >&2
    return 1
  fi

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN
  tmp="$tmpdir/$archive_name"

  echo "ensure-go: fetching $GO_VERSION from $GO_URL" >&2
  if ! fetch "$GO_URL" "$tmp"; then
    echo "ensure-go: download failed: $GO_URL" >&2
    return 1
  fi

  actual="$(sha256_of "$tmp")"
  if [ "$actual" != "$GO_ARCHIVE_SHA256" ]; then
    # Never leave an unverified archive extracted anywhere a caller might
    # find it -- a half-installed Go is worse than none, because "go is
    # present" is what every caller here checks for.
    echo "ensure-go: checksum mismatch for $GO_URL -- refusing to install" >&2
    echo "  expected: $GO_ARCHIVE_SHA256" >&2
    echo "  got:      $actual" >&2
    return 1
  fi

  tar -C "$install_parent_dir" -xzf "$tmp"
  echo "ensure-go: installed $target" >&2
  echo "$target/bin/go"
}

# Guard so scripts/ensure-go.test.sh can `source` this file -- to reuse
# sha256_of/fetch/main directly -- without main running on import.
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  main "$@"
fi
