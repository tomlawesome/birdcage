#!/usr/bin/env bash
# Installs a checksum-pinned gitleaks into a directory, verifying it before
# any caller trusts it. Mirrors scripts/ensure-cosign.sh -- same reasoning,
# same shape: exactly one place gitleaks gets installed from, so the scan
# job and its self-test cannot drift onto two different binaries, and
# nothing here should ever be duplicated into a second copy.
#
# gitleaks does pattern/entropy detection over this (public) repository's
# full history and prints what it finds; a tampered download that lied
# about what it matched, or matched nothing, would be worse than not
# running it at all -- see issue #28's acceptance criteria (checksum-
# verified release, not an unpinned download).
set -euo pipefail

# --- The pin. Bump these together for a new release; nothing else in this
# file should need to change. Deliberately not overridable by environment
# variable, for the same reason ensure-cosign.sh gives: this decides what
# is trusted to find (or miss) a secret, and a protected CI/CD variable is
# settable outside the repository entirely. --version/--sha256/--url are
# flags, written at the call site, and every call site lives in
# .gitlab-ci.yml or a test under scripts/.
GITLEAKS_VERSION="v8.30.1"
# SHA-256 of gitleaks_8.30.1_linux_x64.tar.gz, copied from the release's own
# checksums file:
#   https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt
# fetched 2026-09-27. Cross-checked the same day by separately downloading
# the archive and hashing it locally -- the two matched.
GITLEAKS_ARCHIVE_SHA256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
# SHA-256 of the `gitleaks` binary extracted from that same archive,
# computed locally the same day. Used only as the idempotency check below
# (if a binary is already at the target path with this hash, the archive
# is not re-fetched); the archive checksum above is what actually gates
# what gets installed.
GITLEAKS_BINARY_SHA256="88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509"

GITLEAKS_URL=""

sha256_of() {
  sha256sum "$1" | awk '{print $1}'
}

# Thin wrapper around the actual byte transfer, kept as its own function so
# scripts/ensure-gitleaks.test.sh can point it at a local fixture (file://)
# without touching the network, the same shape as ensure-cosign.sh.
fetch() {
  local url="$1" dest="$2"
  curl -fsSL "$url" -o "$dest"
}

# install_dir='' | resolved from $1, else $GITLEAKS_INSTALL_DIR, else
# ~/.local/bin -- this host's convention for shared executables that don't
# belong to a package manager.
main() {
  local install_dir target actual tmp tmpdir archive_name

  while [ $# -gt 0 ]; do
    case "$1" in
      --version) [ $# -ge 2 ] || { echo "ensure-gitleaks: --version needs a value" >&2; exit 2; }
        GITLEAKS_VERSION="$2"; shift 2 ;;
      --sha256) [ $# -ge 2 ] || { echo "ensure-gitleaks: --sha256 needs a value" >&2; exit 2; }
        GITLEAKS_ARCHIVE_SHA256="$2"; shift 2 ;;
      --binary-sha256) [ $# -ge 2 ] || { echo "ensure-gitleaks: --binary-sha256 needs a value" >&2; exit 2; }
        GITLEAKS_BINARY_SHA256="$2"; shift 2 ;;
      --url) [ $# -ge 2 ] || { echo "ensure-gitleaks: --url needs a value" >&2; exit 2; }
        GITLEAKS_URL="$2"; shift 2 ;;
      --*) echo "ensure-gitleaks: unknown option: $1" >&2; exit 2 ;;
      *) break ;;
    esac
  done

  archive_name="gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz"
  if [ -z "$GITLEAKS_URL" ]; then
    GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/${archive_name}"
  fi

  install_dir="${1:-${GITLEAKS_INSTALL_DIR:-$HOME/.local/bin}}"
  mkdir -p "$install_dir"
  install_dir="$(cd "$install_dir" && pwd)"
  target="$install_dir/gitleaks"

  if [ -x "$target" ]; then
    actual="$(sha256_of "$target")"
    if [ "$actual" = "$GITLEAKS_BINARY_SHA256" ]; then
      echo "ensure-gitleaks: $target already matches the pinned checksum, skipping download" >&2
      echo "$target"
      return 0
    fi
    # Do NOT trust it just because it is already there and executable --
    # that is exactly the silent-drift case this script exists to close.
    echo "ensure-gitleaks: $target exists but does not match the pinned checksum -- not trusting it, replacing it" >&2
    echo "  expected: $GITLEAKS_BINARY_SHA256" >&2
    echo "  got:      $actual" >&2
  fi

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN
  tmp="$tmpdir/$archive_name"

  echo "ensure-gitleaks: fetching gitleaks ${GITLEAKS_VERSION} from $GITLEAKS_URL" >&2
  if ! fetch "$GITLEAKS_URL" "$tmp"; then
    echo "ensure-gitleaks: download failed: $GITLEAKS_URL" >&2
    return 1
  fi

  actual="$(sha256_of "$tmp")"
  if [ "$actual" != "$GITLEAKS_ARCHIVE_SHA256" ]; then
    # Never leave an unverified archive extracted anywhere a caller might
    # find it -- a half-installed gitleaks is worse than none, because
    # "gitleaks is present" is what every caller here checks for.
    echo "ensure-gitleaks: checksum mismatch for $GITLEAKS_URL -- refusing to install" >&2
    echo "  expected: $GITLEAKS_ARCHIVE_SHA256" >&2
    echo "  got:      $actual" >&2
    return 1
  fi

  tar -xzf "$tmp" -C "$tmpdir" gitleaks
  chmod +x "$tmpdir/gitleaks"
  mv "$tmpdir/gitleaks" "$target"
  echo "ensure-gitleaks: installed $target" >&2
  echo "$target"
}

# Guard so scripts/ensure-gitleaks.test.sh can `source` this file -- to
# reuse sha256_of/fetch/main directly -- without main running on import.
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  main "$@"
fi
