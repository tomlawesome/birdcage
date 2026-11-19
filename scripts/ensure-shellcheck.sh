#!/usr/bin/env bash
# Installs a checksum-pinned shellcheck into a directory, verifying it before
# any caller trusts it. Same shape as scripts/ensure-gitleaks.sh (and
# ensure-cosign.sh): exactly one place shellcheck gets installed from, so the
# scan job and its self-test cannot drift onto two different binaries.
# CI-only, never linked or shipped. Slice 1 of #199: it checks every tracked shell script for quoting and error-handling mistakes.
set -euo pipefail

# --- The pin. Bump these together for a new release; nothing else in this
# file should need to change. Deliberately not overridable by environment
# variable: this decides what is trusted to find (or miss) a defect, and a
# protected CI/CD variable is settable outside the repository entirely.
# --version/--sha256/--binary-sha256/--url are flags, written at the call
# site, and every call site lives in .gitlab-ci.yml or a test under scripts/.
SHELLCHECK_VERSION="v0.11.0"
# SHA-256 of shellcheck-v0.11.0.linux.x86_64.tar.xz. The publisher gives no
# checksums, signatures or attestations, and releases are not immutable, so
# this is our own hash, taken on 2026-11-18 from a local download and
# cross-checked against the SHA-256 GitHub records for the asset (release
# API "digest" field) and against a second, separate download -- all three
# matched (the gitleaks method). The archive is .tar.xz, so the image needs
# xz-utils.
SHELLCHECK_ARCHIVE_SHA256="8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198"
# SHA-256 of the `shellcheck` binary extracted from that same archive, computed
# locally the same day. Used only as the idempotency check below (if a
# binary is already at the target path with this hash, the archive is not
# re-fetched); the archive checksum above is what gates what gets installed.
SHELLCHECK_BINARY_SHA256="4da528ddb3a4d1b7b24a59d4e16eb2f5fd960f4bd9a3708a15baddbdf1d5a55b"

SHELLCHECK_URL=""
sha256_of() {
  sha256sum "$1" | awk '{print $1}'
}

# Thin wrapper around the actual byte transfer, kept as its own function so
# scripts/ensure-shellcheck.test.sh can point it at a local fixture (file://)
# without touching the network, the same shape as ensure-cosign.sh.
fetch() {
  local url="$1" dest="$2"
  curl -fsSL "$url" -o "$dest"
}

# install_dir='' | resolved from $1, else $SHELLCHECK_INSTALL_DIR, else
# ~/.local/bin -- this host's convention for shared executables that don't
# belong to a package manager.
main() {
  local install_dir target actual tmp tmpdir archive_name

  while [ $# -gt 0 ]; do
    case "$1" in
      --version) [ $# -ge 2 ] || { echo "ensure-shellcheck: --version needs a value" >&2; exit 2; }
        SHELLCHECK_VERSION="$2"; shift 2 ;;
      --sha256) [ $# -ge 2 ] || { echo "ensure-shellcheck: --sha256 needs a value" >&2; exit 2; }
        SHELLCHECK_ARCHIVE_SHA256="$2"; shift 2 ;;
      --binary-sha256) [ $# -ge 2 ] || { echo "ensure-shellcheck: --binary-sha256 needs a value" >&2; exit 2; }
        SHELLCHECK_BINARY_SHA256="$2"; shift 2 ;;
      --url) [ $# -ge 2 ] || { echo "ensure-shellcheck: --url needs a value" >&2; exit 2; }
        SHELLCHECK_URL="$2"; shift 2 ;;
      --*) echo "ensure-shellcheck: unknown option: $1" >&2; exit 2 ;;
      *) break ;;
    esac
  done

  archive_name="shellcheck-${SHELLCHECK_VERSION}.linux.x86_64.tar.xz"
  if [ -z "$SHELLCHECK_URL" ]; then
    SHELLCHECK_URL="https://github.com/koalaman/shellcheck/releases/download/${SHELLCHECK_VERSION}/${archive_name}"
  fi

  install_dir="${1:-${SHELLCHECK_INSTALL_DIR:-$HOME/.local/bin}}"
  mkdir -p "$install_dir"
  install_dir="$(cd "$install_dir" && pwd)"
  target="$install_dir/shellcheck"

  if [ -x "$target" ]; then
    actual="$(sha256_of "$target")"
    if [ "$actual" = "$SHELLCHECK_BINARY_SHA256" ]; then
      echo "ensure-shellcheck: $target already matches the pinned checksum, skipping download" >&2
      echo "$target"
      return 0
    fi
    # Do NOT trust it just because it is already there and executable --
    # that is exactly the silent-drift case this script exists to close.
    echo "ensure-shellcheck: $target exists but does not match the pinned checksum -- not trusting it, replacing it" >&2
    echo "  expected: $SHELLCHECK_BINARY_SHA256" >&2
    echo "  got:      $actual" >&2
  fi

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN
  tmp="$tmpdir/$archive_name"

  echo "ensure-shellcheck: fetching shellcheck ${SHELLCHECK_VERSION} from $SHELLCHECK_URL" >&2
  if ! fetch "$SHELLCHECK_URL" "$tmp"; then
    echo "ensure-shellcheck: download failed: $SHELLCHECK_URL" >&2
    return 1
  fi

  actual="$(sha256_of "$tmp")"
  if [ "$actual" != "$SHELLCHECK_ARCHIVE_SHA256" ]; then
    # Never leave an unverified archive extracted anywhere a caller might
    # find it -- a half-installed shellcheck is worse than none, because
    # "shellcheck is present" is what every caller here checks for.
    echo "ensure-shellcheck: checksum mismatch for $SHELLCHECK_URL -- refusing to install" >&2
    echo "  expected: $SHELLCHECK_ARCHIVE_SHA256" >&2
    echo "  got:      $actual" >&2
    return 1
  fi

  command -v xz >/dev/null 2>&1 || {
    echo "ensure-shellcheck: xz is needed to unpack the .tar.xz release (apt-get install xz-utils)" >&2
    return 1
  }
  tar -xJf "$tmp" -C "$tmpdir" "shellcheck-${SHELLCHECK_VERSION}/shellcheck"
  chmod +x "$tmpdir/shellcheck-${SHELLCHECK_VERSION}/shellcheck"
  mv "$tmpdir/shellcheck-${SHELLCHECK_VERSION}/shellcheck" "$target"
  echo "ensure-shellcheck: installed $target" >&2
  echo "$target"
}

# Guard so scripts/ensure-shellcheck.test.sh can `source` this file -- to
# reuse sha256_of/fetch/main directly -- without main running on import.
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  main "$@"
fi
