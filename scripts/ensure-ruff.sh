#!/usr/bin/env bash
# Installs a checksum-pinned ruff into a directory, verifying it before
# any caller trusts it. Same shape as scripts/ensure-gitleaks.sh (and
# ensure-cosign.sh): exactly one place ruff gets installed from, so the
# scan job and its self-test cannot drift onto two different binaries.
# CI-only, never linked or shipped. Slice 1 of #199: it scans the Python helper scripts for security mistakes (S rules only).
set -euo pipefail

# --- The pin. Bump these together for a new release; nothing else in this
# file should need to change. Deliberately not overridable by environment
# variable: this decides what is trusted to find (or miss) a defect, and a
# protected CI/CD variable is settable outside the repository entirely.
# --version/--sha256/--binary-sha256/--url are flags, written at the call
# site, and every call site lives in .gitlab-ci.yml or a test under scripts/.
RUFF_VERSION="0.17.5"
# SHA-256 of ruff-x86_64-unknown-linux-musl.tar.gz, copied from the
# release's own per-asset checksum file:
#   https://github.com/astral-sh/ruff/releases/download/0.17.5/ruff-x86_64-unknown-linux-musl.tar.gz.sha256
# fetched 2026-11-18. Cross-checked the same day against the SHA-256 GitHub
# records for the asset (release API "digest" field) and by hashing a
# separate local download -- all three matched. The release also carries
# GitHub attestations (release v0.2 and SLSA v1 provenance, workflow
# release.yml) listing this archive's digest as a subject; read via the
# GitHub attestations API on the same date (signature not re-verified with
# gh attestation verify). Not installed with pip.
RUFF_ARCHIVE_SHA256="dc94b7e225b8910fb6f55298ada32d00e356dbd195a5ffb647847f388cb54f84"
# SHA-256 of the `ruff` binary extracted from that same archive, computed
# locally the same day. Used only as the idempotency check below (if a
# binary is already at the target path with this hash, the archive is not
# re-fetched); the archive checksum above is what gates what gets installed.
RUFF_BINARY_SHA256="3cabf0c94dc8d6e7271564d046d68ac11650e2e0eb3fe55dadf3c6bf8d009eb7"

RUFF_URL=""
sha256_of() {
  sha256sum "$1" | awk '{print $1}'
}

# Thin wrapper around the actual byte transfer, kept as its own function so
# scripts/ensure-ruff.test.sh can point it at a local fixture (file://)
# without touching the network, the same shape as ensure-cosign.sh.
fetch() {
  local url="$1" dest="$2"
  curl -fsSL "$url" -o "$dest"
}

# install_dir='' | resolved from $1, else $RUFF_INSTALL_DIR, else
# ~/.local/bin -- this host's convention for shared executables that don't
# belong to a package manager.
main() {
  local install_dir target actual tmp tmpdir archive_name

  while [ $# -gt 0 ]; do
    case "$1" in
      --version) [ $# -ge 2 ] || { echo "ensure-ruff: --version needs a value" >&2; exit 2; }
        RUFF_VERSION="$2"; shift 2 ;;
      --sha256) [ $# -ge 2 ] || { echo "ensure-ruff: --sha256 needs a value" >&2; exit 2; }
        RUFF_ARCHIVE_SHA256="$2"; shift 2 ;;
      --binary-sha256) [ $# -ge 2 ] || { echo "ensure-ruff: --binary-sha256 needs a value" >&2; exit 2; }
        RUFF_BINARY_SHA256="$2"; shift 2 ;;
      --url) [ $# -ge 2 ] || { echo "ensure-ruff: --url needs a value" >&2; exit 2; }
        RUFF_URL="$2"; shift 2 ;;
      --*) echo "ensure-ruff: unknown option: $1" >&2; exit 2 ;;
      *) break ;;
    esac
  done

  archive_name="ruff-x86_64-unknown-linux-musl.tar.gz"
  if [ -z "$RUFF_URL" ]; then
    RUFF_URL="https://github.com/astral-sh/ruff/releases/download/${RUFF_VERSION}/${archive_name}"
  fi

  install_dir="${1:-${RUFF_INSTALL_DIR:-$HOME/.local/bin}}"
  mkdir -p "$install_dir"
  install_dir="$(cd "$install_dir" && pwd)"
  target="$install_dir/ruff"

  if [ -x "$target" ]; then
    actual="$(sha256_of "$target")"
    if [ "$actual" = "$RUFF_BINARY_SHA256" ]; then
      echo "ensure-ruff: $target already matches the pinned checksum, skipping download" >&2
      echo "$target"
      return 0
    fi
    # Do NOT trust it just because it is already there and executable --
    # that is exactly the silent-drift case this script exists to close.
    echo "ensure-ruff: $target exists but does not match the pinned checksum -- not trusting it, replacing it" >&2
    echo "  expected: $RUFF_BINARY_SHA256" >&2
    echo "  got:      $actual" >&2
  fi

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN
  tmp="$tmpdir/$archive_name"

  echo "ensure-ruff: fetching ruff ${RUFF_VERSION} from $RUFF_URL" >&2
  if ! fetch "$RUFF_URL" "$tmp"; then
    echo "ensure-ruff: download failed: $RUFF_URL" >&2
    return 1
  fi

  actual="$(sha256_of "$tmp")"
  if [ "$actual" != "$RUFF_ARCHIVE_SHA256" ]; then
    # Never leave an unverified archive extracted anywhere a caller might
    # find it -- a half-installed ruff is worse than none, because
    # "ruff is present" is what every caller here checks for.
    echo "ensure-ruff: checksum mismatch for $RUFF_URL -- refusing to install" >&2
    echo "  expected: $RUFF_ARCHIVE_SHA256" >&2
    echo "  got:      $actual" >&2
    return 1
  fi

  tar -xzf "$tmp" -C "$tmpdir" ruff-x86_64-unknown-linux-musl/ruff
  chmod +x "$tmpdir/ruff-x86_64-unknown-linux-musl/ruff"
  mv "$tmpdir/ruff-x86_64-unknown-linux-musl/ruff" "$target"
  echo "ensure-ruff: installed $target" >&2
  echo "$target"
}

# Guard so scripts/ensure-ruff.test.sh can `source` this file -- to
# reuse sha256_of/fetch/main directly -- without main running on import.
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  main "$@"
fi
