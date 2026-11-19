#!/usr/bin/env bash
# Installs a checksum-pinned zizmor into a directory, verifying it before
# any caller trusts it. Same shape as scripts/ensure-gitleaks.sh (and
# ensure-cosign.sh): exactly one place zizmor gets installed from, so the
# scan job and its self-test cannot drift onto two different binaries.
# CI-only, never linked or shipped. Slice 1 of #199: it audits the workflow files for injection and permission mistakes.
set -euo pipefail

# --- The pin. Bump these together for a new release; nothing else in this
# file should need to change. Deliberately not overridable by environment
# variable: this decides what is trusted to find (or miss) a defect, and a
# protected CI/CD variable is settable outside the repository entirely.
# --version/--sha256/--binary-sha256/--url are flags, written at the call
# site, and every call site lives in .gitlab-ci.yml or a test under scripts/.
ZIZMOR_VERSION="v1.32.0"
# SHA-256 of zizmor-x86_64-unknown-linux-gnu.tar.gz. The publisher ships no
# checksums file, so this is our own hash, taken on 2026-11-18 from a local
# download and cross-checked against the SHA-256 GitHub records for the
# asset (release API "digest" field) -- the two matched. GitHub attestations
# exist for the release (a release attestation for tag v1.32.0 and an SLSA
# v1 provenance, workflow release.yml at tag v1.32.0) and both list this
# archive's digest as a subject; read via the GitHub attestations API on the
# same date (signature not re-verified with gh attestation verify). The
# GitHub binary is used, not the PyPI wheel, which carries no PyPI provenance.
ZIZMOR_ARCHIVE_SHA256="bb110cc765eca9cd7efb2e284a956be5974c60027b0970f16397d86208a9957b"
# SHA-256 of the `zizmor` binary extracted from that same archive, computed
# locally the same day. Used only as the idempotency check below (if a
# binary is already at the target path with this hash, the archive is not
# re-fetched); the archive checksum above is what gates what gets installed.
ZIZMOR_BINARY_SHA256="04d55fb88e582a8e9a9ce6b4753df723fc44c35e0d1a8e8771db9e017066c6df"

ZIZMOR_URL=""
sha256_of() {
  sha256sum "$1" | awk '{print $1}'
}

# Thin wrapper around the actual byte transfer, kept as its own function so
# scripts/ensure-zizmor.test.sh can point it at a local fixture (file://)
# without touching the network, the same shape as ensure-cosign.sh.
fetch() {
  local url="$1" dest="$2"
  curl -fsSL "$url" -o "$dest"
}

# install_dir='' | resolved from $1, else $ZIZMOR_INSTALL_DIR, else
# ~/.local/bin -- this host's convention for shared executables that don't
# belong to a package manager.
main() {
  local install_dir target actual tmp tmpdir archive_name

  while [ $# -gt 0 ]; do
    case "$1" in
      --version) [ $# -ge 2 ] || { echo "ensure-zizmor: --version needs a value" >&2; exit 2; }
        ZIZMOR_VERSION="$2"; shift 2 ;;
      --sha256) [ $# -ge 2 ] || { echo "ensure-zizmor: --sha256 needs a value" >&2; exit 2; }
        ZIZMOR_ARCHIVE_SHA256="$2"; shift 2 ;;
      --binary-sha256) [ $# -ge 2 ] || { echo "ensure-zizmor: --binary-sha256 needs a value" >&2; exit 2; }
        ZIZMOR_BINARY_SHA256="$2"; shift 2 ;;
      --url) [ $# -ge 2 ] || { echo "ensure-zizmor: --url needs a value" >&2; exit 2; }
        ZIZMOR_URL="$2"; shift 2 ;;
      --*) echo "ensure-zizmor: unknown option: $1" >&2; exit 2 ;;
      *) break ;;
    esac
  done

  archive_name="zizmor-x86_64-unknown-linux-gnu.tar.gz"
  if [ -z "$ZIZMOR_URL" ]; then
    ZIZMOR_URL="https://github.com/zizmorcore/zizmor/releases/download/${ZIZMOR_VERSION}/${archive_name}"
  fi

  install_dir="${1:-${ZIZMOR_INSTALL_DIR:-$HOME/.local/bin}}"
  mkdir -p "$install_dir"
  install_dir="$(cd "$install_dir" && pwd)"
  target="$install_dir/zizmor"

  if [ -x "$target" ]; then
    actual="$(sha256_of "$target")"
    if [ "$actual" = "$ZIZMOR_BINARY_SHA256" ]; then
      echo "ensure-zizmor: $target already matches the pinned checksum, skipping download" >&2
      echo "$target"
      return 0
    fi
    # Do NOT trust it just because it is already there and executable --
    # that is exactly the silent-drift case this script exists to close.
    echo "ensure-zizmor: $target exists but does not match the pinned checksum -- not trusting it, replacing it" >&2
    echo "  expected: $ZIZMOR_BINARY_SHA256" >&2
    echo "  got:      $actual" >&2
  fi

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN
  tmp="$tmpdir/$archive_name"

  echo "ensure-zizmor: fetching zizmor ${ZIZMOR_VERSION} from $ZIZMOR_URL" >&2
  if ! fetch "$ZIZMOR_URL" "$tmp"; then
    echo "ensure-zizmor: download failed: $ZIZMOR_URL" >&2
    return 1
  fi

  actual="$(sha256_of "$tmp")"
  if [ "$actual" != "$ZIZMOR_ARCHIVE_SHA256" ]; then
    # Never leave an unverified archive extracted anywhere a caller might
    # find it -- a half-installed zizmor is worse than none, because
    # "zizmor is present" is what every caller here checks for.
    echo "ensure-zizmor: checksum mismatch for $ZIZMOR_URL -- refusing to install" >&2
    echo "  expected: $ZIZMOR_ARCHIVE_SHA256" >&2
    echo "  got:      $actual" >&2
    return 1
  fi

  tar -xzf "$tmp" -C "$tmpdir" zizmor
  chmod +x "$tmpdir/zizmor"
  mv "$tmpdir/zizmor" "$target"
  echo "ensure-zizmor: installed $target" >&2
  echo "$target"
}

# Guard so scripts/ensure-zizmor.test.sh can `source` this file -- to
# reuse sha256_of/fetch/main directly -- without main running on import.
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  main "$@"
fi
