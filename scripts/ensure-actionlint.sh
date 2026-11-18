#!/usr/bin/env bash
# Installs a checksum-pinned actionlint into a directory, verifying it before
# any caller trusts it. Same shape as scripts/ensure-gitleaks.sh (and
# ensure-cosign.sh): exactly one place actionlint gets installed from, so the
# scan job and its self-test cannot drift onto two different binaries.
# CI-only, never linked or shipped. Slice 1 of #199: it lints the workflow files that decide what CI and the GitHub mirror run.
set -euo pipefail

# --- The pin. Bump these together for a new release; nothing else in this
# file should need to change. Deliberately not overridable by environment
# variable: this decides what is trusted to find (or miss) a defect, and a
# protected CI/CD variable is settable outside the repository entirely.
# --version/--sha256/--binary-sha256/--url are flags, written at the call
# site, and every call site lives in .gitlab-ci.yml or a test under scripts/.
ACTIONLINT_VERSION="v1.7.12"
# SHA-256 of actionlint_1.7.12_linux_amd64.tar.gz, copied from the release's
# own checksums file:
#   https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_checksums.txt
# fetched 2026-11-18. Cross-checked the same day against the SHA-256 GitHub
# records for the asset (release API "digest" field) and by hashing a
# separate local download -- all three matched. The release also carries a
# GitHub build-provenance attestation (SLSA v1, workflow release.yaml at
# tag v1.7.12) whose subject list names this archive; the attestation's
# presence and subjects were read via the GitHub attestations API on the
# same date (signature not re-verified with gh attestation verify).
ACTIONLINT_ARCHIVE_SHA256="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
# SHA-256 of the `actionlint` binary extracted from that same archive, computed
# locally the same day. Used only as the idempotency check below (if a
# binary is already at the target path with this hash, the archive is not
# re-fetched); the archive checksum above is what gates what gets installed.
ACTIONLINT_BINARY_SHA256="c872d6db8c6bf83a8eaa704fc93999f027d55dffbc63b8a6abdccb47df5f4cd4"

ACTIONLINT_URL=""
sha256_of() {
  sha256sum "$1" | awk '{print $1}'
}

# Thin wrapper around the actual byte transfer, kept as its own function so
# scripts/ensure-actionlint.test.sh can point it at a local fixture (file://)
# without touching the network, the same shape as ensure-cosign.sh.
fetch() {
  local url="$1" dest="$2"
  curl -fsSL "$url" -o "$dest"
}

# install_dir='' | resolved from $1, else $ACTIONLINT_INSTALL_DIR, else
# ~/.local/bin -- this host's convention for shared executables that don't
# belong to a package manager.
main() {
  local install_dir target actual tmp tmpdir archive_name

  while [ $# -gt 0 ]; do
    case "$1" in
      --version) [ $# -ge 2 ] || { echo "ensure-actionlint: --version needs a value" >&2; exit 2; }
        ACTIONLINT_VERSION="$2"; shift 2 ;;
      --sha256) [ $# -ge 2 ] || { echo "ensure-actionlint: --sha256 needs a value" >&2; exit 2; }
        ACTIONLINT_ARCHIVE_SHA256="$2"; shift 2 ;;
      --binary-sha256) [ $# -ge 2 ] || { echo "ensure-actionlint: --binary-sha256 needs a value" >&2; exit 2; }
        ACTIONLINT_BINARY_SHA256="$2"; shift 2 ;;
      --url) [ $# -ge 2 ] || { echo "ensure-actionlint: --url needs a value" >&2; exit 2; }
        ACTIONLINT_URL="$2"; shift 2 ;;
      --*) echo "ensure-actionlint: unknown option: $1" >&2; exit 2 ;;
      *) break ;;
    esac
  done

  archive_name="actionlint_${ACTIONLINT_VERSION#v}_linux_amd64.tar.gz"
  if [ -z "$ACTIONLINT_URL" ]; then
    ACTIONLINT_URL="https://github.com/rhysd/actionlint/releases/download/${ACTIONLINT_VERSION}/${archive_name}"
  fi

  install_dir="${1:-${ACTIONLINT_INSTALL_DIR:-$HOME/.local/bin}}"
  mkdir -p "$install_dir"
  install_dir="$(cd "$install_dir" && pwd)"
  target="$install_dir/actionlint"

  if [ -x "$target" ]; then
    actual="$(sha256_of "$target")"
    if [ "$actual" = "$ACTIONLINT_BINARY_SHA256" ]; then
      echo "ensure-actionlint: $target already matches the pinned checksum, skipping download" >&2
      echo "$target"
      return 0
    fi
    # Do NOT trust it just because it is already there and executable --
    # that is exactly the silent-drift case this script exists to close.
    echo "ensure-actionlint: $target exists but does not match the pinned checksum -- not trusting it, replacing it" >&2
    echo "  expected: $ACTIONLINT_BINARY_SHA256" >&2
    echo "  got:      $actual" >&2
  fi

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN
  tmp="$tmpdir/$archive_name"

  echo "ensure-actionlint: fetching actionlint ${ACTIONLINT_VERSION} from $ACTIONLINT_URL" >&2
  if ! fetch "$ACTIONLINT_URL" "$tmp"; then
    echo "ensure-actionlint: download failed: $ACTIONLINT_URL" >&2
    return 1
  fi

  actual="$(sha256_of "$tmp")"
  if [ "$actual" != "$ACTIONLINT_ARCHIVE_SHA256" ]; then
    # Never leave an unverified archive extracted anywhere a caller might
    # find it -- a half-installed actionlint is worse than none, because
    # "actionlint is present" is what every caller here checks for.
    echo "ensure-actionlint: checksum mismatch for $ACTIONLINT_URL -- refusing to install" >&2
    echo "  expected: $ACTIONLINT_ARCHIVE_SHA256" >&2
    echo "  got:      $actual" >&2
    return 1
  fi

  tar -xzf "$tmp" -C "$tmpdir" actionlint
  chmod +x "$tmpdir/actionlint"
  mv "$tmpdir/actionlint" "$target"
  echo "ensure-actionlint: installed $target" >&2
  echo "$target"
}

# Guard so scripts/ensure-actionlint.test.sh can `source` this file -- to
# reuse sha256_of/fetch/main directly -- without main running on import.
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  main "$@"
fi
