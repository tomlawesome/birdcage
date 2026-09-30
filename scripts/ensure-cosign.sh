#!/usr/bin/env bash
# Installs a checksum-pinned cosign into a directory, verifying it before
# any caller trusts it. Every cosign advisory open right now is a
# *verification* bug -- including a high-severity identity-pinning bypass --
# so a verifier running whatever cosign happened to be lying around, or
# whatever a package mirror serves this week, can fail open silently. The
# fix is not "use cosign carefully", it is "there is exactly one place
# cosign gets installed from, and the signer and every verifier all go
# through it": this script. Nothing here should ever be duplicated into a
# second copy that could drift from this one.
set -euo pipefail

# --- The pin. Bump these two together for a new release; nothing else in
# this file should need to change.
#
# Deliberately NOT overridable by environment variable. The obvious shape
# here is "${COSIGN_SHA256:-<default>}", and it would be wrong: this is the
# binary that decides whether anything gets published, and on this GitLab
# (CE) a protected CI/CD variable is readable -- and settable -- outside the
# repository entirely, so an environment override is a way to weaken the
# verifier without touching a tracked file. The flags below exist for the
# one caller that legitimately needs synthetic values, the test harness.
# A flag has to be written at the call site, and every call site lives in
# .gitlab-ci.yml, which is on supply-chain/policy-files.txt -- so weakening
# the pin moves the policy version and cannot pass unnoticed.
COSIGN_VERSION="v3.1.3"
# SHA-256 of cosign-linux-amd64 (the linux-amd64 release binary), copied
# from the release's own checksums file:
#   https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign_checksums.txt
# fetched 2026-09-20. Cross-checked the same day by separately downloading
# cosign-linux-amd64 itself and hashing it locally -- the two matched.
COSIGN_LINUX_AMD64_SHA256="4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"

# What this pin is, and is not: it is trust-on-first-use. We looked at what
# GitHub served for this URL once, on the date above, and wrote the hash
# down so it cannot drift after that without this script noticing. It does
# NOT prove Sigstore built this binary from the tagged source -- that would
# mean verifying the release's own signing/attestation chain, which this
# script does not do (and which would be circular for the very binary this
# repository uses to do its own verifying). What it buys is narrower and
# still real: once recorded, a compromised upload, a tampered mirror, or a
# corrupted download all produce a byte-for-byte mismatch here, and this
# script refuses to hand back a binary that doesn't match.

# Where the pinned binary is served from. Set from the version above unless
# --url says otherwise; curl handles file:// the same as https://, so a test
# can point this at a local fixture without the download path knowing.
COSIGN_URL=""

sha256_of() {
  sha256sum "$1" | awk '{print $1}'
}

# Thin wrapper around the actual byte transfer. Kept as its own function,
# rather than inlined into main, so a caller that sources this script
# (as scripts/ensure-cosign.test.sh does) can redefine it if COSIGN_URL's
# file:// override is not enough for some future test.
fetch() {
  local url="$1" dest="$2"
  curl -fsSL "$url" -o "$dest"
}

# install_dir='' | resolved from $1, else $COSIGN_INSTALL_DIR, else
# ~/.local/bin -- this host's convention for shared executables that
# don't belong to a package manager.
main() {
  local install_dir target actual tmp

  # --version, --sha256 and --url are the only overrides, and all three are
  # flags rather than environment variables, for the reason given above the
  # pin. Anything else is rejected rather than ignored: a mistyped flag that
  # silently falls back to the real pin would make a test look like it proved
  # something it did not.
  while [ $# -gt 0 ]; do
    case "$1" in
      --version) [ $# -ge 2 ] || { echo "ensure-cosign: --version needs a value" >&2; exit 2; }
        COSIGN_VERSION="$2"; shift 2 ;;
      --sha256) [ $# -ge 2 ] || { echo "ensure-cosign: --sha256 needs a value" >&2; exit 2; }
        COSIGN_LINUX_AMD64_SHA256="$2"; shift 2 ;;
      --url) [ $# -ge 2 ] || { echo "ensure-cosign: --url needs a value" >&2; exit 2; }
        COSIGN_URL="$2"; shift 2 ;;
      --*) echo "ensure-cosign: unknown option: $1" >&2; exit 2 ;;
      *) break ;;
    esac
  done

  if [ -z "$COSIGN_URL" ]; then
    COSIGN_URL="https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
  fi

  install_dir="${1:-${COSIGN_INSTALL_DIR:-$HOME/.local/bin}}"
  mkdir -p "$install_dir"
  install_dir="$(cd "$install_dir" && pwd)"
  target="$install_dir/cosign"

  if [ -x "$target" ]; then
    actual="$(sha256_of "$target")"
    if [ "$actual" = "$COSIGN_LINUX_AMD64_SHA256" ]; then
      echo "ensure-cosign: $target already matches the pinned checksum, skipping download" >&2
      echo "$target"
      return 0
    fi
    # Do NOT trust it just because it is already there and executable --
    # that is exactly the silent-drift case this script exists to close.
    # Fall through and replace it with a freshly verified copy.
    echo "ensure-cosign: $target exists but does not match the pinned checksum -- not trusting it, replacing it" >&2
    echo "  expected: $COSIGN_LINUX_AMD64_SHA256" >&2
    echo "  got:      $actual" >&2
  fi

  tmp="$(mktemp)"
  echo "ensure-cosign: fetching cosign ${COSIGN_VERSION} from $COSIGN_URL" >&2
  if ! fetch "$COSIGN_URL" "$tmp"; then
    rm -f "$tmp"
    echo "ensure-cosign: download failed: $COSIGN_URL" >&2
    return 1
  fi

  actual="$(sha256_of "$tmp")"
  if [ "$actual" != "$COSIGN_LINUX_AMD64_SHA256" ]; then
    # Never leave an unverified binary behind, at the temp path or the
    # target path -- a half-installed cosign is worse than none, because
    # "cosign is present" is what every caller here checks for.
    rm -f "$tmp"
    echo "ensure-cosign: checksum mismatch for $COSIGN_URL -- refusing to install" >&2
    echo "  expected: $COSIGN_LINUX_AMD64_SHA256" >&2
    echo "  got:      $actual" >&2
    return 1
  fi

  chmod +x "$tmp"
  mv "$tmp" "$target"
  echo "ensure-cosign: installed $target" >&2
  echo "$target"
}

# Guard so scripts/ensure-cosign.test.sh can `source` this file -- to
# reuse sha256_of/fetch/main directly -- without main running on import.
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  main "$@"
fi
