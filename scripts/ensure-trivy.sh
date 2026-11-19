#!/usr/bin/env bash
# Installs a pinned, signature- and checksum-verified Trivy into a directory
# (#199 items 1-3, owner decision 66a). Same shape as scripts/ensure-gitleaks.sh,
# with one more gate: the release's checksums file is verified with cosign
# (obtained only through scripts/ensure-cosign.sh, never a cosign found on
# PATH), and the tarball's line in it must equal the pin below, which in turn
# must equal the tarball's real hash. Nothing is installed unless all three
# agree.
#
# Why the extra gate: Trivy's own release channels were hijacked in March 2026
# (CVE-2026-33634), so a hash copied from the same place as the download proves
# little. The Sigstore bundle ties the checksums file to the upstream release
# workflow at this exact tag. Verified by hand against the real v0.76.2
# release on 2026-11-19 ("Verified OK").
#
# Usage: ensure-trivy.sh [--sha256 H] [--base-url URL] <install_dir>
# --base-url is a directory URL holding the three release files; --sha256
# replaces the pinned tarball hash. Both exist for scripts/ensure-trivy.test.sh
# (file:// fixtures); every real call site passes neither. Prints the installed
# path on stdout.
set -euo pipefail

# --- The pin. Bump the version, the asset name's version and the hash
# together, and the identity below (it names the release tag). Deliberately
# not overridable from the environment: this decides what is trusted to report
# vulnerabilities, and a protected CI/CD variable is settable outside the
# repository.
TRIVY_VERSION="v0.76.2"
TRIVY_ARCHIVE="trivy_0.76.2_Linux-64bit.tar.gz"
TRIVY_CHECKSUMS="trivy_0.76.2_checksums.txt"
# SHA-256 of $TRIVY_ARCHIVE, from the release's signed checksums file.
TRIVY_ARCHIVE_SHA256="bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf"
TRIVY_BASE_URL=""

fetch() {
  curl -fsSL "$1" -o "$2"
}

sha256_of() {
  sha256sum "$1" | awk '{print $1}'
}

die() {
  echo "ensure-trivy: $*" >&2
  return 1
}

main() {
  local here install_dir tmpdir cosign_bin line_hash actual

  while [ $# -gt 0 ]; do
    case "$1" in
      --sha256) [ $# -ge 2 ] || { echo "ensure-trivy: --sha256 needs a value" >&2; exit 2; }
        TRIVY_ARCHIVE_SHA256="$2"; shift 2 ;;
      --base-url) [ $# -ge 2 ] || { echo "ensure-trivy: --base-url needs a value" >&2; exit 2; }
        TRIVY_BASE_URL="$2"; shift 2 ;;
      --*) echo "ensure-trivy: unknown option: $1" >&2; exit 2 ;;
      *) break ;;
    esac
  done
  [ -n "$TRIVY_BASE_URL" ] || TRIVY_BASE_URL="https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}"
  TRIVY_BASE_URL="${TRIVY_BASE_URL%/}"

  install_dir="${1:-${TRIVY_INSTALL_DIR:-$HOME/.local/bin}}"
  mkdir -p "$install_dir"
  install_dir="$(cd "$install_dir" && pwd)"

  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN

  cosign_bin="$("$here/ensure-cosign.sh" "$tmpdir/cosign-bin")" || { die "could not get cosign from ensure-cosign.sh"; return 1; }

  echo "ensure-trivy: fetching Trivy ${TRIVY_VERSION} from $TRIVY_BASE_URL" >&2
  local f
  for f in "$TRIVY_ARCHIVE" "$TRIVY_CHECKSUMS" "${TRIVY_CHECKSUMS}.sigstore.json"; do
    fetch "$TRIVY_BASE_URL/$f" "$tmpdir/$f" || { die "download failed: $TRIVY_BASE_URL/$f"; return 1; }
  done

  # 1. The checksums file is the upstream release workflow's, at this tag.
  # The identity is exact (never a regexp) and names the tag literally, so
  # bumping TRIVY_VERSION without it fails here rather than trusting a
  # different release.
  "$cosign_bin" verify-blob --bundle "$tmpdir/${TRIVY_CHECKSUMS}.sigstore.json" --certificate-identity https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.76.2 --certificate-oidc-issuer https://token.actions.githubusercontent.com "$tmpdir/$TRIVY_CHECKSUMS" >&2 \
    || { die "signature verification of $TRIVY_CHECKSUMS failed -- refusing to install"; return 1; }

  # 2. The tarball's line in the (now trusted) checksums file equals the pin.
  line_hash="$(awk -v a="$TRIVY_ARCHIVE" '$2==a {print $1; exit}' "$tmpdir/$TRIVY_CHECKSUMS")"
  if [ -z "$line_hash" ]; then
    die "no line for $TRIVY_ARCHIVE in $TRIVY_CHECKSUMS -- refusing to install"; return 1
  fi
  if [ "$line_hash" != "$TRIVY_ARCHIVE_SHA256" ]; then
    die "$TRIVY_CHECKSUMS lists $line_hash for $TRIVY_ARCHIVE, the pin is $TRIVY_ARCHIVE_SHA256 -- refusing to install"; return 1
  fi

  # 3. The tarball itself equals the pin.
  actual="$(sha256_of "$tmpdir/$TRIVY_ARCHIVE")"
  if [ "$actual" != "$TRIVY_ARCHIVE_SHA256" ]; then
    die "checksum mismatch for $TRIVY_ARCHIVE (expected $TRIVY_ARCHIVE_SHA256, got $actual) -- refusing to install"; return 1
  fi

  mkdir "$tmpdir/x"
  tar -xzf "$tmpdir/$TRIVY_ARCHIVE" -C "$tmpdir/x" trivy
  chmod +x "$tmpdir/x/trivy"
  mv "$tmpdir/x/trivy" "$install_dir/trivy"
  echo "ensure-trivy: installed $install_dir/trivy" >&2
  echo "$install_dir/trivy"
}

# Guard so a test can `source` this file without running main.
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  main "$@"
fi
