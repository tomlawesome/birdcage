#!/usr/bin/env bash
set -euo pipefail

# Gates the licences of the pip packages installed into the mockingbird
# image -- the counterpart to scripts/licence-check.sh (Go modules) and
# scripts/licence-check-npm.sh (npm). Unlike either of those, nothing in
# this repository already installs the Python dependencies before this
# script runs (the npm gate rides inside test:frontend precisely because
# that job already has an installed node_modules; no Python job does), so
# this wrapper does the install itself: `pip install --require-hashes`
# against build/mockingbird/requirements.txt, same as the Dockerfile's
# honeypot stage, into a throwaway directory.
#
# A licence is not recorded anywhere in requirements.txt itself -- only a
# name, a version and a hash -- so there is no way to gate it without
# actually installing the packages and reading what each one's own
# metadata declares. That reading is licence-check-python.py's job; this
# wrapper only resolves paths, does the install, and forwards the exit
# code.
#
# PYTHON_PACKAGES_DIR lets tests (and anything else that already has an
# installed tree) point straight at it and skip the install, the same
# escape hatch NODE_MODULES_DIR gives licence-check-npm.sh.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REQUIREMENTS_FILE="${REQUIREMENTS_FILE:-$SCRIPT_DIR/../build/mockingbird/requirements.txt}"
POLICY_FILE="${POLICY_FILE:-$SCRIPT_DIR/../supply-chain/licence-policy.yml}"

if [ -n "${PYTHON_PACKAGES_DIR:-}" ]; then
  exec python3 "$SCRIPT_DIR/licence-check-python.py" "$PYTHON_PACKAGES_DIR" "$POLICY_FILE"
fi

if [ ! -f "$REQUIREMENTS_FILE" ]; then
  echo "licence-check-python: requirements file not found: $REQUIREMENTS_FILE" >&2
  exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# --require-hashes: the same integrity check the Dockerfile's honeypot
# stage runs, so a package swapped on PyPI fails this gate the same way
# it would fail the image build.
pip install --no-cache-dir --require-hashes --target "$work" -r "$REQUIREMENTS_FILE"

python3 "$SCRIPT_DIR/licence-check-python.py" "$work" "$POLICY_FILE"
