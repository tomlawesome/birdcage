#!/usr/bin/env bash
set -euo pipefail

# Gates the licences of the npm packages under frontend/node_modules --
# the counterpart to scripts/licence-check.sh, which gates the Go modules
# linked into the Birdcage binary. Unlike the Go script, this one does
# not reason from a "what ships" dependency list: the frontend has no
# runtime `dependencies` at all, but Svelte compiles its runtime helpers
# into the built bundle regardless, so the whole installed tree is in
# scope, not just direct dependencies.
#
# The real work (walking node_modules, reading each package.json's
# licence field in its several shapes) is in licence-check-npm.py.
# Python's stdlib json module handles that parsing without adding a
# dependency, which a licence checker installed from npm would not.
# This wrapper only resolves default paths and forwards the exit code,
# so tests can point NODE_MODULES_DIR and POLICY_FILE at fixtures.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NODE_MODULES_DIR="${NODE_MODULES_DIR:-$SCRIPT_DIR/../frontend/node_modules}"
POLICY_FILE="${POLICY_FILE:-$SCRIPT_DIR/../supply-chain/licence-policy.yml}"

exec python3 "$SCRIPT_DIR/licence-check-npm.py" "$NODE_MODULES_DIR" "$POLICY_FILE"
