#!/usr/bin/env bash
# The one place the gitleaks scan command is written, so the CI job
# (lint:gitleaks) and its self-test (scripts/gitleaks-scan.test.sh) run the
# exact same invocation -- issue #28's acceptance criteria:
#   1. scans full history, not just the working tree
#   3/4. redacted output, no secret value ever printed (this repository is
#        public; an unredacted log would republish the secret it just found)
# Full history depends on the caller's checkout being unshallow -- the
# lint:gitleaks job sets GIT_DEPTH: 0 for that; this script only chooses
# what gitleaks does with whatever history is actually present.
set -euo pipefail

GITLEAKS_BIN="${GITLEAKS_BIN:-gitleaks}"
repo="${1:-.}"

if ! command -v "$GITLEAKS_BIN" >/dev/null 2>&1 && [ ! -x "$GITLEAKS_BIN" ]; then
  echo "gitleaks-scan: gitleaks not found (GITLEAKS_BIN=$GITLEAKS_BIN)" >&2
  exit 127
fi

# `git` mode reads commit history at $repo rather than only the working
# tree. --redact (default 100%) is never omitted: this command is the only
# place that decides that, so no caller can accidentally run it unredacted.
# -v prints which file, commit and rule matched -- useful for triage --
# but never the secret text itself: --redact still applies to every field
# verbose mode would otherwise print in the clear.
exec "$GITLEAKS_BIN" git --redact -v --no-banner "$repo"
