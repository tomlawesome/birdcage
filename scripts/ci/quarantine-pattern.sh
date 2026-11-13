#!/bin/sh
# Prints the `go test -skip` / `-run` pattern for scripts/quarantine.txt: every
# name in it, regex-escaped and anchored, joined with `|`. Prints nothing when
# the file lists no test (then the caller must not pass -skip or -run at all).
# The file is the one list of quarantined tests: the gate skips them, the
# non-blocking quarantine job runs them, flake-check.sh is given it as
# --quarantined. See ai/agent-infra scripts/flake-check/README.md.
set -eu
file=${1:-scripts/quarantine.txt}
names=$(grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$file" \
  | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/[][\\.*+?(){}|^$]/\\&/g' \
  | paste -sd'|' -) || true
[ -z "$names" ] || printf '^(%s)$\n' "$names"
