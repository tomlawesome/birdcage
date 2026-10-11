#!/usr/bin/env bash
set -euo pipefail

# Gates the licences of the Go modules linked into the Birdcage binary --
# what `go build ./...` actually ships, not build- or test-only tooling.
# Host independent on purpose: both the `licence` GitHub Actions workflow
# (.github/workflows/licence.yml) and the GitLab `lint:licences` job call
# this same script. Its tests are scripts/licence-check.test.sh.
#
# A library passes when its licence is on allow-licenses:, or when its
# exact library path, module version and licence match an entry under
# allow-go-module-licenses: (owner-accepted exceptions, #8). Anything else
# fails, and so does an entry that matched nothing (a stale exception).

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POLICY_FILE="${POLICY_FILE:-$SCRIPT_DIR/../supply-chain/licence-policy.yml}"
GO_LICENSES_VERSION="${GO_LICENSES_VERSION:-v2.0.1}"

if [ ! -f "$POLICY_FILE" ]; then
  echo "licence-check: policy file not found: $POLICY_FILE" >&2
  exit 1
fi

# list_entries <key>: the "  - X" entries under a top-level key, up to the
# next top-level key. No yq: the file's shape is simple and fixed enough
# for awk/sed. The key is matched exactly, so allow-licenses: never picks
# up allow-go-module-licenses: or the npm/python keys, nor they it.
list_entries() {
  awk -v key="$1:" '
    $0 == key || index($0, key " ") == 1 { in_list=1; next }
    /^[^[:space:]]/ { in_list=0 }
    in_list && /^[[:space:]]*-[[:space:]]*/ {
      sub(/^[[:space:]]*-[[:space:]]*/, "")
      print
    }
  ' "$POLICY_FILE" | sed 's/[[:space:]]*$//'
}

ALLOWED_LICENSES="$(list_entries allow-licenses | paste -sd, -)"

# An empty list must fail loudly rather than silently allowing every
# licence: a policy file that lost its entries (or whose key name drifted
# from what this script parses) must not pass quietly.
if [ -z "$ALLOWED_LICENSES" ]; then
  echo "licence-check: no allow-licenses entries found in $POLICY_FILE -- refusing to run with an empty allow-list" >&2
  exit 1
fi

echo "licence-check: allowed licences: $ALLOWED_LICENSES"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
list_entries allow-go-module-licenses > "$work/exceptions"

go install "github.com/google/go-licenses/v2@${GO_LICENSES_VERSION}"

# go-licenses tells standard-library packages apart by GOROOT. When the go
# command runs a toolchain it downloaded itself (GOTOOLCHAIN), the real
# root is inside the module cache, go-licenses does not know it, and it
# fails with "Package <stdlib> does not have module info". Naming the root
# the go command actually uses fixes that, and changes nothing where the
# two already agree (the CI image).
GOROOT="$(go env GOROOT)"
export GOROOT

# --ignore excludes only Birdcage's own module path from the report; it
# does not add Birdcage's own licence to the allow-list above, and
# Birdcage's own licence is not thereby "allowed" for any dependency that
# happens to share it. (There is no LICENSE file at the repository root at
# the time of writing -- check it if one is added later.)
if ! go-licenses report ./... --ignore github.com/tomlawesome/birdcage > "$work/report.csv"; then
  echo "licence-check: go-licenses report failed" >&2
  exit 1
fi

# The module and version each linked package comes from -- the same build
# list go-licenses reads. A library's version is its module's version.
# Birdcage itself (the main module, which has no version) is left out,
# as it is from the report.
if ! go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}}{{end}}{{end}}' ./... > "$work/deps"; then
  echo "licence-check: go list failed" >&2
  exit 1
fi
sort -u "$work/deps" | grep -v '^$' > "$work/modules" || true

if [ ! -s "$work/report.csv" ]; then
  echo "licence-check: go-licenses report produced no libraries -- refusing to pass an empty report" >&2
  exit 1
fi
if [ ! -s "$work/modules" ]; then
  echo "licence-check: go list produced no modules -- refusing to pass" >&2
  exit 1
fi

# The decision. Every failure is printed; the exit status is 1 if any.
awk -v allowed="$ALLOWED_LICENSES" -v q="'" '
  BEGIN {
    n = split(allowed, a, ",")
    for (i = 1; i <= n; i++) ok[a[i]] = 1
    bad = 0
  }
  phase == "exc" {
    if ($0 !~ /^[^[:space:]@]+@[^[:space:]@]+[[:space:]]+[^[:space:]]+$/) {
      print "licence-check: malformed allow-go-module-licenses entry (want \"<library>@<version> <licence>\"): " $0 > "/dev/stderr"
      bad = 1; next
    }
    split($0, f, /[[:space:]]+/)
    if (f[1] in exc) {
      print "licence-check: duplicate allow-go-module-licenses entry: " f[1] > "/dev/stderr"
      bad = 1; next
    }
    exc[f[1]] = f[2]; order[++nexc] = f[1]
    next
  }
  phase == "mod" {
    if (NF != 2) {
      print "licence-check: unreadable go list line: " $0 > "/dev/stderr"
      bad = 1; next
    }
    modver[$1] = $2
    next
  }
  phase == "report" {
    nf = split($0, c, ",")
    lib = c[1]; lic = c[nf]
    if (nf < 3 || lib == "" || lic == "") {
      print "licence-check: unreadable go-licenses report line: " $0 > "/dev/stderr"
      bad = 1; next
    }
    # The module a library belongs to is the longest module path that is
    # the library itself or a parent directory of it.
    best = ""
    for (m in modver)
      if ((lib == m || index(lib, m "/") == 1) && length(m) > length(best)) best = m
    if (best == "") {
      print "licence-check: no module in the build list for library " lib > "/dev/stderr"
      bad = 1; next
    }
    key = lib "@" modver[best]
    if (lic in ok) next
    if ((key in exc) && exc[key] == lic) {
      used[key] = 1
      print "licence-check: passed by exception: " key " " lic
      next
    }
    print "licence-check: Not allowed licence " q lic q " found for library " q lib q " (" key ")" > "/dev/stderr"
    bad = 1
  }
  END {
    for (i = 1; i <= nexc; i++) {
      k = order[i]
      if (!(k in used)) {
        print "licence-check: stale allow-go-module-licenses entry, matches no library needing it -- delete it: " k " " exc[k] > "/dev/stderr"
        bad = 1
      }
    }
    exit bad
  }
' phase=exc "$work/exceptions" phase=mod "$work/modules" phase=report "$work/report.csv"

echo "licence-check: all linked Go libraries passed"
