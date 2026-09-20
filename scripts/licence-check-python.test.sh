#!/usr/bin/env bash
# Tests for licence-check-python.sh / licence-check-python.py. A guard
# that cannot fail guards nothing, so every rule it enforces has a case
# here that proves it fires.
#
# Deliberately fixture-only: unlike licence-check-npm.test.sh's "the real
# thing must pass" case (frontend/node_modules is already installed and
# already clean), running this checker against a real pip install would
# need network access on every test run, and -- as of #95 -- would not
# even pass: build/mockingbird/requirements.txt really does pull in a GPL
# package (hpfeeds) and two with no declared licence at all (setuptools,
# ordereddict). Proving the gate fires is exactly what these fixtures do,
# without needing that real, currently-failing install.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
checker="$here/licence-check-python.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

# mkpkg <packages_dir> <name-version> <metadata-body>
# name-version becomes the <name-version>.dist-info directory name.
mkpkg() {
  local pkgs="$1" name_version="$2" body="$3"
  mkdir -p "$pkgs/$name_version.dist-info"
  printf '%s\n' "$body" > "$pkgs/$name_version.dist-info/METADATA"
}

# expect <want-exit> <name> <packages_dir> <policy_file>
expect() {
  local want="$1" name="$2" pkgs="$3" pol="$4" got=0 out
  out="$(PYTHON_PACKAGES_DIR="$pkgs" POLICY_FILE="$pol" "$checker" 2>&1)" || got=$?
  if [ "$got" = "$want" ]; then
    echo "ok   $name"; pass=$((pass + 1))
  else
    echo "FAIL $name: exit $got, want $want"; echo "$out" | sed 's/^/       /'
    fail=$((fail + 1))
  fi
}

good_policy="$work/good-policy.yml"
printf '%s\n' 'allow-python-licenses:
  - MIT
  - BSD-3-Clause' > "$good_policy"

pkgs="$work/clean/pkgs"
mkpkg "$pkgs" foo-1.0.0 'Name: foo
Version: 1.0.0
License-Expression: MIT'
mkpkg "$pkgs" bar-2.0.0 'Name: bar
Version: 2.0.0
License-Expression: BSD-3-Clause'
expect 0 "a clean tree with allowed licences passes" "$pkgs" "$good_policy"

pkgs="$work/disallowed/pkgs"
mkpkg "$pkgs" foo-1.0.0 'Name: foo
Version: 1.0.0
License-Expression: MIT'
mkpkg "$pkgs" evil-3.1.4 'Name: evil
Version: 3.1.4
License-Expression: GPL-3.0'
expect 1 "a disallowed licence is caught" "$pkgs" "$good_policy"

pkgs="$work/missing/pkgs"
mkpkg "$pkgs" foo-1.0.0 'Name: foo
Version: 1.0.0
License-Expression: MIT'
mkpkg "$pkgs" mystery-0.1.0 'Name: mystery
Version: 0.1.0'
expect 1 "a package with no licence field at all is caught" "$pkgs" "$good_policy"

pkgs="$work/unknown-placeholder/pkgs"
mkpkg "$pkgs" mystery-0.1.0 'Name: mystery
Version: 0.1.0
License: UNKNOWN'
expect 1 "the distutils UNKNOWN placeholder counts as no licence field" "$pkgs" "$good_policy"

expect 2 "an absent packages dir fails red, not green" "$work/does-not-exist" "$good_policy"

empty_policy="$work/empty-policy.yml"
printf '%s\n' 'allow-python-licenses: []' > "$empty_policy"
pkgs="$work/anyclean/pkgs"
mkpkg "$pkgs" foo-1.0.0 'Name: foo
Version: 1.0.0
License-Expression: MIT'
expect 1 "an empty allow-list refuses to run" "$pkgs" "$empty_policy"

no_key_policy="$work/no-key-policy.yml"
printf '%s\n' 'something-else: []' > "$no_key_policy"
expect 1 "a policy file missing the allow-python-licenses key refuses to run" "$pkgs" "$no_key_policy"

# Real installed packages disagree on how to say the same licence:
# License-Expression (SPDX), a Classifier ("License :: OSI Approved ::
# ..."), and the old free-text License: field. Each form is exercised on
# its own, since a package can carry only one of them.
mit_classifier_policy="$work/mit-classifier-policy.yml"
printf '%s\n' 'allow-python-licenses:
  - MIT License' > "$mit_classifier_policy"

pkgs="$work/classifier-only/pkgs"
mkpkg "$pkgs" foo-1.0.0 'Name: foo
Version: 1.0.0
Classifier: License :: OSI Approved :: MIT License'
expect 0 "the Classifier form, with no other licence field, is read" "$pkgs" "$mit_classifier_policy"

pkgs="$work/classifier-only-bad/pkgs"
mkpkg "$pkgs" evil-1.0.0 'Name: evil
Version: 1.0.0
Classifier: License :: OSI Approved :: GPL License'
expect 1 "a disallowed licence in the Classifier form is caught" "$pkgs" "$mit_classifier_policy"

pkgs="$work/raw-field-only/pkgs"
mkpkg "$pkgs" foo-1.0.0 'Name: foo
Version: 1.0.0
License: BSD-3-Clause'
expect 0 "the raw License: field, with no other licence field, is read" "$pkgs" "$good_policy"

# automat-shaped: a useless raw License: field (real copyright prose, not
# a licence name) alongside a correct Classifier. The package must pass
# on the Classifier candidate rather than being judged by the useless one.
pkgs="$work/useless-raw-field/pkgs"
mkpkg "$pkgs" foo-1.0.0 'Name: foo
Version: 1.0.0
License: Copyright (c) 2014
Classifier: License :: OSI Approved :: MIT License'
expect 0 "a useless raw License: field does not block a good Classifier" "$pkgs" "$mit_classifier_policy"

# cryptography-shaped: a compound SPDX "X OR Y" License-Expression is
# split into alternatives, and matching either one is enough.
pkgs="$work/or-expression/pkgs"
mkpkg "$pkgs" foo-1.0.0 'Name: foo
Version: 1.0.0
License-Expression: Apache-2.0 OR BSD-3-Clause'
expect 0 "one alternative of an OR licence-expression matching is enough" "$pkgs" "$good_policy"

# An AND compound must never be silently split into alternatives: that
# would treat an unreviewed combination as pre-approved just because one
# half happens to be allowed on its own.
pkgs="$work/and-expression/pkgs"
mkpkg "$pkgs" foo-1.0.0 'Name: foo
Version: 1.0.0
License-Expression: MIT AND BSD-3-Clause'
expect 1 "an AND licence-expression is kept whole, not split into a pass" "$pkgs" "$good_policy"

pkgs="$work/and-expression-listed/pkgs"
mkpkg "$pkgs" foo-1.0.0 'Name: foo
Version: 1.0.0
License-Expression: MIT AND BSD-3-Clause'
and_policy="$work/and-policy.yml"
printf '%s\n' 'allow-python-licenses:
  - MIT AND BSD-3-Clause' > "$and_policy"
expect 0 "an AND licence-expression passes when listed as its exact whole" "$pkgs" "$and_policy"

# A METADATA file that cannot be decoded as text is unreadable, not
# absent -- and an unreadable licence is a refusal, never a pass.
pkgs="$work/unreadable/pkgs"
mkdir -p "$pkgs/broken-1.0.0.dist-info"
printf '\xff\xfe\x00\xff\xfe' > "$pkgs/broken-1.0.0.dist-info/METADATA"
expect 1 "an undecodable METADATA file is caught, not skipped" "$pkgs" "$good_policy"

# A dist-info directory with no METADATA file inside it at all (a
# malformed or partial install) is caught the same way.
pkgs="$work/no-metadata-file/pkgs"
mkdir -p "$pkgs/ghost-1.0.0.dist-info"
expect 1 "a dist-info directory with no METADATA file is caught" "$pkgs" "$good_policy"

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
