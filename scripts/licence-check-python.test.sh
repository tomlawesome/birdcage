#!/usr/bin/env bash
# Tests for licence-check-python.sh / licence-check-python.py. A guard
# that cannot fail guards nothing, so every rule it enforces has a case
# here that proves it fires.
#
# Deliberately fixture-only: unlike licence-check-npm.test.sh's "the real
# thing must pass" case (frontend/node_modules is already installed and
# already clean), running this checker against a real pip install would
# need network access on every test run. build/opencanary/requirements.txt
# really does pull in a GPL package (hpfeeds) -- it passes for real, but
# only via a named exception in allow-python-package-licenses:, not because
# its own metadata says something acceptable. Proving the gate fires, and
# that a recorded exception overrides it, is exactly what these fixtures
# do, without needing that real install on every run.
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
  # pip always writes RECORD; an empty one means "installed no assets".
  : > "$pkgs/$name_version.dist-info/RECORD"
}

# mkasset <packages_dir> <name-version> <path>
# Installs <path> under the package and lists it in its RECORD, the way
# pip does, so the bundled-asset check (#179) sees it.
mkasset() {
  local pkgs="$1" name_version="$2" path="$3"
  mkdir -p "$pkgs/$(dirname "$path")"
  printf 'x\n' > "$pkgs/$path"
  printf '%s,sha256=x,2\n' "$path" >> "$pkgs/$name_version.dist-info/RECORD"
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

# expect_grep <want-exit> <name> <packages_dir> <policy_file> <must-contain>
# Same as expect, but also requires the combined stdout+stderr to contain
# a given substring -- for asserting not just pass/fail but that the
# right thing was said (an exception named, a licence file path named).
expect_grep() {
  local want="$1" name="$2" pkgs="$3" pol="$4" needle="$5" got=0 out
  out="$(PYTHON_PACKAGES_DIR="$pkgs" POLICY_FILE="$pol" "$checker" 2>&1)" || got=$?
  if [ "$got" = "$want" ] && printf '%s' "$out" | grep -qF "$needle"; then
    echo "ok   $name"; pass=$((pass + 1))
  else
    echo "FAIL $name: exit $got, want $want, or missing '$needle'"
    echo "$out" | sed 's/^/       /'
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

# --- allow-python-package-licenses: named, version-pinned exceptions ---
# Real-shaped: hpfeeds@3.0.0 declares GPL-3.0 and is accepted anyway,
# under a recorded exception, exactly the shape #95 asked for.
exception_policy="$work/exception-policy.yml"
printf '%s\n' 'allow-python-licenses:
  - MIT
allow-python-package-licenses:
  - evil@3.1.4 GPL-3.0-only' > "$exception_policy"

pkgs="$work/exception-match/pkgs"
mkpkg "$pkgs" foo-1.0.0 'Name: foo
Version: 1.0.0
License-Expression: MIT'
mkpkg "$pkgs" evil-3.1.4 'Name: evil
Version: 3.1.4
License-Expression: GPL-3.0'
expect_grep 0 "a named exception makes an otherwise-refused package pass, and is named in the summary" \
  "$pkgs" "$exception_policy" "evil@3.1.4 — GPL-3.0-only"

pkgs="$work/exception-wrong-version/pkgs"
mkpkg "$pkgs" foo-1.0.0 'Name: foo
Version: 1.0.0
License-Expression: MIT'
mkpkg "$pkgs" evil-3.1.5 'Name: evil
Version: 3.1.5
License-Expression: GPL-3.0'
expect 1 "an exception recorded for a different version does not match; the new version is still refused" \
  "$pkgs" "$exception_policy"

pkgs="$work/stale-exception/pkgs"
mkpkg "$pkgs" foo-1.0.0 'Name: foo
Version: 1.0.0
License-Expression: MIT'
expect_grep 1 "a stale exception matching no installed package fails, distinctly" \
  "$pkgs" "$exception_policy" "stale allow-python-package-licenses exception"

# A "no licence field" offender also names any bundled licence file it
# found, from a License-File: header or a LICENSE* file in the dist-info
# directory -- so whoever writes the next exception knows where to look.
pkgs="$work/no-licence-with-file/pkgs"
mkpkg "$pkgs" mystery-0.1.0 'Name: mystery
Version: 0.1.0
License-File: LICENSE'
printf 'MIT licence text\n' > "$pkgs/mystery-0.1.0.dist-info/LICENSE"
expect_grep 1 "a package with no licence field names its bundled licence file's path" \
  "$pkgs" "$good_policy" "bundled licence file(s): LICENSE"

# --- inside packages (#179): vendored packages and bundled assets ---

pkgs="$work/vendored-bad/pkgs"
mkpkg "$pkgs" carrier-1.0.0 'Name: carrier
Version: 1.0.0
License-Expression: MIT'
mkpkg "$pkgs/carrier/_vendor" inner-2.0.0 'Name: inner
Version: 2.0.0
License-Expression: LGPL-3.0-only'
expect_grep 1 "a vendored package with a disallowed licence is caught, named with its carrier" \
  "$pkgs" "$good_policy" "inner@2.0.0 (vendored in carrier)"

pkgs="$work/vendored-good/pkgs"
mkpkg "$pkgs" carrier-1.0.0 'Name: carrier
Version: 1.0.0
License-Expression: MIT'
mkpkg "$pkgs/carrier/_vendor" inner-2.0.0 'Name: inner
Version: 2.0.0
License-Expression: BSD-3-Clause'
expect 0 "a vendored package with an allowed licence passes" "$pkgs" "$good_policy"

vendored_exception_policy="$work/vendored-exception-policy.yml"
printf '%s\n' 'allow-python-licenses:
  - MIT
allow-python-package-licenses:
  - inner@2.0.0 LGPL-3.0-only' > "$vendored_exception_policy"
expect 0 "a named exception covers a vendored package by its own name@version" \
  "$work/vendored-bad/pkgs" "$vendored_exception_policy"

pkgs="$work/asset-unreviewed/pkgs"
mkpkg "$pkgs" skinny-1.0.0 'Name: skinny
Version: 1.0.0
License-Expression: MIT'
mkasset "$pkgs" skinny-1.0.0 skinny/skin/vendor-logo.png
mkasset "$pkgs" skinny-1.0.0 skinny/skin/theme.css
mkasset "$pkgs" skinny-1.0.0 skinny/own_module.py
expect_grep 1 "an image or stylesheet with no review is caught, whatever the package declares" \
  "$pkgs" "$good_policy" "skinny@1.0.0 skinny/skin/ (2 file(s))"

asset_policy="$work/asset-policy.yml"
printf '%s\n' 'allow-python-licenses:
  - MIT
python-bundled-assets:
  - skinny@1.0.0 skinny/skin/ Vendor-Logo-Reviewed' > "$asset_policy"
expect_grep 0 "a reviewed asset directory passes, and is named in the summary" \
  "$pkgs" "$asset_policy" "skinny/skin/ (2) — Vendor-Logo-Reviewed"

pkgs="$work/asset-bumped/pkgs"
mkpkg "$pkgs" skinny-1.1.0 'Name: skinny
Version: 1.1.0
License-Expression: MIT'
mkasset "$pkgs" skinny-1.1.0 skinny/skin/vendor-logo.png
expect 1 "a review recorded for a different version does not match; the assets are read again" \
  "$pkgs" "$asset_policy"

pkgs="$work/asset-stale/pkgs"
mkpkg "$pkgs" skinny-1.0.0 'Name: skinny
Version: 1.0.0
License-Expression: MIT'
expect_grep 1 "a review matching no installed file fails as stale, distinctly" \
  "$pkgs" "$asset_policy" "stale python-bundled-assets"

pkgs="$work/no-record/pkgs"
mkpkg "$pkgs" norec-1.0.0 'Name: norec
Version: 1.0.0
License-Expression: MIT'
rm "$pkgs/norec-1.0.0.dist-info/RECORD"
expect_grep 1 "a package with no RECORD is caught, not treated as having no assets" \
  "$pkgs" "$good_policy" "(no RECORD file)"

# --- package names match after PEP 503 normalisation (#179) ---
# A policy entry's package name matches the installed METADATA Name: once
# both are normalised (lowercase; any run of "-", "_" or "." is one
# separator). The version must still match exactly.

# Twisted-shaped: METADATA says "Name: Twisted", the policy records it in
# lowercase, as pip's own normalised name for it.
pkgs="$work/norm-asset-case/pkgs"
mkpkg "$pkgs" twisted-26.4.0 'Name: Twisted
Version: 26.4.0
License-Expression: MIT'
mkasset "$pkgs" twisted-26.4.0 twisted/python/_pydoctortemplates/pydoctor.css
mkasset "$pkgs" twisted-26.4.0 twisted/python/_pydoctortemplates/index.css

# Pair (not vacuous): the same install with no review recorded is refused,
# so the asset is really found and really needs an entry.
expect_grep 1 "a mixed-case Name with bundled assets and no review entry is refused" \
  "$pkgs" "$good_policy" "bundled asset file(s) with no python-bundled-assets review"

norm_case_asset_policy="$work/norm-asset-case-policy.yml"
printf '%s\n' 'allow-python-licenses:
  - MIT
python-bundled-assets:
  - twisted@26.4.0 twisted/python/_pydoctortemplates/ MIT' > "$norm_case_asset_policy"
expect 0 "a lowercase python-bundled-assets entry matches a mixed-case Name" \
  "$pkgs" "$norm_case_asset_policy"

# Guard: a normalised-name match with a different version must still fail.
norm_case_asset_bumped_policy="$work/norm-asset-case-bumped-policy.yml"
printf '%s\n' 'allow-python-licenses:
  - MIT
python-bundled-assets:
  - twisted@26.4.1 twisted/python/_pydoctortemplates/ MIT' > "$norm_case_asset_bumped_policy"
expect 1 "a normalised-name bundled-assets entry for a different version still does not match" \
  "$pkgs" "$norm_case_asset_bumped_policy"

# zope.interface-shaped: "." in the installed Name, "-" in the policy.
pkgs="$work/norm-asset-punct/pkgs"
mkpkg "$pkgs" zope.interface-7.2 'Name: zope.interface
Version: 7.2
License-Expression: MIT'
mkasset "$pkgs" zope.interface-7.2 zope/interface/skin/logo.png
expect_grep 1 "a dotted Name with bundled assets and no review entry is refused" \
  "$pkgs" "$good_policy" "bundled asset file(s) with no python-bundled-assets review"

norm_punct_asset_policy="$work/norm-asset-punct-policy.yml"
printf '%s\n' 'allow-python-licenses:
  - MIT
python-bundled-assets:
  - zope-interface@7.2 zope/interface/skin/ MIT' > "$norm_punct_asset_policy"
expect 0 "a hyphenated python-bundled-assets entry matches a dotted Name" \
  "$pkgs" "$norm_punct_asset_policy"

# Underscore against hyphen, and a mixed run of separators in the Name.
pkgs="$work/norm-asset-underscore/pkgs"
mkpkg "$pkgs" Foo_.-Bar-1.0.0 'Name: Foo_.-Bar
Version: 1.0.0
License-Expression: MIT'
mkasset "$pkgs" Foo_.-Bar-1.0.0 foo_bar/skin/theme.css
expect_grep 1 "a Name with a mixed run of separators and no review entry is refused" \
  "$pkgs" "$good_policy" "bundled asset file(s) with no python-bundled-assets review"

norm_run_asset_policy="$work/norm-asset-run-policy.yml"
printf '%s\n' 'allow-python-licenses:
  - MIT
python-bundled-assets:
  - foo-bar@1.0.0 foo_bar/skin/ MIT' > "$norm_run_asset_policy"
expect 0 "a run of mixed separators in the Name is one separator when matching bundled-assets" \
  "$pkgs" "$norm_run_asset_policy"

# The same rule for allow-python-package-licenses:. The package is refused
# on its licence without an exception (the pair), and passes with one whose
# name differs only in case or punctuation.
pkgs="$work/norm-exc-underscore/pkgs"
mkpkg "$pkgs" Evil_Pkg-3.1.4 'Name: Evil_Pkg
Version: 3.1.4
License-Expression: GPL-3.0'
expect 1 "a mixed-case, underscored Name with a disallowed licence and no exception is refused" \
  "$pkgs" "$good_policy"

norm_exc_policy="$work/norm-exc-policy.yml"
printf '%s\n' 'allow-python-licenses:
  - MIT
allow-python-package-licenses:
  - evil-pkg@3.1.4 GPL-3.0-only' > "$norm_exc_policy"
expect 0 "a lowercase hyphenated licence exception matches an underscored mixed-case Name" \
  "$pkgs" "$norm_exc_policy"

pkgs="$work/norm-exc-dot/pkgs"
mkpkg "$pkgs" evil.pkg-3.1.4 'Name: evil.pkg
Version: 3.1.4
License-Expression: GPL-3.0'
expect 0 "a hyphenated licence exception matches a dotted Name" \
  "$pkgs" "$norm_exc_policy"

# Guard: a normalised-name match with a different version is still refused.
pkgs="$work/norm-exc-wrong-version/pkgs"
mkpkg "$pkgs" Evil_Pkg-3.1.5 'Name: Evil_Pkg
Version: 3.1.5
License-Expression: GPL-3.0'
expect 1 "a normalised-name licence exception for a different version still does not match" \
  "$pkgs" "$norm_exc_policy"

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
