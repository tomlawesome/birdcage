#!/usr/bin/env bash
# Tests for go-fetch-guard.py. A guard that cannot fail guards nothing,
# so every rule it enforces has a case here that proves it fires.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
guard="$here/go-fetch-guard.py"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

# A build directory that satisfies every rule: birdcage installs git in
# its Go build stage only, the other image fetches nothing it does not
# use, and both set GOPRIVATE before any go command.
birdcage_good='FROM golang:1-alpine AS backend
WORKDIR /src
ENV GOPRIVATE=github.com/tomlawesome/*
RUN apk add --no-cache git=2.54.0-r0
COPY go.mod go.sum ./
RUN go mod download
RUN go build -o /out/birdcage ./cmd/birdcage

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=backend /out/birdcage /birdcage'

holder_good='FROM golang:1-alpine AS build
WORKDIR /src
ENV GOPRIVATE=github.com/tomlawesome/*
COPY . .
RUN CGO_ENABLED=0 go build -o /out/holder ./cmd/holder

FROM scratch
COPY --from=build /out/holder /holder'

# fixture <birdcage-Dockerfile> <holder-Dockerfile>: a fresh build dir.
fixture() {
  rm -rf "$work/build"
  mkdir -p "$work/build/birdcage" "$work/build/holder"
  printf '%s\n' "$1" > "$work/build/birdcage/Dockerfile"
  printf '%s\n' "$2" > "$work/build/holder/Dockerfile"
}

# expect <want-exit> <name> <needle> -- runs the guard on $work/build.
# `needle`, when not empty, must appear in the output, so each fixture
# proves the message names what it caught, not just that something failed.
expect() {
  local want="$1" name="$2" needle="$3" got=0 out ok=1
  out="$(python3 "$guard" "$work/build" 2>&1)" || got=$?
  [ "$got" = "$want" ] || ok=0
  if [ -n "$needle" ] && ! grep -qF -- "$needle" <<<"$out"; then ok=0; fi
  if [ "$ok" = 1 ]; then
    echo "ok   $name"; pass=$((pass + 1))
  else
    echo "FAIL $name: exit $got (want $want)$([ -n "$needle" ] && echo ", needle '$needle' missing")"
    echo "$out" | sed 's/^/       /'
    fail=$((fail + 1))
  fi
}

fixture "$birdcage_good" "$holder_good"
expect 0 "a compliant build directory passes" "2 Go build stage(s)"

# GOPRIVATE itself.
fixture "$birdcage_good" "${holder_good/ENV GOPRIVATE=github.com\/tomlawesome\/\*
/}"
expect 1 "a Go stage without GOPRIVATE is caught" "holder/Dockerfile stage 1 (build)"

fixture "$birdcage_good" 'FROM golang:1-alpine AS build
COPY . .
RUN go mod download
ENV GOPRIVATE=github.com/tomlawesome/*
RUN go build ./cmd/holder'
expect 1 "GOPRIVATE set only after the first go command is caught" "go mod download"

fixture "$birdcage_good" "${holder_good/tomlawesome\/\*/someoneelse/*}"
expect 1 "GOPRIVATE naming someone else's modules is caught" "'github.com/someoneelse/*'"

fixture "$birdcage_good" "${holder_good/tomlawesome\/\*/tomlawesome/gauntlet}"
expect 1 "GOPRIVATE covering gauntlet alone, not the owner's other modules, is caught" "holder"

fixture "$birdcage_good" "${holder_good/ENV GOPRIVATE=github.com\/tomlawesome\/\*/ENV GOPRIVATE=github.com/tomlawesome/*
ENV GOPRIVATE=}"
expect 1 "a later ENV that empties GOPRIVATE is caught" "GOPRIVATE ''"

fixture "$birdcage_good" "${holder_good/ENV GOPRIVATE=github.com\/tomlawesome\/\*/ENV CGO_ENABLED=0 GOPRIVATE=\"example.com/x,github.com/tomlawesome\"}"
expect 0 "a wider pattern in a list, in a multi-key ENV, passes" ""

fixture "$birdcage_good" "${holder_good/ENV GOPRIVATE=github.com\/tomlawesome\/\*/ENV GOPRIVATE github.com/*}"
expect 0 "the legacy ENV form with a wider glob passes" ""

fixture "$birdcage_good" 'FROM golang:1-alpine AS base
ENV GOPRIVATE=github.com/tomlawesome/*
FROM base AS build
RUN go build ./cmd/holder'
expect 0 "a stage built FROM an earlier stage inherits its GOPRIVATE" ""

fixture "$birdcage_good" 'FROM golang:1-alpine AS base
FROM base AS build
RUN go build ./cmd/holder'
expect 1 "inheriting from a stage without GOPRIVATE is still caught" "stage 2 (build)"

fixture "$birdcage_good" "${holder_good/COPY . ./ENV GONOPROXY=example.com
COPY . .}"
expect 1 "GONOPROXY, which overrides GOPRIVATE for the proxy, is caught" "sets GONOPROXY"

fixture "$birdcage_good" "${holder_good/RUN CGO_ENABLED=0/RUN GONOSUMDB=example.com CGO_ENABLED=0}"
expect 1 "GONOSUMDB inline in a RUN is caught" "sets GONOSUMDB"

# git.
fixture "$birdcage_good" "${holder_good/COPY . ./RUN apk add --no-cache git
COPY . .}"
expect 1 "git installed in any image but birdcage is caught" "holder/Dockerfile stage 1 (build): installs git"

fixture "$birdcage_good" "${holder_good/COPY . ./RUN apk add --no-cache curl \\
    git=2.54.0-r0
COPY . .}"
expect 1 "git hidden on a continuation line is caught" "installs git"

fixture "$birdcage_good" "${holder_good/FROM scratch/FROM debian:13
RUN apt-get update \&\& apt-get install -y git}"
expect 1 "git from apt-get, in a final stage with no go command, is caught" "stage 2: installs git"

fixture "$birdcage_good
RUN apk add --no-cache git=2.54.0-r0" "$holder_good"
expect 1 "git in birdcage's final, shipped stage is caught" "final, shipped stage"

fixture "$birdcage_good" "${holder_good/COPY . ./RUN apk add --no-cache gitleaks=8.0.0-r0
COPY . .}"
expect 0 "a package merely starting with git is not git" ""

# Reading the directory at all.
expect_red() {
  local name="$1" dir="$2" got=0 out
  out="$(python3 "$guard" "$dir" 2>&1)" || got=$?
  if [ "$got" = 2 ]; then
    echo "ok   $name"; pass=$((pass + 1))
  else
    echo "FAIL $name: exit $got, want 2"; echo "$out" | sed 's/^/       /'
    fail=$((fail + 1))
  fi
}
expect_red "a missing build directory fails red, not green" "$work/does-not-exist"
mkdir -p "$work/empty/nothing-here"
expect_red "a build directory with no Dockerfiles fails red, not green" "$work/empty"

# ---- Repository-wide scan (spec items 1-7) ----------------------------
# These cases build a git repository, `git add` the files so they are
# tracked, and run the guard from its root the way CI does.
repo_root="$(cd "$here/.." && pwd)"
repo="$work/repo"
genv='ENV GOPRIVATE=github.com/tomlawesome/*'

repo_new() {
  rm -rf "$repo"; mkdir -p "$repo"
  git -C "$repo" init -q 2>/dev/null
  put build/birdcage/Dockerfile "${1:-$birdcage_good}"
  put build/holder/Dockerfile "$holder_good"
}
put() { mkdir -p "$repo/$(dirname "$1")"; printf '%s\n' "$2" > "$repo/$1"; }
# expect_repo <want-exit> <name> <needle>
expect_repo() {
  local want="$1" name="$2" needle="$3" got=0 out ok=1
  git -C "$repo" add -A
  out="$(cd "$repo" && python3 "$guard" 2>&1)" || got=$?
  if [ "$want" = 0 ]; then [ "$got" = 0 ] || ok=0; else [ "$got" != 0 ] || ok=0; fi
  if [ -n "$needle" ] && ! grep -qF -- "$needle" <<<"$out"; then ok=0; fi
  if [ "$ok" = 1 ]; then
    echo "ok   $name"; pass=$((pass + 1))
  else
    echo "FAIL $name: exit $got (want $want)$([ -n "$needle" ] && echo ", needle '$needle' missing")"
    echo "$out" | sed 's/^/       /'
    fail=$((fail + 1))
  fi
}
# pair <name> <path> <bad-body> <good-body> <needle>: the bad Dockerfile
# at <path> must be refused naming the path; the good one must pass.
pair() {
  repo_new; put "$2" "$3"
  expect_repo 1 "$1: refused" "$5"
  repo_new; put "$2" "$4"
  expect_repo 0 "$1: compliant neighbour passes" ""
}
nogo() { printf 'FROM golang:1-alpine\n%s\nCOPY . .\nRUN %s\n' "$2" "$1"; }   # nogo <run> <env-line>
mkgo() { printf 'FROM golang:1-alpine AS b\n%s\nRUN %s\n' "$2" "$1"; }          # mkgo <run> <env-line>

# Item 7: the repository's own Dockerfiles keep passing.
got=0; out="$(cd "$repo_root" && python3 "$guard" 2>&1)" || got=$?
if [ "$got" = 0 ]; then echo "ok   the repository's current Dockerfiles pass (item 7)"; pass=$((pass + 1))
else echo "FAIL the repository's current Dockerfiles pass (item 7): exit $got"; echo "$out" | sed 's/^/       /'; fail=$((fail + 1)); fi

repo_new
expect_repo 0 "item 1 baseline: the compliant fixture repo passes" ""

# Item 1: every tracked Dockerfile, any name, any depth.
pair "item 1: Dockerfile outside build/ (deploy/api) is scanned" deploy/api/Dockerfile \
  "$(mkgo 'go build ./...' '')" "$(mkgo 'go build ./...' "$genv")" "deploy/api/Dockerfile"
pair "item 1: Dockerfile at the repository root is scanned" Dockerfile \
  "$(mkgo 'go build ./...' '')" "$(mkgo 'go build ./...' "$genv")" "Dockerfile"
pair "item 1: Dockerfile.dev is scanned" tools/Dockerfile.dev \
  "$(mkgo 'go build ./...' '')" "$(mkgo 'go build ./...' "$genv")" "tools/Dockerfile.dev"
pair "item 1: api.Dockerfile is scanned" tools/api.Dockerfile \
  "$(mkgo 'go build ./...' '')" "$(mkgo 'go build ./...' "$genv")" "tools/api.Dockerfile"
pair "item 1: a deeply nested Dockerfile is scanned" a/b/c/d/Dockerfile \
  "$(mkgo 'go build ./...' '')" "$(mkgo 'go build ./...' "$genv")" "a/b/c/d/Dockerfile"
pair "item 1: a second Dockerfile under build/birdcage (Dockerfile.ci) is scanned" build/birdcage/Dockerfile.ci \
  "$(mkgo 'go test ./...' '')" "$(mkgo 'go test ./...' "$genv")" "Dockerfile.ci"
pair "item 1: git in an out-of-build Dockerfile is scanned" deploy/tools/Dockerfile \
  "$(printf 'FROM alpine\nRUN apk add --no-cache git\n')" "$(printf 'FROM alpine\nRUN apk add --no-cache curl\n')" "deploy/tools/Dockerfile"

# Item 2: what counts as running Go.
pair "item 2: absolute path /usr/local/go/bin/go in shell form counts as go" ex/a/Dockerfile \
  "$(mkgo '/usr/local/go/bin/go build ./...' '')" "$(mkgo '/usr/local/go/bin/go build ./...' "$genv")" "ex/a/Dockerfile"
pair "item 2: exec form [\"go\",\"build\"] counts as go" ex/b/Dockerfile \
  "$(mkgo '["go","build","./..."]' '')" "$(mkgo '["go","build","./..."]' "$genv")" "ex/b/Dockerfile"
pair "item 2: exec form with /usr/local/go/bin/go counts as go" ex/c/Dockerfile \
  "$(mkgo '["/usr/local/go/bin/go","build"]' '')" "$(mkgo '["/usr/local/go/bin/go","build"]' "$genv")" "ex/c/Dockerfile"
pair "item 2: go inside a RUN heredoc body counts as go" ex/d/Dockerfile \
  "$(printf 'FROM golang:1-alpine\nRUN <<EOF\nset -e\ngo build ./...\nEOF\n')" \
  "$(printf 'FROM golang:1-alpine\n%s\nRUN <<EOF\nset -e\ngo build ./...\nEOF\n' "$genv")" "ex/d/Dockerfile"
pair "item 2: go -C dir build counts as go" ex/e/Dockerfile \
  "$(mkgo 'go -C cmd/x build' '')" "$(mkgo 'go -C cmd/x build' "$genv")" "ex/e/Dockerfile"
pair "item 2: go after && in a compound RUN counts as go" ex/f/Dockerfile \
  "$(mkgo 'make deps && go build ./...' '')" "$(mkgo 'make deps && go build ./...' "$genv")" "ex/f/Dockerfile"
repo_new; put ex/g/Dockerfile "$(printf 'FROM rust:1\nRUN cargo build --release\nRUN echo gopher\n')"
expect_repo 0 "item 2: a stage that never invokes go needs no GOPRIVATE" ""

# Item 3: GOPRIVATE placement and inheritance.
repo_new; put ex/h/Dockerfile "$(printf 'FROM golang:1-alpine AS base\n%s\nFROM base AS mid\nFROM mid AS build\nRUN go build ./...\n' "$genv")"
expect_repo 0 "item 3: GOPRIVATE inherited through two FROM hops passes" ""
repo_new; put ex/i/Dockerfile "$(printf 'FROM golang:1-alpine AS other\n%s\nFROM golang:1-alpine AS build\nRUN go build ./...\n' "$genv")"
expect_repo 1 "item 3: GOPRIVATE in an unrelated sibling stage does not count" "ex/i/Dockerfile"
repo_new; put ex/j/Dockerfile "$(printf 'FROM golang:1-alpine\nRUN <<EOF\ngo build ./...\nEOF\n%s\n' "$genv")"
expect_repo 1 "item 3: GOPRIVATE set after a heredoc go RUN is too late" "ex/j/Dockerfile"
repo_new; put ex/k/Dockerfile "$(printf 'FROM golang:1-alpine\n%s\nRUN ["/usr/local/go/bin/go","build"]\n' "ENV GOPRIVATE=github.com/someoneelse/*")"
expect_repo 1 "item 3: a wrong GOPRIVATE before an exec-form go RUN is caught" "ex/k/Dockerfile"

# Item 4: any other way of setting the Go fetch variables is refused.
for kv in 'GOPROXY=https://proxy.example.com' 'GOSUMDB=off' 'GOFLAGS=-mod=mod' 'GONOPROXY=example.com' 'GONOSUMDB=example.com'; do
  k="${kv%%=*}"
  pair "item 4: ENV $k is refused" v/env-$k/Dockerfile \
    "$(mkgo 'go build ./...' "$genv
ENV $kv")" "$(mkgo 'go build ./...' "$genv")" "v/env-$k/Dockerfile"
  repo_new; put v/exp-$k/Dockerfile "$(mkgo 'go build ./...' "$genv
RUN export $kv")"
  expect_repo 1 "item 4: RUN export $k is refused" "v/exp-$k/Dockerfile"
  repo_new; put v/inl-$k/Dockerfile "$(mkgo "$kv go build ./..." "$genv")"
  expect_repo 1 "item 4: inline $k= before go in a RUN is refused" "v/inl-$k/Dockerfile"
done
pair "item 4: RUN GOPRIVATE= go build (emptied inline) is refused" v/empty/Dockerfile \
  "$(mkgo 'GOPRIVATE= go build ./...' "$genv")" "$(mkgo 'go build ./...' "$genv")" "v/empty/Dockerfile"
pair "item 4: RUN export GOPRIVATE=... is refused even with a value that looks right" v/exportpriv/Dockerfile \
  "$(mkgo 'go build ./...' 'RUN export GOPRIVATE=github.com/tomlawesome/*')" "$(mkgo 'go build ./...' "$genv")" "v/exportpriv/Dockerfile"
pair "item 4: RUN GOPRIVATE=<right value> go build is refused: only ENV is allowed" v/runpriv/Dockerfile \
  "$(mkgo 'GOPRIVATE=github.com/tomlawesome/* go build ./...' "$genv")" "$(mkgo 'go build ./...' "$genv")" "v/runpriv/Dockerfile"
pair "item 4: ENV GOPROXY in a stage that never runs go is still refused" v/nogo/Dockerfile \
  "$(printf 'FROM alpine\nENV GOPROXY=direct\nRUN echo hi\n')" "$(printf 'FROM alpine\nRUN echo hi\n')" "v/nogo/Dockerfile"

# Item 5: git installs, whatever the flags.
gitpair() { # gitpair <label> <install-RUN> <clean-RUN> <path>
  pair "item 5: $1 is caught" "$4" "$(nogo "$2" "$genv")" "$(nogo "$3" "$genv")" "$4"
}
gitpair "apk with flags before add" 'apk --no-cache --update add git' 'apk --no-cache --update add curl' g/apk1/Dockerfile
gitpair "apk add with flags between add and git" 'apk add -U --no-cache --virtual .x git' 'apk add -U --no-cache curl' g/apk2/Dockerfile
gitpair "apt-get install with flags" 'apt-get -y --no-install-recommends install ca-certificates git' 'apt-get -y --no-install-recommends install ca-certificates' g/apt1/Dockerfile
gitpair "apt install" 'apt install -y git' 'apt install -y curl' g/apt2/Dockerfile
gitpair "apt-get install with a pinned git=<version>" 'apt-get install -y git=1:2.39.5-0' 'apt-get install -y curl' g/apt3/Dockerfile
gitpair "dnf install" 'dnf install -y git' 'dnf install -y curl' g/dnf/Dockerfile
gitpair "yum install" 'yum -y install git' 'yum -y install curl' g/yum/Dockerfile
gitpair "microdnf install" 'microdnf --setopt=install_weak_deps=0 install -y git' 'microdnf install -y curl' g/mdnf/Dockerfile
gitpair "apk add git=<version>" 'apk add --no-cache git=2.54.0-r0' 'apk add --no-cache curl' g/apk3/Dockerfile
repo_new; put g/lfs/Dockerfile "$(nogo 'apt-get install -y git-lfs' "$genv")"
expect_repo 0 "item 5: git-lfs is not git" ""
repo_new; put g/lfs2/Dockerfile "$(nogo 'apk add --no-cache --update gitleaks=8.0.0-r0 git-lfs' "$genv")"
expect_repo 0 "item 5: gitleaks and git-lfs together, with flags, are not git" ""

# Item 6: git is allowed only in birdcage's non-final, non-parent stage.
repo_new "$birdcage_good"
expect_repo 0 "item 6: git in birdcage's builder stage, copied from, passes (COPY --from is fine)" ""
bc_direct="$(printf 'FROM golang:1-alpine AS backend\n%s\nRUN apk add --no-cache git=2.54.0-r0\nRUN go build -o /out/birdcage ./cmd/birdcage\n\nFROM backend AS test\nRUN true\n\nFROM gcr.io/distroless/static-debian13:nonroot\nCOPY --from=backend /out/birdcage /birdcage\n' "$genv")"
repo_new "$bc_direct"
expect_repo 1 "item 6: a stage built FROM the git stage (directly) is refused" "build/birdcage/Dockerfile"
bc_chain="$(printf 'FROM golang:1-alpine AS backend\n%s\nRUN apk add --no-cache git=2.54.0-r0\nRUN go build -o /out/birdcage ./cmd/birdcage\n\nFROM backend AS mid\nRUN true\n\nFROM mid AS tail\nRUN true\n\nFROM gcr.io/distroless/static-debian13:nonroot\nCOPY --from=tail /out/birdcage /birdcage\n' "$genv")"
repo_new "$bc_chain"
expect_repo 1 "item 6: a stage built FROM the git stage through another stage is refused" "build/birdcage/Dockerfile"
bc_ok="$(printf 'FROM golang:1-alpine AS backend\n%s\nRUN apk add --no-cache git=2.54.0-r0\nRUN go build -o /out/birdcage ./cmd/birdcage\n\nFROM golang:1-alpine AS tools\n%s\nRUN go build -o /out/tool ./cmd/tool\n\nFROM gcr.io/distroless/static-debian13:nonroot\nCOPY --from=backend /out/birdcage /birdcage\nCOPY --from=tools /out/tool /tool\n' "$genv" "$genv")"
repo_new "$bc_ok"
expect_repo 0 "item 6: an unrelated extra stage next to the git stage passes" ""
repo_new; put build/birdcage/Dockerfile.dev "$birdcage_good"
expect_repo 1 "item 6: git in birdcage's Dockerfile.dev is not the allowed file" "Dockerfile.dev"
repo_new; put deploy/birdcage/Dockerfile "$birdcage_good"
expect_repo 1 "item 6: git in a birdcage Dockerfile outside build/birdcage is refused" "deploy/birdcage/Dockerfile"
repo_new; put build/holder/Dockerfile "$(printf '%s\nRUN apk add --no-cache git\nRUN go build ./cmd/holder\n\nFROM scratch\nCOPY --from=build /out/holder /holder\n' "$(printf 'FROM golang:1-alpine AS build\n%s' "$genv")")"
expect_repo 1 "item 6: git in a non-final stage of any other Dockerfile is still refused" "build/holder/Dockerfile"

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
