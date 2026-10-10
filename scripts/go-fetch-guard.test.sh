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

fixture "$birdcage_good" "${holder_good/ENV GOPRIVATE=github.com\/tomlawesome\/\*/ENV GOFLAGS=-mod=readonly GOPRIVATE=\"example.com/x,github.com/tomlawesome\"}"
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

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
