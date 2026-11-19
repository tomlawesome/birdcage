#!/usr/bin/env bash
# Planted defect for the shellcheck self-test (#199). Expected: SC2086 and SC2164.
dir="$1"
cd "$dir"
rm -rf $dir/*
