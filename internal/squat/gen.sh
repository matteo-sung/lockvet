#!/usr/bin/env bash
# Regenerates the embedded popular-package name lists.
# Run from the repo root: ./internal/squat/gen.sh
#
# Sources (see package doc for attribution):
#   npm    — npm-high-impact by Titus Wormer (MIT), full list
#   PyPI   — Top PyPI Packages by Hugo van Kemenade (DOI
#            10.5281/zenodo.2586599), top 8000
#   crates — crates.io API sorted by all-time downloads, top 2500
#            (1 req/s, identifying User-Agent, per their crawler policy)
set -euo pipefail
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -sL https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top.js |
  grep -o "'[^']*'" | tr -d "'" > "$tmp/npm.txt"

curl -sL https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json |
  jq -r '.rows[0:8000][].project' > "$tmp/pypi.txt"

: > "$tmp/crates.txt"
for p in $(seq 1 25); do
  curl -s -A "lockvet-gen-popular (https://github.com/matteo-sung/lockvet)" \
    "https://crates.io/api/v1/crates?sort=downloads&per_page=100&page=$p" |
    jq -r '.crates[].id' >> "$tmp/crates.txt"
  sleep 1.2
done

for f in npm pypi crates; do
  sort -u "$tmp/$f.txt" | awk 'length($0)>=4' | gzip -9n > "data/$f.txt.gz"
done
for f in npm pypi crates; do
  printf '%s: %s names\n' "$f" "$(zcat "data/$f.txt.gz" | wc -l)"
done
