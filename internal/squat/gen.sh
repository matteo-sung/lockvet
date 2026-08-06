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
#   gems   — ecosyste.ms packages API (data CC BY-SA 4.0), rubygems.org
#            sorted by downloads, top 5000
#   php    — packagist.org explore/popular.json (official API), top 4000
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

: > "$tmp/gems.txt"
for p in $(seq 1 5); do
  curl -s -A "lockvet-gen-popular (https://github.com/matteo-sung/lockvet)" \
    "https://packages.ecosyste.ms/api/v1/registries/rubygems.org/packages?sort=downloads&order=desc&per_page=1000&page=$p" |
    jq -r '.[].name' >> "$tmp/gems.txt"
  sleep 1.2
done

: > "$tmp/php.txt"
for p in $(seq 1 40); do
  curl -s -A "lockvet-gen-popular (https://github.com/matteo-sung/lockvet)" \
    "https://packagist.org/explore/popular.json?per_page=100&page=$p" |
    jq -r '.packages[].name' >> "$tmp/php.txt"
  sleep 1.2
done

for f in npm pypi crates gems php; do
  sort -u "$tmp/$f.txt" | awk 'length($0)>=4' | gzip -9n > "data/$f.txt.gz"
done
for f in npm pypi crates gems php; do
  printf '%s: %s names\n' "$f" "$(zcat "data/$f.txt.gz" | wc -l)"
done
