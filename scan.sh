#!/usr/bin/env bash
# Scans the same images with Trivy and Grype and stores raw JSON, timings and tool versions.
# Usage: bash scan.sh
set -u
mkdir -p results/trivy results/grype logs

IMAGES=(
  nginx:1.19
  python:3.8
  node:14
  alpine:3.12
  ubuntu:20.04
  nginx:1.27
  bkimminich/juice-shop
)

# Update both vulnerability databases once, so scan time does not include the download
trivy image --download-db-only >> logs/db_update.txt 2>&1
grype db update >> logs/db_update.txt 2>&1

# Record versions and database dates
{
  date -u
  echo "--- trivy"; trivy --version
  echo "--- grype"; grype version
  echo "--- grype db"; grype db status
} > logs/versions.txt 2>&1

echo "image,tool,milliseconds" > results/timings.csv
: > logs/errors.txt

for img in "${IMAGES[@]}"; do
  safe=$(echo "$img" | tr '/:' '__')
  if ! docker pull -q "$img" > /dev/null 2>&1; then
    echo "PULL FAILED: $img" | tee -a logs/errors.txt
    continue
  fi

  s=$(date +%s%N)
  trivy image --quiet --scanners vuln --list-all-pkgs --skip-db-update -f json -o "results/trivy/$safe.json" "$img" 2>> logs/errors.txt
  e=$(date +%s%N)
  echo "$img,trivy,$(( (e - s) / 1000000 ))" >> results/timings.csv

  s=$(date +%s%N)
  GRYPE_DB_AUTO_UPDATE=false grype "$img" -o json > "results/grype/$safe.json" 2>> logs/errors.txt
  e=$(date +%s%N)
  echo "$img,grype,$(( (e - s) / 1000000 ))" >> results/timings.csv

  echo "done: $img"
done

echo "Finished. Next: python3 analyze.py"
