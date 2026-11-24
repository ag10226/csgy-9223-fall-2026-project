#!/usr/bin/env bash
# Builds the Lambda for AWS (Linux, ARM64) on Mac or Linux.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags lambda.norpc -trimpath -ldflags "-s -w" -o build/bootstrap .
echo "OK: built build/bootstrap (Terraform zips it during apply)"
