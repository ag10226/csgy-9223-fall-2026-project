#!/usr/bin/env bash
# Publishes a throwaway generic package version to the sandbox CodeArtifact
# repository, which triggers a "CodeArtifact Package Version State Change" event.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
tf() { terraform -chdir="$root/terraform" "$@"; }

domain=$(tf output -raw codeartifact_domain)
repo=$(tf output -raw codeartifact_repository)
version="0.1.$(date +%s)"

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
echo "hello from group12 at $(date -u +%FT%TZ)" > "$workdir/hello.txt"
tar -czf "$workdir/hello.tgz" -C "$workdir" hello.txt
sha256=$(shasum -a 256 "$workdir/hello.tgz" | cut -d' ' -f1)

aws codeartifact publish-package-version \
  --domain "$domain" --repository "$repo" \
  --format generic --namespace group12 --package hello \
  --package-version "$version" \
  --asset-content "$workdir/hello.tgz" --asset-name hello.tgz --asset-sha256 "$sha256"
