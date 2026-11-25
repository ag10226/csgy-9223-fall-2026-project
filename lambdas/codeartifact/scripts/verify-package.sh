#!/usr/bin/env bash
# Verifies a package version from the CodeArtifact repository the way a consumer
# would: download one asset and its Sigstore bundles, check both with cosign
# against the signing key's public key, and show that a tampered copy fails.
#
# usage: verify-package.sh <format> <namespace|-> <package> <version> <asset>
#   e.g. verify-package.sh generic group12 hello 0.1.1795388110 hello.tgz
set -euo pipefail

if [ $# -ne 5 ]; then
  echo "usage: $0 <format> <namespace|-> <package> <version> <asset>" >&2
  exit 2
fi
format=$1 namespace=$2 package=$3 version=$4 asset=$5

root="$(cd "$(dirname "$0")/.." && pwd)"
tf() { terraform -chdir="$root/terraform" "$@"; }
domain=$(tf output -raw codeartifact_domain)
repo=$(tf output -raw codeartifact_repository)
bucket=$(tf output -raw signatures_bucket)

namespace_args=()
if [ "$namespace" != "-" ]; then
  namespace_args=(--namespace "$namespace")
fi

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
cd "$workdir"

# Same key layout as versionPrefix in the Lambda: the base64 revision is
# rewritten to the URL-safe alphabet without padding.
revision=$(aws codeartifact describe-package-version --domain "$domain" --repository "$repo" \
  --format "$format" "${namespace_args[@]}" --package "$package" --package-version "$version" \
  --query packageVersion.revision --output text)
prefix="codeartifact/$domain/$repo/$format/${namespace/#-/_}/$package/$version/$(printf '%s' "$revision" | tr '/+' '_-' | sed 's/=*$//')"

echo "== Downloading $asset and its bundles"
aws codeartifact get-package-version-asset --domain "$domain" --repository "$repo" \
  --format "$format" "${namespace_args[@]}" --package "$package" --package-version "$version" \
  --asset "$asset" "$asset" >/dev/null
aws s3 cp --quiet "s3://$bucket/$prefix/assets/$asset.sigstore.json" asset.sigstore.json
aws s3 cp --quiet "s3://$bucket/$prefix/provenance.att.sigstore.json" provenance.att.sigstore.json

# Consumers verify offline with the public key, which Terraform outputs.
tf output -raw public_key_pem > cosign.pub

echo "== Signature"
cosign verify-blob --key cosign.pub --bundle asset.sigstore.json --insecure-ignore-tlog=true "$asset"

echo "== Provenance attestation"
cosign verify-blob-attestation --key cosign.pub --bundle provenance.att.sigstore.json \
  --type slsaprovenance1 --insecure-ignore-tlog=true "$asset"
jq '.dsseEnvelope.payload | @base64d | fromjson' provenance.att.sigstore.json

echo "== Tampered copy (must fail)"
cp "$asset" "tampered-$asset"
printf 'x' >> "tampered-$asset"
if cosign verify-blob --key cosign.pub --bundle asset.sigstore.json --insecure-ignore-tlog=true "tampered-$asset" 2>/dev/null; then
  echo "FAIL: tampered copy verified" >&2
  exit 1
fi
echo "OK: tampered copy rejected"
