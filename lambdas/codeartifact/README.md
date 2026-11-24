# CodeArtifact signer (Group 12, Dan Huynh)

AWS Lambda function in Go. When a package version is published to the CodeArtifact
repository, EventBridge invokes it, and it:

1. re-reads the version from the CodeArtifact API (the event is only a trigger) and skips it
   unless it is `Published` and was published into the domain, not pulled from an upstream
   registry such as npmjs.com
2. streams every file ("asset") of the version, computes its SHA-256, and fails if it doesn't
   match the hash and size CodeArtifact reports
3. signs each asset's digest with an AWS KMS key (ECC P-256), writing a Sigstore bundle per asset
4. builds one signed SLSA provenance attestation (in-toto + DSSE) with every asset as a subject

Everything goes to the signatures bucket and can be checked with cosign:

```
s3://<signatures_bucket>/codeartifact/<domain>/<repo>/<format>/<namespace>/<package>/<version>/<revision>/
    assets/<asset>.sigstore.json   signature over each asset
    provenance.sigstore.json        attestation covering all assets (written last)
```

An empty namespace is written as `_`, and the revision uses the URL-safe base64 alphabet.
Objects are never overwritten, and `provenance.sigstore.json` marks a revision as done, so
repeated or retried events are safe.

## Layout

| Path | What it is |
| --- | --- |
| `main.go` | Lambda entry point: loads config, AWS clients, and the signing key |
| `handler.go` | Event filtering, CodeArtifact download and hash check, S3 writes |
| `provenance.go` | The in-toto statement with the SLSA provenance v1 predicate |
| `internal/signing/` | KMS signing and Sigstore bundles; `signingtest/` has a fake KMS and a sigstore-go verifier |
| `testdata/` | Real events captured from AWS, used by the unit tests |
| `terraform/` | CodeArtifact domain and repo, signatures bucket, IAM role, Lambda, EventBridge rule, optional test KMS key |
| `scripts/` | Build scripts for Mac/Linux (`build.sh`) and Windows (`build.ps1`), plus test helpers |

## Quick start

```bash
go test ./...                   # unit tests, no AWS needed
scripts/build.sh                # or: powershell -ExecutionPolicy Bypass -File scripts\build.ps1
cd terraform
terraform init
terraform apply                 # creates a personal test key
# or: terraform apply -var="kms_key_arn=arn:aws:kms:us-east-1:<acct>:key/<id>"
```

If the shared event routing sends CodeArtifact events to this function, add
`-var="enable_eventbridge_rule=false"` and point the routing at the `lambda_function_arn` output.

## Try it

```bash
scripts/publish-test-package.sh            # publishes generic package group12/hello <version>
aws logs tail "$(terraform -chdir=terraform output -raw log_group_name)" --since 5m
scripts/verify-package.sh generic group12 hello <version> hello.tgz
scripts/capture-event.sh <name>            # saves the last event to testdata/<name>.json
```

`verify-package.sh` downloads the asset and its bundles and runs:

```bash
cosign verify-blob --key cosign.pub --bundle asset.sigstore.json \
  --insecure-ignore-tlog=true hello.tgz

cosign verify-blob-attestation --key cosign.pub --bundle provenance.sigstore.json \
  --type slsaprovenance1 --insecure-ignore-tlog=true hello.tgz
```

then checks that a tampered copy is rejected. `cosign.pub` comes from the `public_key_pem`
output. `--insecure-ignore-tlog` is needed because signatures are not uploaded to the public
Rekor transparency log (a deliberate choice for a private system).

## What the attestation claims

This function does not build packages. The provenance says that CodeArtifact published these
exact bytes as this package version, and that this function checked and signed them:
`builder.id` is the function's ARN, and `externalParameters` identify the domain, repository,
package, version, and revision.
