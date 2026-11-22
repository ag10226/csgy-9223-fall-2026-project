# S3 signer (Group 12, Chris Petersen)

AWS Lambda function in Go. When a file is uploaded to the artifacts bucket, it:

1. streams the file and computes its SHA-256 digest
2. signs the digest with an AWS KMS key (ECC P-256), writing `<key>.sig`
3. builds a signed SLSA provenance attestation (in-toto + DSSE), writing `<key>.att.json`

Both outputs go to the signatures bucket and can be checked with cosign.

## Layout

| Path | What it is |
| --- | --- |
| `main.go` | Lambda entry point: S3 download, KMS signing, S3 upload |
| `internal/events/` | Parses S3 notifications and EventBridge S3 events |
| `internal/signing/` | Digest, signature, in-toto statement, DSSE envelope (stdlib only) |
| `terraform/` | Buckets, IAM role, Lambda, S3 trigger, optional test KMS key |
| `scripts/` | Build scripts for Windows (`build.ps1`) and Mac/Linux (`build.sh`) |

## Quick start

```powershell
go mod tidy                     # first time only: downloads AWS libraries
go test ./...                   # unit tests, no AWS needed
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
cd terraform
terraform init
terraform apply                 # creates a personal test key
# or: terraform apply -var="kms_key_arn=arn:aws:kms:us-east-1:<acct>:key/<id>"
```

## Verify a file

```powershell
aws s3 cp app.exe s3://<artifacts_bucket>/app.exe
aws s3 cp s3://<signatures_bucket>/app.exe.sig .
aws s3 cp s3://<signatures_bucket>/app.exe.att.json .

cosign verify-blob --key awskms:///<kms_key_arn> --signature app.exe.sig `
  --insecure-ignore-tlog=true --new-bundle-format=false app.exe

cosign verify-blob-attestation --key awskms:///<kms_key_arn> --signature app.exe.att.json `
  --type slsaprovenance1 --insecure-ignore-tlog=true --new-bundle-format=false app.exe
```

`--insecure-ignore-tlog` is needed because signatures are not uploaded to the public
Rekor transparency log (a deliberate choice for a private system).
