# S3 signer

AWS Lambda function in Go. When a file is uploaded to the artifacts bucket, it uses
cosign's own Go code (the same code the `cosign` CLI runs) to:

1. sign the file with the team's AWS KMS key, writing `<key>.sigstore.json`
2. sign a SLSA provenance attestation describing the upload, writing `<key>.att.sigstore.json`

Both are standard Sigstore bundles, cosign 3's default format, written to the signatures bucket.

## Layout

| Path | What it is |
| --- | --- |
| `main.go` | Lambda entry point: download from S3, cosign sign-blob and attest-blob, upload bundles |
| `internal/events/` | Parses S3 notifications and EventBridge S3 events |
| `internal/provenance/` | Builds the in-toto statement (bucket, key, SHA-256, uploader, IP, signer) |
| `terraform/` | Buckets, IAM role, Lambda, S3 trigger, optional test KMS key |
| `scripts/` | Build scripts for Windows (`build.ps1`) and Mac/Linux (`build.sh`) |

## Quick start

```powershell
go mod tidy                     # downloads cosign and AWS libraries (a few minutes the first time)
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
aws s3 cp s3://<signatures_bucket>/app.exe.sigstore.json .
aws s3 cp s3://<signatures_bucket>/app.exe.att.sigstore.json .

cosign verify-blob --key awskms:///<kms_key_arn> --bundle app.exe.sigstore.json `
  --insecure-ignore-tlog=true app.exe

cosign verify-blob-attestation --key awskms:///<kms_key_arn> --bundle app.exe.att.sigstore.json `
  --type slsaprovenance1 --insecure-ignore-tlog=true app.exe
```

`--insecure-ignore-tlog` is needed because signatures are not uploaded to the public
Rekor transparency log (a deliberate choice for a private system).
