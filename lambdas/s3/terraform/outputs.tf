output "artifacts_bucket" {
  description = "Upload files here to have them signed."
  value       = aws_s3_bucket.artifacts.bucket
}

output "signatures_bucket" {
  description = "Signatures (.sig) and attestations (.att.json) appear here."
  value       = aws_s3_bucket.signatures.bucket
}

output "lambda_function_name" {
  value = aws_lambda_function.signer.function_name
}

output "kms_key_arn" {
  description = "The key the Lambda signs with."
  value       = local.kms_key_arn
}

output "cosign_key_ref" {
  description = "Pass this to cosign --key to verify using KMS directly."
  value       = "awskms:///${local.kms_key_arn}"
}

output "public_key_pem" {
  description = "Public key for offline verification. Safe to share."
  value       = data.aws_kms_public_key.signing.public_key_pem
}
