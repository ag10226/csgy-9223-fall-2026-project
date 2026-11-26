output "codeartifact_domain" {
  value = aws_codeartifact_domain.packages.domain
}

output "codeartifact_repository" {
  description = "Publish packages here to have them signed."
  value       = aws_codeartifact_repository.packages.repository
}

output "signatures_bucket" {
  description = "Signatures and attestations appear here, under the codeartifact/ prefix."
  value       = aws_s3_bucket.signatures.bucket
}

output "lambda_function_name" {
  value = aws_lambda_function.signer.function_name
}

output "lambda_function_arn" {
  description = "Target for shared event routing when enable_eventbridge_rule is false."
  value       = aws_lambda_function.signer.arn
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.signer.name
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
