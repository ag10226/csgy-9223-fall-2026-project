data "aws_caller_identity" "current" {}

locals {
  account_id      = data.aws_caller_identity.current.account_id
  function_name   = "${var.project}-codeartifact-signer"
  create_test_key = var.kms_key_arn == ""
  kms_key_arn     = local.create_test_key ? one(aws_kms_key.test[*].arn) : var.kms_key_arn

  # Key prefix for this function's objects in the signatures bucket; passed to
  # the code so the two can't drift apart.
  signature_prefix = "codeartifact"
}

# ---------------------------------------------------------------------------
# Signing key: a personal test key, only created when kms_key_arn is empty.
# Same type as the team key: asymmetric, ECC P-256, sign/verify only.
# ---------------------------------------------------------------------------
resource "aws_kms_key" "test" {
  count                    = local.create_test_key ? 1 : 0
  description              = "${var.project} personal TEST signing key for the CodeArtifact signer"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days  = 7
}

resource "aws_kms_alias" "test" {
  count         = local.create_test_key ? 1 : 0
  name          = "alias/${var.project}-codeartifact-signer-test"
  target_key_id = aws_kms_key.test[0].key_id
}

# ---------------------------------------------------------------------------
# CodeArtifact: package versions published to this repository get signed.
# ---------------------------------------------------------------------------
resource "aws_codeartifact_domain" "packages" {
  domain = var.project
}

resource "aws_codeartifact_repository" "packages" {
  repository = "packages"
  domain     = aws_codeartifact_domain.packages.domain
}

# ---------------------------------------------------------------------------
# Signatures bucket. Bucket names must be unique worldwide, so the account ID
# is added; "codeartifact" keeps it apart from the S3 signer's bucket.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "signatures" {
  bucket        = "${var.project}-codeartifact-signatures-${local.account_id}"
  force_destroy = true # lets `terraform destroy` delete it even if it has files (fine for a class project)
}

resource "aws_s3_bucket_versioning" "signatures" {
  bucket = aws_s3_bucket.signatures.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "signatures" {
  bucket                  = aws_s3_bucket.signatures.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# IAM role the Lambda runs as. Least privilege: each statement grants only
# what the handler calls, scoped to this repository, this function's prefix
# in the signatures bucket, one key, and its own log group.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "assume_lambda" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "signer" {
  name               = local.function_name
  assume_role_policy = data.aws_iam_policy_document.assume_lambda.json
}

data "aws_iam_policy_document" "signer" {
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.signer.arn}:*"]
  }

  statement {
    sid = "ReadPackages"
    actions = [
      "codeartifact:DescribePackageVersion",
      "codeartifact:ListPackageVersionAssets",
      "codeartifact:GetPackageVersionAsset",
    ]
    resources = ["${replace(aws_codeartifact_repository.packages.arn, ":repository/", ":package/")}/*"]
  }

  statement {
    sid       = "ReadWriteSignatures"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.signatures.arn}/${local.signature_prefix}/*"]
  }

  # Without ListBucket, HeadObject on a missing key returns 403 instead of 404,
  # and the handler can't tell "not signed yet" from "access denied".
  statement {
    sid       = "ListSignatures"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.signatures.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["${local.signature_prefix}/*"]
    }
  }

  # Sign only 32-byte digests, only with ECDSA_SHA_256, only with this key.
  statement {
    sid       = "SignDigests"
    actions   = ["kms:Sign"]
    resources = [local.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:SigningAlgorithm"
      values   = ["ECDSA_SHA_256"]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:MessageType"
      values   = ["DIGEST"]
    }
  }

  # cosign reads the public key and the key's signing algorithm before signing.
  statement {
    sid       = "ReadSigningKey"
    actions   = ["kms:GetPublicKey", "kms:DescribeKey"]
    resources = [local.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "signer" {
  name   = "${local.function_name}-permissions"
  role   = aws_iam_role.signer.id
  policy = data.aws_iam_policy_document.signer.json
}

# ---------------------------------------------------------------------------
# The Lambda function. Build first: scripts/build.sh (Mac/Linux) or
# scripts/build.ps1 (Windows) creates ../build/bootstrap.
# ---------------------------------------------------------------------------
data "archive_file" "lambda" {
  type             = "zip"
  source_file      = "${path.module}/../build/bootstrap"
  output_path      = "${path.module}/../build/function.zip"
  output_file_mode = "0755" # Lambda must be able to execute "bootstrap", even when zipped on Windows
}

resource "aws_cloudwatch_log_group" "signer" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 14
}

resource "aws_lambda_function" "signer" {
  function_name    = local.function_name
  role             = aws_iam_role.signer.arn
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  runtime          = "provided.al2023"
  handler          = "bootstrap"
  architectures    = ["arm64"]
  memory_size      = 1024 # cosign holds each asset in memory while signing it
  timeout          = 120

  environment {
    variables = {
      KMS_KEY_ARN      = local.kms_key_arn
      SIGNATURE_BUCKET = aws_s3_bucket.signatures.bucket
      SIGNATURE_PREFIX = local.signature_prefix
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.signer,
    aws_iam_role_policy.signer,
  ]
}

# ---------------------------------------------------------------------------
# Trigger: EventBridge invokes the Lambda when a package version in this
# domain is published. The handler re-checks the state, so this filter only
# saves invocations.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "codeartifact" {
  count = var.enable_eventbridge_rule ? 1 : 0
  name  = "${var.project}-codeartifact-events"
  event_pattern = jsonencode({
    source        = ["aws.codeartifact"]
    "detail-type" = ["CodeArtifact Package Version State Change"]
    detail = {
      domainName          = [aws_codeartifact_domain.packages.domain]
      packageVersionState = ["Published"]
    }
  })
}

resource "aws_cloudwatch_event_target" "signer" {
  count = var.enable_eventbridge_rule ? 1 : 0
  rule  = aws_cloudwatch_event_rule.codeartifact[0].name
  arn   = aws_lambda_function.signer.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  count         = var.enable_eventbridge_rule ? 1 : 0
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.signer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.codeartifact[0].arn
}

# Public half of the signing key, so anyone can verify signatures offline.
data "aws_kms_public_key" "signing" {
  key_id = local.kms_key_arn
}
