data "aws_caller_identity" "current" {}

locals {
  account_id      = data.aws_caller_identity.current.account_id
  function_name   = "${var.project}-s3-signer"
  create_test_key = var.kms_key_arn == ""
  kms_key_arn     = local.create_test_key ? one(aws_kms_key.test[*].arn) : var.kms_key_arn
}

# ---------------------------------------------------------------------------
# Signing key: a personal test key, only created when kms_key_arn is empty.
# Same type as the team key: asymmetric, ECC P-256, sign/verify only.
# ---------------------------------------------------------------------------
resource "aws_kms_key" "test" {
  count                    = local.create_test_key ? 1 : 0
  description              = "${var.project} personal TEST signing key for the S3 signer"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days  = 7
}

resource "aws_kms_alias" "test" {
  count         = local.create_test_key ? 1 : 0
  name          = "alias/${var.project}-s3-signer-test"
  target_key_id = aws_kms_key.test[0].key_id
}

# ---------------------------------------------------------------------------
# Buckets: uploads go into "artifacts", results go into "signatures".
# Keeping them separate means the Lambda can never trigger itself.
# Bucket names must be unique worldwide, so the account ID is added.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "artifacts" {
  bucket        = "${var.project}-artifacts-${local.account_id}"
  force_destroy = true # lets `terraform destroy` delete it even if it has files (fine for a class project)
}

resource "aws_s3_bucket" "signatures" {
  bucket        = "${var.project}-signatures-${local.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "signatures" {
  bucket                  = aws_s3_bucket.signatures.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# IAM role the Lambda runs as. Least privilege: read artifacts, write
# signatures, sign with ONE key, write logs. Nothing else.
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

resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.signer.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "signer" {
  statement {
    sid       = "ReadArtifacts"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${aws_s3_bucket.artifacts.arn}/*"]
  }

  statement {
    sid       = "WriteSignatures"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.signatures.arn}/*"]
  }

  statement {
    sid       = "SignWithTeamKey"
    actions   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
    resources = [local.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "signer" {
  name   = "${local.function_name}-permissions"
  role   = aws_iam_role.signer.id
  policy = data.aws_iam_policy_document.signer.json
}

# ---------------------------------------------------------------------------
# The Lambda function. Build first: scripts/build.ps1 (Windows) or
# scripts/build.sh (Mac/Linux) creates ../build/bootstrap.
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
  memory_size      = 256
  timeout          = 60

  environment {
    variables = {
      KMS_KEY_ARN      = local.kms_key_arn
      SIGNATURE_BUCKET = aws_s3_bucket.signatures.bucket
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.signer,
    aws_iam_role_policy_attachment.logs,
    aws_iam_role_policy.signer,
  ]
}

# ---------------------------------------------------------------------------
# Trigger: S3 calls the Lambda whenever a file is created in "artifacts".
# ---------------------------------------------------------------------------
resource "aws_lambda_permission" "allow_s3" {
  count          = var.enable_s3_trigger ? 1 : 0
  statement_id   = "AllowS3Invoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.signer.function_name
  principal      = "s3.amazonaws.com"
  source_arn     = aws_s3_bucket.artifacts.arn
  source_account = local.account_id
}

resource "aws_s3_bucket_notification" "artifacts" {
  count  = var.enable_s3_trigger ? 1 : 0
  bucket = aws_s3_bucket.artifacts.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.signer.arn
    events              = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_lambda_permission.allow_s3]
}

# Public half of the signing key, so anyone can verify signatures offline.
data "aws_kms_public_key" "signing" {
  key_id = local.kms_key_arn
}
