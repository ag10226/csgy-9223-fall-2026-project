variable "project" {
  description = "Prefix for every resource name."
  type        = string
  default     = "group12"
}

variable "aws_region" {
  description = "The whole team must use the same region."
  type        = string
  default     = "us-east-1"
}

variable "kms_key_arn" {
  description = <<-EOT
    ARN of the team's shared signing key (from Phillip).
    Leave empty to create a personal test key in your own account.
  EOT
  type        = string
  default     = ""
}

variable "enable_s3_trigger" {
  description = "Trigger the Lambda directly from S3. Set to false if Phillip routes events through EventBridge instead."
  type        = bool
  default     = true
}
