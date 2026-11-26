variable "project" {
  description = "Prefix for every resource name. Also the CodeArtifact domain name."
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
    ARN of the team's shared signing key.
    Leave empty to create a personal test key in your own account.
  EOT
  type        = string
  default     = ""
}

variable "enable_eventbridge_rule" {
  description = "Route CodeArtifact events to the Lambda with this stack's own EventBridge rule. Set to false if the shared event routing sends them instead."
  type        = bool
  default     = true
}
