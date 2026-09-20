variable "aws_region" {
  description = "AWS region where the KMS key is created."
  type        = string
  default     = "us-east-2"
}

variable "name" {
  description = "Project name used for naming and tagging."
  type        = string
  default     = "cornerstone-ca"
}

variable "alias_name" {
  description = "KMS alias (without the 'alias/' prefix). Must match the CLI --key-id default."
  type        = string
  default     = "cornerstone-root-ca"
}

variable "description" {
  description = "Description of the KMS key."
  type        = string
  default     = "Cornerstone Root CA signing key (RSA-4096/SHA-256)"
}

variable "deletion_window_in_days" {
  description = "Waiting period before key deletion (7-30 days)."
  type        = number
  default     = 30

  validation {
    condition     = var.deletion_window_in_days >= 7 && var.deletion_window_in_days <= 30
    error_message = "deletion_window_in_days must be between 7 and 30."
  }
}

variable "signer_principal_arns" {
  description = "IAM principals allowed to sign with the key (kms:Sign/GetPublicKey). Empty means IAM-managed."
  type        = list(string)
  default     = []
}

variable "create_certificate_bucket" {
  description = "Create the S3 bucket used to back up public certificates."
  type        = bool
  default     = true
}

variable "assume_role_arn" {
  description = "Optional role ARN to assume before creating resources (cross-account deployments)."
  type        = string
  default     = null
}

variable "tags" {
  description = "Additional tags to merge into the default tags."
  type        = map(string)
  default     = {}
}
