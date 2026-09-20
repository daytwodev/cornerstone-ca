output "kms_key_id" {
  description = "Key ID of the Root CA KMS key."
  value       = aws_kms_key.root_ca.key_id
}

output "kms_key_arn" {
  description = "ARN of the Root CA KMS key (use it as --key-id for maximum precision)."
  value       = aws_kms_key.root_ca.arn
}

output "kms_alias_name" {
  description = "Alias of the Root CA KMS key."
  value       = aws_kms_alias.root_ca.name
}

output "kms_alias_arn" {
  description = "ARN of the Root CA KMS key alias."
  value       = aws_kms_alias.root_ca.arn
}

output "certificate_bucket_name" {
  description = "S3 bucket for public certificate backups (null if not created)."
  value       = var.create_certificate_bucket ? aws_s3_bucket.certificates[0].id : null
}

output "certificate_bucket_arn" {
  description = "ARN of the certificate backup bucket (null if not created)."
  value       = var.create_certificate_bucket ? aws_s3_bucket.certificates[0].arn : null
}
