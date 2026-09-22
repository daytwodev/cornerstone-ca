data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  tags = merge(
    {
      Name      = "${var.name}-root-ca"
      Project   = var.name
      ManagedBy = "cornerstone-ca"
    },
    var.tags,
  )
}

# Asymmetric RSA-4096 signing key (SIGN_VERIFY) used by the Root CA.
# KMS never exports the private key and does not support rotation for
# asymmetric keys.
resource "aws_kms_key" "root_ca" {
  description              = var.description
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_4096"
  deletion_window_in_days  = var.deletion_window_in_days
  enable_key_rotation      = false
  policy                   = data.aws_iam_policy_document.root_ca_key.json

  tags = local.tags

  # Losing this key is unrecoverable: block accidental destruction.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "root_ca" {
  name          = "alias/${var.alias_name}"
  target_key_id = aws_kms_key.root_ca.key_id
}

data "aws_iam_policy_document" "root_ca_key" {
  # Required so account IAM policies can delegate use of the key. It does not
  # grant permissions by itself: it only allows IAM to do so.
  statement {
    sid       = "EnableAccountAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  # Least privilege for whoever signs from a laptop. Only kms:Sign and
  # kms:GetPublicKey are used (the key check is done from the GetPublicKey
  # response, so kms:DescribeKey is not needed).
  dynamic "statement" {
    for_each = length(var.signer_principal_arns) > 0 ? [1] : []

    content {
      sid       = "AllowSigningPrincipals"
      effect    = "Allow"
      actions   = ["kms:Sign", "kms:Verify", "kms:GetPublicKey"]
      resources = ["*"]

      principals {
        type        = "AWS"
        identifiers = var.signer_principal_arns
      }
    }
  }

  # No principal, not even the account root, can delete, disable, or remove
  # the alias of the CMK. This protects the key from accidental/irreversible
  # destruction. A key policy cannot protect the key from the account's own
  # administrators (whoever can kms:PutKeyPolicy controls the key); use
  # Organizations SCPs for that.
  statement {
    sid    = "ProtectRootKey"
    effect = "Deny"

    actions = [
      "kms:ScheduleKeyDeletion",
      "kms:DisableKey",
      "kms:DeleteAlias",
    ]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

# Durable backup of the PUBLIC certificates (Root and Intermediate). This is
# not a distribution repository: public access is blocked and TLS is required.
resource "aws_s3_bucket" "certificates" {
  count = var.create_certificate_bucket ? 1 : 0

  bucket = "${var.name}-certificates-${local.account_id}"
  tags   = local.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "certificates" {
  count = var.create_certificate_bucket ? 1 : 0

  bucket = aws_s3_bucket.certificates[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "certificates" {
  count = var.create_certificate_bucket ? 1 : 0

  bucket = aws_s3_bucket.certificates[0].id

  rule {
    # The Root CMK is SIGN_VERIFY and cannot encrypt, so use SSE-S3.
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "certificates" {
  count = var.create_certificate_bucket ? 1 : 0

  bucket                  = aws_s3_bucket.certificates[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "certificates" {
  count = var.create_certificate_bucket ? 1 : 0

  bucket = aws_s3_bucket.certificates[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_policy" "certificates" {
  count = var.create_certificate_bucket ? 1 : 0

  bucket = aws_s3_bucket.certificates[0].id
  policy = data.aws_iam_policy_document.certificates_bucket[0].json
}

data "aws_iam_policy_document" "certificates_bucket" {
  count = var.create_certificate_bucket ? 1 : 0

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.certificates[0].arn, "${aws_s3_bucket.certificates[0].arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  dynamic "statement" {
    for_each = length(var.signer_principal_arns) > 0 ? [1] : []

    content {
      sid    = "AllowSigningPrincipalsBackup"
      effect = "Allow"

      actions = [
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket",
      ]
      resources = [
        aws_s3_bucket.certificates[0].arn,
        "${aws_s3_bucket.certificates[0].arn}/*",
      ]

      principals {
        type        = "AWS"
        identifiers = var.signer_principal_arns
      }
    }
  }
}
