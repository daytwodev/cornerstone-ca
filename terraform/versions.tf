terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.60"
    }
  }

  # Partial S3 backend. Supply the bucket and region at init time:
  #   terraform init -backend-config=backend.hcl
  # See backend.hcl.example.
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region

  # Optional: assume a role to deploy into another account.
  dynamic "assume_role" {
    for_each = var.assume_role_arn == null ? [] : [var.assume_role_arn]
    content {
      role_arn = assume_role.value
    }
  }
}
