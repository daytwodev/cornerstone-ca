# Terraform: Root CA KMS key

Creates and protects the infrastructure piece of Cornerstone:

- Asymmetric KMS CMK (`RSA_4096`, `SIGN_VERIFY`), its alias, and a minimal
  key policy.
- Private S3 bucket (optional) to back up the public certificates.

## Backend

State is stored in S3. The backend is a partial configuration, so pass the
bucket and region at init time:

```bash
cp backend.hcl.example backend.hcl   # then edit it
terraform init -backend-config=backend.hcl
```

The state bucket must already exist (create it once, out of band, with
versioning, SSE, public access blocked, and TLS-only access).

## Usage

```bash
terraform init -backend-config=backend.hcl
terraform plan
# terraform apply   # only when you actually intend to create the root
```

## Protections

- `lifecycle { prevent_destroy = true }` on `aws_kms_key` and
  `aws_s3_bucket`: `terraform destroy` fails instead of deleting the root.
- Key policy `ProtectRootKey`: denies `kms:ScheduleKeyDeletion`,
  `kms:PutKeyPolicy`, `kms:DisableKey`, and `kms:DeleteAlias` to every
  principal (including the account root). Denying `kms:PutKeyPolicy` also
  makes the key policy immutable through the AWS API, so the deny cannot be
  removed without AWS Support. This raises the bar; it is not absolute.
- Backup bucket: versioning enabled, SSE `AES256`, `block_public_*` set to
  true, S3 Object Ownership enforced, and a policy that requires TLS
  (`aws:SecureTransport`).

## Variables

| Variable                    | Default                               | Description |
|-----------------------------|---------------------------------------|-------------|
| `aws_region`                | `us-east-2`                           | Region for the CMK and bucket. |
| `name`                      | `cornerstone-ca`                      | Name used for naming and tags. |
| `alias_name`                | `cornerstone-root-ca`                 | Alias (without `alias/`); must match the CLI default. |
| `description`               | `Cornerstone Root CA signing key ...` | CMK description. |
| `deletion_window_in_days`   | `30`                                  | Deletion window (7-30). |
| `signer_principal_arns`     | `[]`                                  | Principals with `kms:Sign`/`GetPublicKey` and S3 object access. Empty means IAM-managed. |
| `create_certificate_bucket` | `true`                                | Create the public certificate backup bucket. |
| `assume_role_arn`           | `null`                                | Optional role to assume (cross-account deployments). |
| `tags`                      | `{}`                                  | Additional tags. |

## Outputs

`kms_key_id`, `kms_key_arn`, `kms_alias_name`, `kms_alias_arn`,
`certificate_bucket_name`, `certificate_bucket_arn`.

## Key policy

- `EnableAccountAdministration`: allows the account root to administer the
  key (needed so IAM policies can delegate; grants nothing by itself).
- `AllowSigningPrincipals` (optional): `kms:Sign`, `kms:Verify`, and
  `kms:GetPublicKey` for the listed ARNs. `kms:DescribeKey` is not needed:
  the key check comes from the `GetPublicKey` response.
- `ProtectRootKey`: denies deletion, disabling, policy changes, and alias
  deletion of the CMK.

`enable_key_rotation` is `false` because KMS does not support rotation for
asymmetric keys. The bucket uses SSE-S3 (`AES256`) because the CMK is
`SIGN_VERIFY` and cannot encrypt.
