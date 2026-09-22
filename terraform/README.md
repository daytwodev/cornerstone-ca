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
  `kms:DisableKey`, and `kms:DeleteAlias` to every principal (including the
  account root), so the key cannot be deleted or disabled by accident. The
  policy stays editable. A key policy cannot protect the key from the
  account's own administrators; use Organizations SCPs for that.
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
- `ProtectRootKey`: denies deletion, disabling, and alias deletion of the
  CMK.

`enable_key_rotation` is `false` because KMS does not support rotation for
asymmetric keys. The bucket uses SSE-S3 (`AES256`) because the CMK is
`SIGN_VERIFY` and cannot encrypt.

## Destroying

The root is intentionally hard to delete:

- `lifecycle { prevent_destroy = true }` on the KMS key and the S3 bucket.
- The key policy `ProtectRootKey` denies `kms:ScheduleKeyDeletion`,
  `kms:DisableKey`, and `kms:DeleteAlias` to everyone, including the account
  root.

Teardown is Terraform-only. Edit `main.tf` to lift the protections, then apply
and destroy:

1. Remove the two `lifecycle { prevent_destroy = true }` blocks (KMS key and
   bucket), set `force_destroy = true` on the bucket, and remove the
   `ProtectRootKey` statement from the key policy.
2. `terraform apply` (drops the deny) and `terraform destroy` (purges and
   deletes the versioned bucket, and schedules the KMS key deletion).

The bucket ships with `force_destroy = false`, so if you forget to set it to
`true` the destroy fails with `BucketNotEmpty` (safe) instead of emptying it.
Deleting the key is irreversible once the KMS deletion window passes
(`aws kms cancel-key-deletion` reverses it during the window); after that, no
new Intermediate CA can be signed, though existing certificates stay valid as
trust anchors.

The state bucket lives outside this root, so delete it last with the
`terraform-state-bootstrap` tool (a separate repository):

```bash
# from https://github.com/daytwodev/terraform-state-bootstrap
./bootstrap.sh destroy --bucket <name>-tfstate-<account> --yes
```
