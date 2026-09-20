# Security Policy

Cornerstone is a manual Root CA CLI whose signing key lives in AWS KMS, plus a
small Terraform root that creates and protects that key. Security reports are
welcome and taken seriously.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**:

- Preferred: open a private advisory via GitHub's
  [Security Advisories](../../security/advisories/new) ("Report a
  vulnerability").
- If you cannot use GitHub, contact a maintainer directly rather than opening
  a public issue.

Please include: a description, the impact, a minimal reproduction, affected
versions, and any suggested fix.

Do not disclose the issue publicly until a fix or mitigation is available.

## Scope

In scope:

- The `cornerstone` Python package (certificate construction, CSR validation,
  KMS signing, S3 backup).
- The certificate profiles (extensions, validity, subject handling).
- The Terraform root (IAM key policy, S3 backup bucket, protections).

Out of scope:

- AWS KMS/API behavior itself.
- Misconfiguration of a user's AWS account, IAM policies, or S3 bucket outside
  this repository.
- The security of the systems that generate and consume CSRs/certificates.

## Design boundaries

Cornerstone deliberately does **not** issue leaf certificates, does not
publish a CRL or OCSP responder, and does not run a network service. It only
signs Intermediate CA CSRs and never generates keys or CSRs. Anything that
requires those capabilities is out of scope by design.
