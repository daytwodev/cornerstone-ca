# AGENTS.md

Guidance for AI coding agents working in this repository. Humans are welcome
to use it too. Keep it short; the [README](README.md) has the full picture.

## Project

Cornerstone: a Root CA whose RSA-4096 private key lives in AWS KMS and never
leaves it. Two commands: `init-root` (self-sign the Root) and `sign-csr` (sign
an Intermediate CA CSR). It never issues leaf certificates and has no CRL/OCSP.

## Layout

- `cornerstone/` — Python package.
  - `kms_signer.py` — wraps the KMS key as an `rsa.RSAPrivateKey`.
  - `certificates.py` — X.509 construction and CSR/Root validation.
  - `cli.py` — CLI and error handling.
- `terraform/` — the KMS CMK (RSA-4096, `SIGN_VERIFY`), alias, key policy, and
  the S3 certificate-backup bucket.
- `tests/` — pytest end-to-end and negative-path tests. `fake_kms.py` is an
  in-memory KMS double, so no AWS is needed.
- Never commit: `backend.hcl`, `*.tfvars`, `*.crt`, `*.csr`, `*.key`,
  `.terraform/`, `*.tfstate` (all gitignored).

## Setup and checks

```bash
python3 -m pip install -e ".[test]"
python3 -m pytest -q

terraform -chdir=terraform fmt -check
terraform -chdir=terraform init -backend=false
terraform -chdir=terraform validate
```

CI (`.github/workflows/ci.yml`) runs the same on Python 3.9/3.12/3.13.

## Non-negotiable behavior

- `sign-csr` must keep refusing: CSRs without `basicConstraints CA:TRUE`, empty
  or CN-less subjects, subjects equal to the Root, non-RSA or under-4096-bit
  keys, and MD5/SHA-1 signatures. The explicit escape hatch is
  `--allow-non-ca-csr`; do not weaken the default.
- The certificate profile is intentional: Root = `CA:true` (no pathlen);
  Intermediate = `CA:true, pathlen:0`; `keyUsage` critical
  `keyCertSign+cRLSign`; SKI/AKI = keyid + issuer + serial; SHA-256/RSA-4096.
  Do not add CRL, AIA, or certificate policies unless asked.
- KMS signing uses `MessageType=DIGEST` +
  `SigningAlgorithm=RSASSA_PKCS1_V1_5_SHA_256`.
- The CMK is validated on load (`SIGN_VERIFY`, RSA-4096, supports
  `RSASSA_PKCS1_V1_5_SHA_256`). Keep that fail-fast behavior.
- Private key material never exists outside KMS: never write, log, or print it.

## Conventions

- English for code, comments, docs, and commit messages.
- Minimal dependencies: `boto3` + `cryptography` (the CLI is stdlib only).
- Keep the SPDX headers (`Apache-2.0`), `LICENSE`, and `NOTICE`.
- `terraform/` uses a partial S3 backend; see `backend.hcl.example`.

## Gotchas

- `cryptography`'s Rust x509 backend type-checks the signing key. Duck typing
  alone fails; `KmsRsaPrivateKey` must subclass `rsa.RSAPrivateKey`.
- On a fresh checkout (or CI), `terraform init` needs
  `-backend-config=backend.hcl`; `plan`/`apply`/`destroy` never do.
- KMS keys are per-account and per-region, and their material is not
  exportable.

## Status

Released `v0.1.0`. CI (`pytest` + `terraform validate`) and Dependabot are
enabled. This repo stays **generic** on purpose: concrete deployments (AWS
account IDs, KMS key ARNs, the specific Root CA, state bucket) are kept out of
it.
