# Cornerstone

A Root CA whose private key lives in an AWS KMS asymmetric CMK and never
leaves it. The goal is a **stable** trust anchor that team laptops trust once,
while Intermediate CAs (for example a Red Hat IdM deployment in External CA
mode) come and go without changing the root.

It is the cloud equivalent of an offline OpenSSL + LUKS2 VM: the key is not
in a file, signing happens in KMS, and the CLI is run by hand when something
needs to be signed — just like the offline VM is booted only for a single
ceremony.

## What it does

1. `init-root`: builds and self-signs the Root certificate with the CMK key
   (`basicConstraints = critical, CA:true` with no pathlen; default validity
   7300 days).
2. `sign-csr`: parses an **Intermediate CA** CSR (PEM/DER), verifies its
   self-signature, and signs it with the CMK key (`CA:true, pathlen:0`;
   default validity 1825 days, cap 3650). It refuses CSRs that do not request
   `basicConstraints CA:TRUE`, have an empty subject or no CN, share the Root
   subject, or carry a non-RSA/weak key or a weak signature hash.
3. With `--s3-uri`, backs up the public `.crt` to S3. KMS stores the key,
   **not** the certificate, so the `.crt` is what must be preserved. The
   upload is verified (ETag) and a failure is reported; losing the Root
   `.crt` is also unrecoverable, so protect the backup bucket too.

## What it does NOT do (on purpose)

- No leaf (server/client TLS) certificates.
- No key or CSR generation: it only receives, verifies, and signs, matching
  the reference offline Root CA.
- No certificate reconstruction from KMS (it does not store serial/validity):
  that is why it backs the `.crt` up to S3.
- No CRL, no OCSP, no AIA repository.
- Not serverless: a manual CLI, not Lambda/API Gateway.
- No multi-tenancy and no configurable certificate profiles (the `--profile`
  flag is only the AWS CLI profile).

## Layout

```
cornerstone-ca/
├── terraform/        # KMS asymmetric CMK (RSA_4096, SIGN_VERIFY) + alias + key policy
├── cornerstone/      # Python package (boto3 + cryptography)
└── tests/            # end-to-end flow with a locally generated openssl CSR
```

## Requirements

- Python >= 3.9 with `boto3` and `cryptography >= 42` (`pip install -e .`).
- `openssl` (only to verify/inspect; the CLI does not use it).
- An asymmetric RSA-4096 `SIGN_VERIFY` CMK (created by the Terraform) and
  `kms:Sign` + `kms:GetPublicKey` permission on it. When the key is loaded,
  Cornerstone verifies it is `SIGN_VERIFY`, RSA-4096, and supports
  `RSASSA_PKCS1_V1_5_SHA_256`; it fails fast otherwise.

## Terraform

Creates the CMK, its alias, a minimal key policy, and a private S3 bucket for
backing up public certificates. State uses a partial S3 backend, so pass the
bucket and region at init time:

```bash
cd terraform
cp backend.hcl.example backend.hcl   # then edit it
terraform init -backend-config=backend.hcl
terraform plan
terraform apply        # only when you actually intend to create the root
```

Root protections:

- `lifecycle { prevent_destroy = true }` on the CMK and the bucket (Terraform
  cannot destroy them).
- Key policy `ProtectRootKey`: denies `kms:ScheduleKeyDeletion`,
  `kms:DisableKey`, and `kms:DeleteAlias` to everyone, including the account
  root, so the key cannot be deleted or disabled by accident. The policy stays
  editable. A key policy cannot protect the key from the account's own
  administrators (whoever can `kms:PutKeyPolicy` controls it); use
  Organizations SCPs for that.
- Backup bucket: versioning, SSE (AES256), public access blocked, and S3
  Object Ownership enforced.

The default alias is `alias/cornerstone-root-ca`, which is also the CLI
`--key-id` default. Outputs: `kms_key_id`, `kms_key_arn`, `kms_alias_name`,
`kms_alias_arn`, `certificate_bucket_name`, `certificate_bucket_arn`.

## Usage

```bash
# Once: create and save the root (the .crt is public).
cornerstone init-root --out root-ca.crt \
  --cn "Cornerstone Root CA" --org "Example Corp" --country US \
  --s3-uri s3://cornerstone-ca-certificates-<account>/root-ca/

# Every time the IdM is rebuilt: sign its Intermediate CA CSR.
cornerstone sign-csr --csr ipa.csr --root-cert root-ca.crt --out ipa.crt \
  --s3-uri s3://cornerstone-ca-certificates-<account>/intermediates/
```

Useful options: `--key-id` (CMK ARN/alias), `--region`, `--profile`,
`--s3-uri` (back up the `.crt`), `--days` (caps 10950 / 3650), `--force`.
`--org` and `--country` are required for `init-root`. `sign-csr` refuses
non-CA CSRs unless you pass the explicit, dangerous `--allow-non-ca-csr`.

### Red Hat IdM (External CA) flow

```bash
# On the IdM server:
ipa-server-install --external-ca           # generates /root/ipa.csr
# Copy ipa.csr to the laptop and sign it:
cornerstone sign-csr --csr ipa.csr --root-cert root-ca.crt --out ipa.crt
# Return ipa.crt + root-ca.crt to IdM and finish the installation:
ipa-server-install --external-cert-file=/root/ipa.crt \
                   --external-cert-file=/root/root-ca.crt
```

## Certificate profile

| Field            | Root (init-root)                  | Intermediate (sign-csr)               |
|------------------|-----------------------------------|---------------------------------------|
| subject          | `--cn/--org/--country`            | the one from the received CSR         |
| issuer           | itself                            | the Root                              |
| basicConstraints | critical, `CA:true` (no pathlen)  | critical, `CA:true, pathlen:0`        |
| keyUsage         | critical, `keyCertSign, cRLSign`  | critical, `keyCertSign, cRLSign`      |
| SKI / AKI        | hash / keyid + issuer + serial    | hash / keyid + issuer + serial        |
| signature        | SHA-256 with RSA-4096 (KMS)       | SHA-256 with RSA-4096 (KMS)           |

Certificate policies and CRL/AIA fields are omitted on purpose; they are
deployment-specific and IdM does not require them. The profile matches the
`[ v3_root_ca ]` and `[ v3_intermediate_idm ]` sections of the offline
reference CA for everything that matters to the chain of trust. `notBefore`
is backdated 15 minutes to tolerate clock skew, and the Intermediate `notAfter`
is capped to the Root's `notAfter`.

## Verification

```bash
python3 -m pytest tests -v          # 23 tests, including the full CLI flow
```

The tests generate a CSR with `openssl req -new -newkey rsa:4096`, sign it,
and validate the chain with the real openssl binary. Representative output:

```
$ openssl verify -CAfile root-ca.crt idm-intermediate.crt
idm-intermediate.crt: OK

$ openssl x509 -in idm-intermediate.crt -noout -text
        X509v3 Basic Constraints: critical
            CA:TRUE, pathlen:0
        X509v3 Key Usage: critical
            Certificate Sign, CRL Sign
    Signature Algorithm: sha256WithRSAEncryption
```

Every signature calls KMS with `MessageType=DIGEST` and
`SigningAlgorithm=RSASSA_PKCS1_V1_5_SHA_256` (RSA-4096 + SHA-256), which is
the equivalent of `openssl ca -md sha256`.

## Findings from official documentation (FreeIPA / Dogtag / RHEL 10)

- FreeIPA imposes no X.509 extensions of its own: in the second phase of the
  install (`cainstance.py`, `self.external == 2`) it loads the signed
  certificate plus the chain and hands them to Dogtag. The real requirement
  is Dogtag's: the certificate must be a valid CA (`basicConstraints
  CA:true`, `keyUsage keyCertSign+cRLSign`).
- The CSR generated by `ipa-server-install --external-ca` requests
  `basicConstraints=CA:TRUE` and `keyUsage=digitalSignature,keyCertSign,cRLSign`.
  The certificate returned to it does **not** have to repeat `digitalSignature`:
  `keyCertSign` is enough to sign certificates (our profile omits it).
- AIA/CRL/EKU/policies are not required on the Intermediate for IdM to accept
  it; those fields are for the deployment's relying parties, not for IdM.
- RHEL 10 *Managing certificates in IdM*, chapter 18 (externally-signed CA):
  confirms the IdM CA becomes a **subCA** of the external CA and that, "from
  the certificate point of view, there is no difference between being signed
  by a self-signed IdM CA and being signed externally" (that is, it is a
  normal CA certificate). It lists no additional extension requirements.
- `--external-cert-file` is repeated once per certificate: the signed one and
  the complete root/chain (the docs require the full chain). Accepted formats:
  PEM/DER/PKCS#7 (Table 5.2). The same flag is used for the initial install
  (`ipa-server-install`) and for renewal (`ipa-cacert-manage renew
  --external-ca`).
- The certificate must match the key IdM generated in phase 1; Dogtag
  verifies that pairing.
- Note: older docs use `--external_cert_file`/`--external_ca_file`; RHEL 9+
  uses the repeated `--external-cert-file`.

## Not tested without AWS

- `terraform apply` / actual CMK creation (the Terraform was written and
  validated with `terraform validate`; it was not applied).
- Real `kms:Sign` / `kms:GetPublicKey` calls. The tests use an in-memory
  double with **the same call shape** (DIGEST + algorithm), backed by a real
  local RSA key, and the chain is verified with openssl.
- End-to-end against a real IdM (`ipa-server-install --external-ca`).

## References

- `aws-samples/csr-builder-for-kms` — builds KMS-signed CSRs using
  `asn1crypto` + `oscrypto`. It confirms the algorithm name
  (`RSASSA_PKCS1_V1_5_SHA_256`) and the `KeyUsage == SIGN_VERIFY` check. Its
  stack was not adopted (`oscrypto` has been unmaintained since 2022 and has
  issues with OpenSSL 3); Cornerstone uses `cryptography`.
- `ericnorris/google-kms-x509` (Go) and `necrobious/aws-kms-ca` (Rust) — the
  exact analogue of our approach: implement the language's private-key
  interface (`crypto.Signer` in Go) on top of KMS so the X.509 builder signs
  transparently.
- `aws-samples/aws-kms-jce` — KMS ↔ Java mapping table, confirming
  `RSASSA_PKCS1_V1_5_SHA_256` = `SHA256withRSA`.

## License

Apache License 2.0. Copyright 2026 Ricardo Arguello. See [LICENSE](LICENSE)
and [NOTICE](NOTICE).
