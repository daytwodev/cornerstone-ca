# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ricardo Arguello
"""Command line interface: ``cornerstone init-root`` / ``cornerstone sign-csr``.

This is a manual ceremony tool. It creates the Root once, then signs the
Intermediate CA CSR that an external IdM generates. It never generates keys
or CSRs and never issues leaf certificates.
"""

from __future__ import annotations

import argparse
import sys

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes

try:
    from botocore.exceptions import BotoCoreError, ClientError

    _AWS_ERRORS = (BotoCoreError, ClientError)
except ImportError:  # pragma: no cover - botocore ships with boto3
    _AWS_ERRORS = ()

from . import __version__, certificates
from .kms_signer import load_kms_signer

DEFAULT_KEY_ID = "alias/cornerstone-root-ca"


def _make_session(args):
    # boto3 is imported lazily so unit tests of the certificate layer do not
    # need AWS credentials/configuration available.
    import boto3

    if args.profile:
        return boto3.Session(profile_name=args.profile)
    return boto3.Session()


def _make_kms_client(args):
    return _make_session(args).client("kms", region_name=args.region)


def _make_s3_client(args):
    return _make_session(args).client("s3", region_name=args.region)


def _parse_s3_uri(uri):
    prefix = "s3://"
    if not uri.startswith(prefix):
        raise certificates.CertificateError(
            f"invalid S3 URI {uri!r}; expected s3://bucket/prefix"
        )
    rest = uri[len(prefix):]
    bucket, _, key_prefix = rest.partition("/")
    if not bucket:
        raise certificates.CertificateError(
            f"invalid S3 URI {uri!r}; expected s3://bucket/prefix"
        )
    return bucket, key_prefix.strip("/")


def _upload_certificate(args, path):
    """Back up a public certificate to S3. The .crt is not secret."""
    if not args.s3_uri:
        return None
    s3 = _make_s3_client(args)
    bucket, prefix = _parse_s3_uri(args.s3_uri)
    key = f"{prefix}/{path.name}" if prefix else path.name
    try:
        response = s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=path.read_bytes(),
            ContentType="application/x-pem-file",
            ServerSideEncryption="AES256",
        )
    except _AWS_ERRORS as exc:
        raise certificates.CertificateError(
            f"{path} was written locally, but the S3 backup failed: {exc}. "
            "Back it up manually; the .crt cannot be reconstructed from KMS."
        )
    if not response.get("ETag"):
        raise certificates.CertificateError(
            f"{path} was written locally, but the S3 backup could not be "
            f"confirmed (no ETag for s3://{bucket}/{key})."
        )
    uri = f"s3://{bucket}/{key}"
    print(f"Backed up to S3: {uri}")
    return uri


def _print_certificate_summary(label, cert):
    print(f"{label}:")
    print(f"  Subject         : {cert.subject.rfc4514_string()}")
    print(f"  Issuer          : {cert.issuer.rfc4514_string()}")
    print(f"  Serial          : {cert.serial_number:x}")
    print(f"  Not valid before: {cert.not_valid_before_utc.isoformat()}")
    print(f"  Not valid after : {cert.not_valid_after_utc.isoformat()}")
    print(f"  SHA-256         : {cert.fingerprint(hashes.SHA256()).hex()}")


def _assert_issued_by(cert, issuer_cert):
    try:
        cert.verify_directly_issued_by(issuer_cert)
    except (ValueError, InvalidSignature) as exc:
        raise certificates.CertificateError(
            f"issued certificate does not verify against the issuer ({exc}); "
            "check --root-cert and --key-id."
        )


def cmd_init_root(args):
    certificates.validate_days(args.days, certificates.ROOT_MAX_VALIDITY_DAYS, "Root CA")

    kms = _make_kms_client(args)
    signer = load_kms_signer(kms, args.key_id)

    subject = certificates.build_subject(
        common_name=args.cn,
        organization=args.org,
        country=args.country,
    )
    print(f"Creating Root CA certificate with KMS key {args.key_id} ...")
    cert = certificates.create_root_certificate(signer, subject, days=args.days)
    _assert_issued_by(cert, cert)
    path = certificates.write_certificate(args.out, cert, force=args.force)

    _print_certificate_summary("Root CA certificate", cert)
    print("  BasicConstraints: critical, CA:TRUE (no pathlen)")
    print("  KeyUsage        : critical, keyCertSign, cRLSign")
    print(f"Written: {path}")
    _upload_certificate(args, path)
    print("The Root private key never left KMS; only the public .crt was written.")
    return 0


def cmd_sign_csr(args):
    certificates.validate_days(
        args.days, certificates.INTERMEDIATE_MAX_VALIDITY_DAYS, "Intermediate CA"
    )

    root_cert = certificates.load_certificate(args.root_cert)
    csr = certificates.load_csr(args.csr)

    kms = _make_kms_client(args)
    signer = load_kms_signer(kms, args.key_id)

    print(f"Signing Intermediate CA CSR {args.csr} with KMS key {args.key_id} ...")
    cert = certificates.sign_intermediate(
        signer,
        root_cert,
        csr,
        days=args.days,
        require_ca=not args.allow_non_ca_csr,
    )
    _assert_issued_by(cert, root_cert)
    path = certificates.write_certificate(args.out, cert, force=args.force)

    _print_certificate_summary("Intermediate CA certificate", cert)
    print("  BasicConstraints: critical, CA:TRUE, pathlen:0")
    print("  KeyUsage        : critical, keyCertSign, cRLSign")
    print(f"Written: {path}")
    _upload_certificate(args, path)
    print("Cornerstone never generated this key or CSR; it only signed what it received.")
    return 0


def _add_aws_options(parser):
    parser.add_argument(
        "--key-id",
        default=DEFAULT_KEY_ID,
        help=f"KMS key id, ARN or alias (default: {DEFAULT_KEY_ID}).",
    )
    parser.add_argument("--region", default=None, help="AWS region (optional).")
    parser.add_argument("--profile", default=None, help="AWS CLI profile (optional).")
    parser.add_argument(
        "--s3-uri",
        default=None,
        help="Back up the generated public certificate here, e.g. s3://bucket/prefix.",
    )


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cornerstone",
        description="Root CA whose private key lives in AWS KMS (RSA-4096/SHA-256).",
    )
    parser.add_argument("--version", action="version", version=f"cornerstone {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser(
        "init-root", help="Create and self-sign the Root CA certificate."
    )
    init.add_argument("--out", default="root-ca.crt", help="Output certificate path.")
    init.add_argument("--cn", default=certificates.DEFAULT_ROOT_CN, help="Root CA common name.")
    init.add_argument("--org", required=True, help="Organization (O) for the Root subject.")
    init.add_argument("--country", required=True, help="Country (C), ISO-3166 alpha-2.")
    init.add_argument(
        "--days",
        type=int,
        default=certificates.ROOT_VALIDITY_DAYS,
        help=(
            f"Validity in days (default: {certificates.ROOT_VALIDITY_DAYS}, "
            f"max: {certificates.ROOT_MAX_VALIDITY_DAYS})."
        ),
    )
    init.add_argument("--force", action="store_true", help="Overwrite an existing output file.")
    _add_aws_options(init)
    init.set_defaults(func=cmd_init_root)

    sign = subparsers.add_parser(
        "sign-csr", help="Sign an Intermediate CA CSR (CA:true, pathlen:0)."
    )
    sign.add_argument("--csr", required=True, help="CSR (PEM/DER) generated elsewhere.")
    sign.add_argument("--root-cert", default="root-ca.crt", help="Root CA certificate (PEM).")
    sign.add_argument("--out", default="intermediate-ca.crt", help="Output certificate path.")
    sign.add_argument(
        "--days",
        type=int,
        default=certificates.INTERMEDIATE_VALIDITY_DAYS,
        help=(
            f"Validity in days (default: {certificates.INTERMEDIATE_VALIDITY_DAYS}, "
            f"max: {certificates.INTERMEDIATE_MAX_VALIDITY_DAYS})."
        ),
    )
    sign.add_argument(
        "--allow-non-ca-csr",
        action="store_true",
        help="DANGER: sign even if the CSR does not request basicConstraints CA:TRUE.",
    )
    sign.add_argument("--force", action="store_true", help="Overwrite an existing output file.")
    _add_aws_options(sign)
    sign.set_defaults(func=cmd_sign_csr)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except certificates.CertificateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (ValueError, OSError, x509.ExtensionNotFound, InvalidSignature) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except _AWS_ERRORS as exc:
        print(f"error: AWS request failed: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
