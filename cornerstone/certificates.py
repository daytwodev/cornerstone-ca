# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ricardo Arguello
"""X.509 construction and validation for Cornerstone.

Profiles mirror a reference offline Root CA's ``openssl.cnf``:
Root = ``[ v3_root_ca ]``, Intermediate = ``[ v3_intermediate_idm ]``.

Deployment-specific fields (certificate policies, CRL distribution points,
and AIA) are deliberately omitted: Cornerstone publishes no CRL and no
certificate repository, and it never issues leaf certificates.
"""

from __future__ import annotations

import datetime
import os
import pathlib
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT_VALIDITY_DAYS = 7300  # ~20 years
ROOT_MAX_VALIDITY_DAYS = 10950  # ~30 years
INTERMEDIATE_VALIDITY_DAYS = 1825  # ~5 years
INTERMEDIATE_MAX_VALIDITY_DAYS = 3650  # ~10 years

# Cornerstone issues RSA-4096 certificates; the signed Intermediate key must
# not downgrade that. Matches the reference CA's min_rsa_bits.
MIN_INTERMEDIATE_RSA_BITS = 4096

# Backdate notBefore to tolerate modest clock skew between the signing host,
# KMS, and the systems that will consume the certificate.
NOT_BEFORE_BACKDATE = datetime.timedelta(minutes=15)

_WEAK_HASHES = {"md5", "sha1"}

DEFAULT_ROOT_CN = "Cornerstone Root CA"


class CertificateError(Exception):
    """Raised for invalid inputs or failed certificate construction."""


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def random_serial_number():
    return x509.random_serial_number()


def build_subject(common_name, organization, country, organizational_unit=None):
    attributes = []
    if country:
        attributes.append(x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country))
    if organization:
        attributes.append(x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, organization))
    if organizational_unit:
        attributes.append(
            x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit)
        )
    attributes.append(x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name))
    return x509.Name(attributes)


def key_usage_ca():
    """keyUsage = critical, keyCertSign, cRLSign (nothing else)."""
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def _authority_key_identifier(issuer_name, issuer_ski_digest, issuer_serial):
    """authorityKeyIdentifier = keyid:always, issuer:always."""
    return x509.AuthorityKeyIdentifier(
        key_identifier=issuer_ski_digest,
        authority_cert_issuer=[x509.DirectoryName(issuer_name)],
        authority_cert_serial_number=issuer_serial,
    )


def validate_days(days, maximum, label):
    if not isinstance(days, int) or days <= 0:
        raise CertificateError(f"{label} validity must be a positive number of days.")
    if days > maximum:
        raise CertificateError(
            f"{label} validity {days} days exceeds the {maximum}-day cap."
        )


def _validate_root_certificate(signer, root_cert):
    """Ensure --root-cert is a self-signed CA issued by the KMS key in use."""
    try:
        constraints = root_cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound:
        raise CertificateError("--root-cert is not a CA (missing basicConstraints).")
    if not constraints.ca:
        raise CertificateError("--root-cert is not a CA (basicConstraints CA:FALSE).")
    if root_cert.subject != root_cert.issuer:
        raise CertificateError(
            "--root-cert is not self-signed; Cornerstone expects the self-signed Root."
        )

    now = utcnow()
    if root_cert.not_valid_after_utc <= now:
        raise CertificateError("--root-cert is expired.")
    if root_cert.not_valid_before_utc > now:
        raise CertificateError("--root-cert is not yet valid.")

    root_key = root_cert.public_key()
    signer_key = signer.public_key()
    if (
        not isinstance(root_key, rsa.RSAPublicKey)
        or root_key.public_numbers() != signer_key.public_numbers()
    ):
        raise CertificateError("--root-cert does not match the KMS key (--key-id).")


def _validate_csr(csr, root_cert, require_ca):
    """Reject CSRs that should not become an Intermediate CA certificate."""
    subject = csr.subject
    if not list(subject):
        raise CertificateError("CSR has an empty subject; RFC 5280 requires a subject.")
    if not subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
        raise CertificateError("CSR subject has no commonName (CN).")
    if subject == root_cert.subject:
        raise CertificateError(
            "CSR subject is identical to the Root subject; refusing a same-name sub-CA."
        )

    if require_ca:
        try:
            constraints = csr.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound:
            raise CertificateError(
                "CSR does not request basicConstraints CA:TRUE; refusing to sign a "
                "non-CA request (use --allow-non-ca-csr to override)."
            )
        if not constraints.ca:
            raise CertificateError(
                "CSR requests basicConstraints CA:FALSE; refusing to sign a non-CA "
                "request (use --allow-non-ca-csr to override)."
            )

    public_key = csr.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise CertificateError(
            f"CSR public key must be RSA, not {type(public_key).__name__}."
        )
    if public_key.key_size < MIN_INTERMEDIATE_RSA_BITS:
        raise CertificateError(
            f"CSR RSA key is {public_key.key_size}-bit; "
            f"minimum is {MIN_INTERMEDIATE_RSA_BITS}-bit."
        )

    signature_hash = csr.signature_hash_algorithm
    if signature_hash is None or signature_hash.name in _WEAK_HASHES:
        raise CertificateError(
            "CSR is signed with a weak or missing hash; use SHA-256 or stronger."
        )


def _write_pem(path, cert, force):
    """Write the certificate atomically, refusing to overwrite unless forced."""
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = cert.public_bytes(serialization.Encoding.PEM)

    if not force:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        except FileExistsError:
            raise CertificateError(f"{path} already exists; pass --force to overwrite.")
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(path, 0o644)
        return path

    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".cornerstone-crt-")
    tmp_path = pathlib.Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
    return path


def create_root_certificate(signer, subject_name, days=ROOT_VALIDITY_DAYS):
    """Build and self-sign the Root CA certificate using the KMS signer."""
    validate_days(days, ROOT_MAX_VALIDITY_DAYS, "Root CA")

    public_key = signer.public_key()
    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    serial = random_serial_number()
    now = utcnow()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now - NOT_BEFORE_BACKDATE)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(ski, critical=False)
        .add_extension(
            _authority_key_identifier(subject_name, ski.digest, serial),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(key_usage_ca(), critical=True)
    )
    return builder.sign(signer, hashes.SHA256())


def load_certificate(path):
    path = pathlib.Path(path)
    if not path.is_file():
        raise CertificateError(f"Certificate not found: {path}")
    try:
        return x509.load_pem_x509_certificate(path.read_bytes())
    except ValueError as exc:
        raise CertificateError(f"Could not parse certificate {path}: {exc}")


def load_csr(path):
    """Load a CSR from PEM (or DER) and verify its self-signature."""
    path = pathlib.Path(path)
    if not path.is_file():
        raise CertificateError(f"CSR not found: {path}")
    data = path.read_bytes()
    try:
        csr = x509.load_pem_x509_csr(data)
    except ValueError:
        try:
            csr = x509.load_der_x509_csr(data)
        except ValueError as exc:
            raise CertificateError(f"Could not parse CSR {path}: {exc}")
    if not csr.is_signature_valid:
        raise CertificateError(f"CSR {path} has an invalid signature.")
    return csr


def _issuer_subject_key_identifier(root_cert):
    try:
        return root_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value
    except x509.ExtensionNotFound:
        return x509.SubjectKeyIdentifier.from_public_key(root_cert.public_key())


def sign_intermediate(signer, root_cert, csr, days=INTERMEDIATE_VALIDITY_DAYS, require_ca=True):
    """Sign an externally generated Intermediate CA CSR with the Root key."""
    validate_days(days, INTERMEDIATE_MAX_VALIDITY_DAYS, "Intermediate CA")
    _validate_root_certificate(signer, root_cert)
    _validate_csr(csr, root_cert, require_ca)

    public_key = csr.public_key()
    issuer_ski = _issuer_subject_key_identifier(root_cert)
    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    now = utcnow()

    not_after = now + datetime.timedelta(days=days)
    if not_after > root_cert.not_valid_after_utc:
        not_after = root_cert.not_valid_after_utc

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(root_cert.subject)
        .public_key(public_key)
        .serial_number(random_serial_number())
        .not_valid_before(now - NOT_BEFORE_BACKDATE)
        .not_valid_after(not_after)
        .add_extension(ski, critical=False)
        .add_extension(
            _authority_key_identifier(
                root_cert.subject, issuer_ski.digest, root_cert.serial_number
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(key_usage_ca(), critical=True)
    )
    return builder.sign(signer, hashes.SHA256())


def write_certificate(path, cert, force=False):
    return _write_pem(path, cert, force)
