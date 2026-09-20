# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ricardo Arguello
"""End-to-end and negative-path tests.

The happy path creates a Root with a KMS-backed key, signs a locally generated
Intermediate CA CSR, and verifies the chain with the real ``openssl`` binary.
The KMS double (tests/fake_kms.py) lets all of this run without AWS while
keeping the exact KMS call shape Cornerstone uses in production.
"""

from __future__ import annotations

import shutil
import subprocess
import types

import pytest
from botocore.exceptions import EndpointConnectionError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cornerstone import certificates
from cornerstone.cli import _parse_s3_uri
from cornerstone.cli import main as cli_main
from cornerstone.kms_signer import load_kms_signer

from fake_kms import LocalKmsDouble

OPENSSL = shutil.which("openssl")
pytestmark = pytest.mark.skipif(OPENSSL is None, reason="openssl binary not available")

SUBJECT = certificates.build_subject(
    common_name="Cornerstone Root CA", organization="Example Corp", country="US"
)
ROOT_SUBJECT_STRING = "/C=US/O=Example Corp/CN=Cornerstone Root CA"
CA_SUBJECT_STRING = "/C=US/O=Example Corp/CN=Example IdM Issuing CA"


def openssl(*args):
    return subprocess.run(
        [OPENSSL, *args], capture_output=True, text=True, check=False
    )


def make_csr(
    path,
    key_size=4096,
    subject=CA_SUBJECT_STRING,
    key_type="rsa",
    basic_constraints="critical,CA:TRUE",
    key_usage="critical,keyCertSign,cRLSign",
):
    command = [
        OPENSSL, "req", "-new", "-nodes",
        "-keyout", str(path) + ".key", "-out", str(path),
        "-subj", subject,
    ]
    if key_type == "ec":
        command += ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"]
    else:
        command += ["-newkey", f"rsa:{key_size}"]
    if basic_constraints:
        command += ["-addext", f"basicConstraints={basic_constraints}"]
    if key_usage:
        command += ["-addext", f"keyUsage={key_usage}"]
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return path


def make_empty_subject_csr(path, key_size=4096):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    return path


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    work = tmp_path_factory.mktemp("cornerstone")
    kms = LocalKmsDouble()
    signer = load_kms_signer(kms, "alias/cornerstone-root-ca")
    root = certificates.create_root_certificate(signer, SUBJECT, days=7300)
    csrs = {
        "ca": make_csr(work / "ca.csr"),
        "leaf": make_csr(
            work / "leaf.csr",
            basic_constraints="critical,CA:FALSE",
            key_usage="critical,digitalSignature,keyEncipherment",
        ),
        "noext": make_csr(work / "noext.csr", basic_constraints=None, key_usage=None),
        "same": make_csr(work / "same.csr", subject=ROOT_SUBJECT_STRING),
        "weak": make_csr(work / "weak.csr", key_size=2048),
        "ec": make_csr(work / "ec.csr", key_type="ec"),
        "empty": make_empty_subject_csr(work / "empty.csr"),
    }
    return types.SimpleNamespace(kms=kms, signer=signer, root=root, csr=csrs, work=work)


def test_init_root_and_sign_csr_end_to_end(env, tmp_path):
    env.kms.calls.clear()

    root = certificates.create_root_certificate(env.signer, SUBJECT, days=7300)
    root_path = certificates.write_certificate(tmp_path / "root-ca.crt", root)

    csr = certificates.load_csr(env.csr["ca"])
    intermediate = certificates.sign_intermediate(env.signer, root, csr, days=1825)
    intermediate_path = certificates.write_certificate(
        tmp_path / "idm-intermediate.crt", intermediate
    )

    verify = openssl("verify", "-CAfile", str(root_path), str(intermediate_path))
    assert verify.returncode == 0, verify.stderr
    intermediate.verify_directly_issued_by(root)

    assert len(env.kms.calls) == 2
    assert all(c["MessageType"] == "DIGEST" for c in env.kms.calls)
    assert all(c["SigningAlgorithm"] == "RSASSA_PKCS1_V1_5_SHA_256" for c in env.kms.calls)


def test_certificate_profiles_match_reference(env, tmp_path):
    root_path = certificates.write_certificate(tmp_path / "root-ca.crt", env.root)
    intermediate = certificates.sign_intermediate(
        env.signer, env.root, certificates.load_csr(env.csr["ca"]), days=1825
    )
    intermediate_path = certificates.write_certificate(
        tmp_path / "idm-intermediate.crt", intermediate
    )

    root_bc = env.root.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert root_bc.ca is True and root_bc.path_length is None
    root_ku = env.root.extensions.get_extension_for_class(x509.KeyUsage).value
    assert root_ku.key_cert_sign and root_ku.crl_sign
    assert not (root_ku.digital_signature or root_ku.key_encipherment or root_ku.data_encipherment)

    inter_bc = intermediate.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert inter_bc.ca is True and inter_bc.path_length == 0
    inter_ku = intermediate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert inter_ku.key_cert_sign and inter_ku.crl_sign
    assert not (inter_ku.digital_signature or inter_ku.key_encipherment or inter_ku.data_encipherment)

    for cert in (env.root, intermediate):
        cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)

    text = openssl("x509", "-in", str(intermediate_path), "-noout", "-text").stdout
    assert "CA:TRUE, pathlen:0" in text
    assert "Certificate Sign, CRL Sign" in text
    root_text = openssl("x509", "-in", str(root_path), "-noout", "-text").stdout
    assert "CA:TRUE" in root_text and "pathlen" not in root_text


def test_cli_runs_the_whole_flow(env, tmp_path, monkeypatch):
    monkeypatch.setattr("cornerstone.cli._make_kms_client", lambda args: env.kms)

    root_path = tmp_path / "root-ca.crt"
    assert cli_main([
        "init-root", "--out", str(root_path), "--key-id", "alias/cornerstone-root-ca",
        "--org", "Example Corp", "--country", "US",
    ]) == 0

    intermediate_path = tmp_path / "idm-intermediate.crt"
    assert cli_main([
        "sign-csr",
        "--csr", str(env.csr["ca"]),
        "--root-cert", str(root_path),
        "--out", str(intermediate_path),
    ]) == 0

    verify = openssl("verify", "-CAfile", str(root_path), str(intermediate_path))
    assert verify.returncode == 0, verify.stderr


class FakeS3:
    def __init__(self):
        self.puts = []

    def put_object(self, **kwargs):
        self.puts.append(kwargs)
        return {"ETag": '"fake-etag"'}


def test_cli_backs_up_certificate_to_s3(env, tmp_path, monkeypatch):
    s3 = FakeS3()
    monkeypatch.setattr("cornerstone.cli._make_kms_client", lambda args: env.kms)
    monkeypatch.setattr("cornerstone.cli._make_s3_client", lambda args: s3)

    root_path = tmp_path / "root-ca.crt"
    assert cli_main([
        "init-root", "--out", str(root_path),
        "--org", "Example Corp", "--country", "US",
        "--s3-uri", "s3://cornerstone-backup/root-ca/",
    ]) == 0

    assert len(s3.puts) == 1
    put = s3.puts[0]
    assert put["Bucket"] == "cornerstone-backup"
    assert put["Key"] == "root-ca/root-ca.crt"
    assert put["Body"] == root_path.read_bytes()
    assert put["ServerSideEncryption"] == "AES256"


def test_cli_reports_s3_failure_cleanly(env, tmp_path, monkeypatch, capsys):
    class FailingS3:
        def put_object(self, **kwargs):
            raise EndpointConnectionError(endpoint_url="https://s3.example")

    monkeypatch.setattr("cornerstone.cli._make_kms_client", lambda args: env.kms)
    monkeypatch.setattr("cornerstone.cli._make_s3_client", lambda args: FailingS3())

    code = cli_main([
        "init-root", "--out", str(tmp_path / "root-ca.crt"),
        "--org", "Example Corp", "--country", "US",
        "--s3-uri", "s3://cornerstone-backup/root-ca/",
    ])
    assert code == 2
    err = capsys.readouterr().err
    assert "S3 backup failed" in err and "Traceback" not in err


def test_cli_reports_invalid_country_cleanly(env, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("cornerstone.cli._make_kms_client", lambda args: env.kms)

    code = cli_main([
        "init-root", "--out", str(tmp_path / "root-ca.crt"),
        "--org", "Example Corp", "--country", "USA",
    ])
    assert code == 2
    err = capsys.readouterr().err
    assert err.startswith("error:") and "Traceback" not in err


def test_rejects_leaf_csr(env):
    with pytest.raises(certificates.CertificateError):
        certificates.sign_intermediate(env.signer, env.root, certificates.load_csr(env.csr["leaf"]))


def test_rejects_csr_without_ca_extension(env):
    with pytest.raises(certificates.CertificateError):
        certificates.sign_intermediate(env.signer, env.root, certificates.load_csr(env.csr["noext"]))


def test_allow_non_ca_csr_override(env, tmp_path, monkeypatch):
    monkeypatch.setattr("cornerstone.cli._make_kms_client", lambda args: env.kms)
    root_path = certificates.write_certificate(tmp_path / "root-ca.crt", env.root)

    assert cli_main([
        "sign-csr", "--csr", str(env.csr["noext"]),
        "--root-cert", str(root_path), "--out", str(tmp_path / "a.crt"),
    ]) == 2
    assert cli_main([
        "sign-csr", "--csr", str(env.csr["noext"]),
        "--root-cert", str(root_path), "--out", str(tmp_path / "b.crt"),
        "--allow-non-ca-csr",
    ]) == 0


def test_rejects_empty_subject_csr(env):
    with pytest.raises(certificates.CertificateError):
        certificates.sign_intermediate(env.signer, env.root, certificates.load_csr(env.csr["empty"]))


def test_rejects_same_name_as_root(env):
    with pytest.raises(certificates.CertificateError):
        certificates.sign_intermediate(env.signer, env.root, certificates.load_csr(env.csr["same"]))


def test_rejects_weak_rsa_csr(env):
    with pytest.raises(certificates.CertificateError):
        certificates.sign_intermediate(env.signer, env.root, certificates.load_csr(env.csr["weak"]))


def test_rejects_non_rsa_csr(env):
    with pytest.raises(certificates.CertificateError):
        certificates.sign_intermediate(env.signer, env.root, certificates.load_csr(env.csr["ec"]))


def test_rejects_weak_csr_hash(env):
    # OpenSSL 3.x refuses to sign a CSR with SHA-1, so simulate the parsed
    # CSR that the validator would see.
    real = certificates.load_csr(env.csr["ca"])
    weak = types.SimpleNamespace(
        subject=real.subject,
        extensions=real.extensions,
        public_key=real.public_key,
        signature_hash_algorithm=types.SimpleNamespace(name="sha1"),
        is_signature_valid=True,
    )
    with pytest.raises(certificates.CertificateError):
        certificates.sign_intermediate(env.signer, env.root, weak)


def test_rejects_wrong_root_cert(env):
    other = LocalKmsDouble()
    other_signer = load_kms_signer(other, "alias/other-key")
    other_root = certificates.create_root_certificate(other_signer, SUBJECT, days=7300)
    with pytest.raises(certificates.CertificateError):
        certificates.sign_intermediate(
            env.signer, other_root, certificates.load_csr(env.csr["ca"])
        )


def test_intermediate_validity_capped_to_root(env):
    short_root = certificates.create_root_certificate(env.signer, SUBJECT, days=30)
    intermediate = certificates.sign_intermediate(
        env.signer, short_root, certificates.load_csr(env.csr["ca"]), days=1825
    )
    assert intermediate.not_valid_after_utc <= short_root.not_valid_after_utc


def test_validity_caps_are_enforced(env):
    with pytest.raises(certificates.CertificateError):
        certificates.create_root_certificate(env.signer, SUBJECT, days=10951)
    with pytest.raises(certificates.CertificateError):
        certificates.create_root_certificate(env.signer, SUBJECT, days=0)
    with pytest.raises(certificates.CertificateError):
        certificates.sign_intermediate(
            env.signer, env.root, certificates.load_csr(env.csr["ca"]), days=3651
        )


def test_rejects_kms_key_that_is_not_for_signing():
    kms = LocalKmsDouble(key_usage="ENCRYPT_DECRYPT")
    with pytest.raises(ValueError):
        load_kms_signer(kms, "alias/wrong-key")


def test_rejects_kms_key_without_pkcs1_sha256():
    kms = LocalKmsDouble(signing_algorithms=["RSASSA_PSS_SHA_256"])
    with pytest.raises(ValueError):
        load_kms_signer(kms, "alias/wrong-key")


def test_rejects_kms_key_that_is_not_rsa4096():
    kms = LocalKmsDouble(key_size=2048)
    with pytest.raises(ValueError):
        load_kms_signer(kms, "alias/wrong-key")


def test_write_is_atomic_and_force_works(env, tmp_path):
    path = tmp_path / "cert.crt"
    certificates.write_certificate(path, env.root)
    assert path.is_file()
    with pytest.raises(certificates.CertificateError):
        certificates.write_certificate(path, env.root)
    certificates.write_certificate(path, env.root, force=True)


def test_private_operations_raise(env):
    with pytest.raises(NotImplementedError):
        env.signer.private_numbers()
    with pytest.raises(NotImplementedError):
        env.signer.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    with pytest.raises(NotImplementedError):
        env.signer.decrypt(b"ciphertext", None)


def test_parse_s3_uri():
    assert _parse_s3_uri("s3://bucket/prefix/") == ("bucket", "prefix")
    assert _parse_s3_uri("s3://bucket") == ("bucket", "")
    with pytest.raises(certificates.CertificateError):
        _parse_s3_uri("s3://")
    with pytest.raises(certificates.CertificateError):
        _parse_s3_uri("https://bucket/prefix")
