# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ricardo Arguello
"""Duck-typed RSA private key that delegates signing to an AWS KMS CMK.

cryptography's Rust x509 backend isinstance-checks the key type, so we
subclass ``rsa.RSAPrivateKey`` and implement ``sign()`` on top of KMS.
Private material never leaves KMS: the accessors for it raise.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as padding_module
from cryptography.hazmat.primitives.asymmetric import rsa


# RSA-4096 + SHA-256, matching the offline reference CA.
DEFAULT_SIGNING_ALGORITHM = "RSASSA_PKCS1_V1_5_SHA_256"
EXPECTED_KEY_SPEC = "RSA_4096"

# KMS Sign accepts a pre-hashed digest with MessageType=DIGEST; these are the
# only digest lengths the project supports.
_KMS_DIGEST_ALGORITHMS = {
    hashes.SHA256: DEFAULT_SIGNING_ALGORITHM,
}


def _validate_key_metadata(response, key_id):
    """Fail fast if the CMK is not a SIGN_VERIFY RSA-4096/SHA-256 key."""
    key_usage = response.get("KeyUsage")
    if key_usage != "SIGN_VERIFY":
        raise ValueError(
            f"KMS key {key_id!r} has KeyUsage {key_usage!r}; Cornerstone requires SIGN_VERIFY."
        )

    # KMS always reports SigningAlgorithms for a SIGN_VERIFY key; treat a
    # missing list as a failure instead of silently skipping the check.
    algorithms = response.get("SigningAlgorithms") or []
    if DEFAULT_SIGNING_ALGORITHM not in algorithms:
        raise ValueError(
            f"KMS key {key_id!r} does not support {DEFAULT_SIGNING_ALGORITHM}."
        )


def load_public_key(kms_client, key_id):
    """Fetch and validate the CMK's public key from KMS."""
    response = kms_client.get_public_key(KeyId=key_id)
    _validate_key_metadata(response, key_id)

    public_key = serialization.load_der_public_key(response["PublicKey"])
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError(
            f"KMS key {key_id!r} is not an RSA key; Cornerstone requires {EXPECTED_KEY_SPEC}."
        )
    if public_key.key_size != 4096:
        raise ValueError(
            f"KMS key {key_id!r} is RSA-{public_key.key_size}; "
            f"Cornerstone requires {EXPECTED_KEY_SPEC}."
        )
    return public_key


class KmsRsaPrivateKey(rsa.RSAPrivateKey):
    """RSA private key interface backed by a KMS asymmetric CMK."""

    def __init__(self, kms_client, key_id, public_key):
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("public_key must be an RSA public key")
        self._kms = kms_client
        self._key_id = key_id
        self._public_key = public_key

    # --- The only method cryptography actually calls when signing X.509. ---
    def sign(self, data, padding, algorithm):
        if not isinstance(padding, padding_module.PKCS1v15):
            raise NotImplementedError(
                "Cornerstone only supports PKCS#1 v1.5 padding (RSA-4096 + SHA-256)."
            )
        signing_algorithm = _KMS_DIGEST_ALGORITHMS.get(type(algorithm))
        if signing_algorithm is None:
            raise NotImplementedError(
                "Cornerstone only supports SHA-256 with this KMS key."
            )

        digest = hashes.Hash(algorithm)
        digest.update(data)
        digest = digest.finalize()

        response = self._kms.sign(
            KeyId=self._key_id,
            Message=digest,
            MessageType="DIGEST",
            SigningAlgorithm=signing_algorithm,
        )
        return response["Signature"]

    # --- RSA public surface (no private material). ---
    @property
    def key_size(self):
        return self._public_key.key_size

    def public_key(self):
        return self._public_key

    # --- Private operations are impossible by design. ---
    def decrypt(self, ciphertext, padding):
        raise NotImplementedError("The KMS CMK does not support decrypt.")

    def private_numbers(self):
        raise NotImplementedError("Private key material never leaves KMS.")

    def private_bytes(self, encoding, format, encryption_algorithm):
        raise NotImplementedError("Private key material never leaves KMS.")

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


def load_kms_signer(kms_client, key_id):
    """Build a KmsRsaPrivateKey for ``key_id`` using its public key."""
    return KmsRsaPrivateKey(kms_client, key_id, load_public_key(kms_client, key_id))
