# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ricardo Arguello
"""An in-memory KMS double.

It mimics the two boto3 calls Cornerstone makes (``get_public_key`` and
``sign``) using a real local RSA key, so the whole flow can be exercised
without AWS. ``MessageType="DIGEST"`` means KMS signs the supplied SHA-256
digest directly (no re-hashing), hence ``Prehashed``.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

RSA_KEY_SIZE = 4096
SIGNING_ALGORITHM = "RSASSA_PKCS1_V1_5_SHA_256"
KEY_SPECS = {2048: "RSA_2048", 3072: "RSA_3072", 4096: "RSA_4096"}


class LocalKmsDouble:
    def __init__(
        self,
        key_size=RSA_KEY_SIZE,
        key_usage="SIGN_VERIFY",
        key_spec=None,
        signing_algorithms=None,
    ):
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        self._key_usage = key_usage
        self._key_spec = key_spec or KEY_SPECS[key_size]
        self._signing_algorithms = (
            signing_algorithms if signing_algorithms is not None else [SIGNING_ALGORITHM]
        )
        self.calls = []

    @property
    def private_key(self):
        return self._key

    def get_public_key(self, KeyId):
        der = self._key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        return {
            "KeyId": KeyId,
            "PublicKey": der,
            "KeySpec": self._key_spec,
            "KeyUsage": self._key_usage,
            "SigningAlgorithms": self._signing_algorithms,
        }

    def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
        if MessageType != "DIGEST":
            raise AssertionError(f"expected MessageType=DIGEST, got {MessageType!r}")
        if SigningAlgorithm != SIGNING_ALGORITHM:
            raise AssertionError(f"unexpected SigningAlgorithm {SigningAlgorithm!r}")
        if len(Message) != hashes.SHA256().digest_size:
            raise AssertionError("digest length does not match SHA-256")
        self.calls.append(
            {"KeyId": KeyId, "MessageType": MessageType, "SigningAlgorithm": SigningAlgorithm}
        )
        signature = self._key.sign(
            Message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
        )
        return {"KeyId": KeyId, "Signature": signature, "SigningAlgorithm": SigningAlgorithm}
