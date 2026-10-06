"""ML-DSA-44 adapters backed by ``cryptography`` and OpenSSL.

The implementation uses the standardized FIPS 204 primitive exposed by a
maintained cryptographic library. No ML-DSA arithmetic is implemented here.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA44PrivateKey,
    MLDSA44PublicKey,
)


class MLDSA44Signer:
    algorithm = "ML-DSA-44"

    def __init__(self, private_key: MLDSA44PrivateKey) -> None:
        self._private_key = private_key

    @classmethod
    def generate(cls) -> "MLDSA44Signer":
        return cls(MLDSA44PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, seed: bytes) -> "MLDSA44Signer":
        return cls(MLDSA44PrivateKey.from_seed_bytes(seed))

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    def public_key_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes_raw()

    def private_key_bytes(self) -> bytes:
        """Return the serialized 32-byte seed, not the expanded internal key."""

        return self._private_key.private_bytes_raw()

    def private_key_pem(self) -> bytes:
        return self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def public_key_pem(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )


class MLDSA44Verifier:
    algorithm = "ML-DSA-44"

    def __init__(self, public_key: MLDSA44PublicKey) -> None:
        self._public_key = public_key

    @classmethod
    def from_public_bytes(cls, public_key: bytes) -> "MLDSA44Verifier":
        return cls(MLDSA44PublicKey.from_public_bytes(public_key))

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self._public_key.verify(signature, message)
        except (InvalidSignature, ValueError):
            return False
        return True


class MLDSA44Scheme:
    algorithm = "ML-DSA-44"

    def generate(self) -> MLDSA44Signer:
        return MLDSA44Signer.generate()

    def signer_from_private_bytes(self, private_key: bytes) -> MLDSA44Signer:
        return MLDSA44Signer.from_private_bytes(private_key)

    def verifier(self, public_key: bytes) -> MLDSA44Verifier:
        return MLDSA44Verifier.from_public_bytes(public_key)
