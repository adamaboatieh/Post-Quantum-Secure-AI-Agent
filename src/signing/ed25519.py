"""Ed25519 signing and verification adapters.

The private-key object is held only by ``Ed25519Signer``. The receiving server
uses ``Ed25519Verifier`` constructed from public bytes.
"""

from __future__ import annotations

from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class Ed25519Signer:
    algorithm = "Ed25519"

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    @classmethod
    def generate(cls) -> "Ed25519Signer":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem_file(cls, path: Path) -> "Ed25519Signer":
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("Expected an Ed25519 private key")
        return cls(key)

    @classmethod
    def from_private_bytes(cls, private_key: bytes) -> "Ed25519Signer":
        return cls(Ed25519PrivateKey.from_private_bytes(private_key))

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    def public_key_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def private_key_bytes(self) -> bytes:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

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


class Ed25519Verifier:
    algorithm = "Ed25519"

    def __init__(self, public_key: Ed25519PublicKey) -> None:
        self._public_key = public_key

    @classmethod
    def from_public_bytes(cls, public_key: bytes) -> "Ed25519Verifier":
        return cls(Ed25519PublicKey.from_public_bytes(public_key))

    @classmethod
    def from_pem_file(cls, path: Path) -> "Ed25519Verifier":
        key = serialization.load_pem_public_key(path.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("Expected an Ed25519 public key")
        return cls(key)

    def public_key_bytes(self) -> bytes:
        return self._public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self._public_key.verify(signature, message)
        except InvalidSignature:
            return False
        return True


class Ed25519Scheme:
    algorithm = "Ed25519"

    def generate(self) -> Ed25519Signer:
        return Ed25519Signer.generate()

    def signer_from_private_bytes(self, private_key: bytes) -> Ed25519Signer:
        return Ed25519Signer.from_private_bytes(private_key)

    def verifier(self, public_key: bytes) -> Ed25519Verifier:
        return Ed25519Verifier.from_public_bytes(public_key)
