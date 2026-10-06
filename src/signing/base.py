"""Small structural interfaces for algorithm-independent action signing."""

from __future__ import annotations

from typing import Protocol


class Signer(Protocol):
    algorithm: str

    def sign(self, message: bytes) -> bytes: ...

    def public_key_bytes(self) -> bytes: ...

    def private_key_bytes(self) -> bytes: ...


class Verifier(Protocol):
    algorithm: str

    def verify(self, message: bytes, signature: bytes) -> bool: ...


class SignatureScheme(Protocol):
    algorithm: str

    def generate(self) -> Signer: ...

    def signer_from_private_bytes(self, private_key: bytes) -> Signer: ...

    def verifier(self, public_key: bytes) -> Verifier: ...
