"""Configuration-driven signature algorithm registry."""

from __future__ import annotations

import os

from signing.base import SignatureScheme
from signing.ed25519 import Ed25519Scheme
from signing.ml_dsa import MLDSA44Scheme

_SCHEMES: dict[str, SignatureScheme] = {
    "ed25519": Ed25519Scheme(),
    "ml-dsa": MLDSA44Scheme(),
    "ml-dsa-44": MLDSA44Scheme(),
}


def get_scheme(name: str | None = None) -> SignatureScheme:
    selected = (name or os.getenv("SIGNATURE_SCHEME", "ed25519")).strip().lower()
    try:
        return _SCHEMES[selected]
    except KeyError as exc:
        raise ValueError(f"unsupported signature scheme: {selected}") from exc


def available_algorithms() -> tuple[str, ...]:
    return ("Ed25519", "ML-DSA-44")
