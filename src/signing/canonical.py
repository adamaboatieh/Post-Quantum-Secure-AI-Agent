"""Deterministic encoding for the signed-action protocol.

The MVP schema deliberately excludes floating-point numbers. That removes
cross-language number-formatting ambiguity while we validate the protocol.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

DOMAIN_SEPARATOR = b"PQSA-ACTION-V1\x00"


class CanonicalizationError(ValueError):
    """Raised when a value is outside the MVP canonical JSON profile."""


def _validate(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        raise CanonicalizationError(f"floating-point values are forbidden at {path}")
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"object key at {path} is not a string")
            _validate(child, f"{path}.{key}")
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _validate(child, f"{path}[{index}]")
        return
    raise CanonicalizationError(f"unsupported value type at {path}: {type(value).__name__}")


def canonical_json(value: Mapping[str, Any]) -> bytes:
    """Return deterministic UTF-8 JSON bytes for the restricted MVP profile."""

    try:
        _validate(value)
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return encoded.encode("utf-8")
    except (UnicodeError, RecursionError) as exc:
        raise CanonicalizationError("value cannot be encoded as canonical JSON") from exc


def signing_bytes(payload: Mapping[str, Any]) -> bytes:
    """Bind a canonical payload to this protocol version."""

    return DOMAIN_SEPARATOR + canonical_json(payload)
