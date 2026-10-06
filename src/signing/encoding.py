"""Strict base64url helpers used by the transport envelope."""

from __future__ import annotations

import base64
import binascii


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("base64url value must be a non-empty string")
    if "=" in value:
        raise ValueError("base64url padding is not permitted")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("base64url value must contain ASCII characters") from exc
    padding = b"=" * (-len(raw) % 4)
    try:
        decoded = base64.b64decode(raw + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64url value") from exc
    if b64url_encode(decoded) != value:
        raise ValueError("base64url value is not canonical")
    return decoded
