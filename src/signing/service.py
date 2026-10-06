"""Highly trusted request construction and private-key boundary."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from signing.base import Signer
from signing.canonical import signing_bytes
from signing.encoding import b64url_encode


def format_utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


class TrustedSigningService:
    """Owns the private signer; model adapters receive no reference to it."""

    def __init__(
        self,
        signer: Signer,
        *,
        agent_id: str = "agent-01",
        key_id: str | None = None,
        audience: str = "pqsa-tool-service",
    ) -> None:
        self._signer = signer
        self.agent_id = agent_id
        self.key_id = key_id or f"{agent_id}-{signer.algorithm.lower()}-v1"
        self.audience = audience

    @property
    def algorithm(self) -> str:
        return self._signer.algorithm

    def create_envelope(
        self,
        tool: str,
        arguments: dict[str, Any],
        *,
        now: datetime | None = None,
        ttl: timedelta = timedelta(seconds=60),
        request_id: str | None = None,
        nonce: str | None = None,
    ) -> dict[str, Any]:
        issued_at = now or datetime.now(UTC)
        if issued_at.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        if ttl <= timedelta(0):
            raise ValueError("ttl must be positive")
        payload: dict[str, Any] = {
            "protocol": "pqsa-action-v1",
            "audience": self.audience,
            "algorithm": self.algorithm,
            "agent_id": self.agent_id,
            "key_id": self.key_id,
            "request_id": request_id or str(uuid.uuid4()),
            "nonce": nonce or b64url_encode(secrets.token_bytes(16)),
            "issued_at": format_utc(issued_at),
            "expires_at": format_utc(issued_at + ttl),
            "tool": tool,
            "arguments": arguments,
        }
        signature = self._signer.sign(signing_bytes(payload))
        return {"payload": payload, "signature": b64url_encode(signature)}
