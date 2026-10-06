"""Verify, freshness-check, authorize, replay-check, then execute."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from policy.policy import AuthorizationDenied, Policy
from server.replay import ReplayBackend
from signing.canonical import CanonicalizationError, signing_bytes
from signing.encoding import b64url_decode
from signing.schemes import get_scheme
from tools.file_access import FileReadDenied
from tools.registry import execute_tool

PAYLOAD_FIELDS = {
    "protocol",
    "audience",
    "algorithm",
    "agent_id",
    "key_id",
    "request_id",
    "nonce",
    "issued_at",
    "expires_at",
    "tool",
    "arguments",
}


class RequestRejected(Exception):
    def __init__(self, code: str, message: str, *, verified: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.verified = verified


@dataclass(frozen=True)
class TrustedKey:
    agent_id: str
    algorithm: str
    public_key: bytes


def parse_utc(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RequestRejected("MALFORMED_REQUEST", f"{field} must end in Z")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(UTC)
    except ValueError as exc:
        raise RequestRejected("MALFORMED_REQUEST", f"{field} is invalid") from exc


class ToolServer:
    def __init__(
        self,
        trusted_keys: dict[str, TrustedKey],
        replay_store: ReplayBackend,
        policy: Policy,
        *,
        audience: str = "pqsa-tool-service",
        max_request_lifetime: timedelta = timedelta(seconds=60),
        allowed_clock_skew: timedelta = timedelta(seconds=5),
    ) -> None:
        self._trusted_keys = dict(trusted_keys)
        self._replay_store = replay_store
        self._policy = policy
        self._audience = audience
        self._max_request_lifetime = max_request_lifetime
        self._allowed_clock_skew = allowed_clock_skew

    def execute(self, envelope: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        payload = self.verify_and_accept(envelope, now=now)
        try:
            result = execute_tool(payload["tool"], payload["arguments"], policy=self._policy)
        except (FileReadDenied, ValueError) as exc:
            raise RequestRejected("EXECUTION_DENIED", "tool execution was denied", verified=True) from exc
        return {
            "status": "completed",
            "request_id": payload["request_id"],
            "algorithm": payload["algorithm"],
            "tool": payload["tool"],
            "result": result,
        }

    def verify_and_accept(
        self,
        envelope: dict[str, Any],
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        payload, signature = self._parse_envelope(envelope)
        trusted_key = self._resolve_key(payload)
        try:
            message = signing_bytes(payload)
        except CanonicalizationError as exc:
            raise RequestRejected("MALFORMED_REQUEST", str(exc)) from exc
        verifier = get_scheme(trusted_key.algorithm).verifier(trusted_key.public_key)
        if not verifier.verify(message, signature):
            raise RequestRejected("INVALID_SIGNATURE", "signature verification failed")

        check_time = (now or datetime.now(UTC)).astimezone(UTC)
        try:
            self._check_freshness(payload, check_time)
            self._policy.authorize(payload["agent_id"], payload["tool"], payload["arguments"])
            claimed = self._replay_store.claim(
                agent_id=payload["agent_id"],
                request_id=payload["request_id"],
                nonce=payload["nonce"],
            )
            if claimed is not True:
                raise RequestRejected("REPLAY_DETECTED", "request ID or nonce was reused")
        except AuthorizationDenied as exc:
            raise RequestRejected("AUTHORIZATION_DENIED", str(exc), verified=True) from exc
        except RequestRejected as exc:
            exc.verified = True
            raise
        except Exception as exc:
            raise RequestRejected("REPLAY_UNAVAILABLE", "replay store unavailable", verified=True) from exc
        return payload

    def _parse_envelope(self, envelope: Any) -> tuple[dict[str, Any], bytes]:
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
            raise RequestRejected("MALFORMED_REQUEST", "envelope fields are invalid")
        payload = envelope["payload"]
        if not isinstance(payload, dict) or set(payload) != PAYLOAD_FIELDS:
            raise RequestRejected("MALFORMED_REQUEST", "payload fields are invalid")
        for field in PAYLOAD_FIELDS - {"arguments"}:
            if not isinstance(payload[field], str) or not payload[field]:
                raise RequestRejected("MALFORMED_REQUEST", f"{field} must be a non-empty string")
        if not isinstance(payload["arguments"], dict):
            raise RequestRejected("MALFORMED_REQUEST", "arguments must be an object")
        try:
            signature = b64url_decode(envelope["signature"])
            nonce = b64url_decode(payload["nonce"])
            uuid.UUID(payload["request_id"])
        except (KeyError, ValueError) as exc:
            raise RequestRejected("MALFORMED_REQUEST", str(exc)) from exc
        if len(nonce) < 16:
            raise RequestRejected("MALFORMED_REQUEST", "nonce must contain at least 128 bits")
        return payload, signature

    def _resolve_key(self, payload: dict[str, Any]) -> TrustedKey:
        if payload["protocol"] != "pqsa-action-v1" or payload["audience"] != self._audience:
            raise RequestRejected("MALFORMED_REQUEST", "protocol or audience is not accepted")
        key = self._trusted_keys.get(payload["key_id"])
        if key is None:
            raise RequestRejected("UNTRUSTED_KEY", "key ID is not trusted")
        if payload["agent_id"] != key.agent_id or payload["algorithm"] != key.algorithm:
            raise RequestRejected("UNTRUSTED_KEY", "identity or algorithm does not match the trusted key")
        return key

    def _check_freshness(self, payload: dict[str, Any], now: datetime) -> None:
        issued_at = parse_utc(payload["issued_at"], "issued_at")
        expires_at = parse_utc(payload["expires_at"], "expires_at")
        if expires_at <= issued_at or expires_at - issued_at > self._max_request_lifetime:
            raise RequestRejected("MALFORMED_REQUEST", "request validity window is invalid")
        if issued_at > now + self._allowed_clock_skew:
            raise RequestRejected("NOT_YET_VALID", "request is not yet valid")
        if expires_at <= now:
            raise RequestRejected("EXPIRED", "request has expired")
