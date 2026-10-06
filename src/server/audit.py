"""Minimal durable action records and read-only historical signature checks.

The signed envelope authenticates the requested action. The local SQLite row,
identity binding, timestamps, and execution outcome are not themselves signed.
An independently retained public-key fingerprint can pin the verifying key.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from signing.canonical import CanonicalizationError, canonical_json, signing_bytes
from signing.encoding import b64url_decode, b64url_encode
from signing.schemes import get_scheme


class AuditUnavailable(Exception):
    """A durable audit operation failed; its underlying details stay local."""


def public_key_sha256(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


class AuditStore:
    """Commit the accepted request before invocation, then record its outcome."""

    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)
        self._lock = threading.Lock()
        self._connection: sqlite3.Connection | None = None
        try:
            self.database.parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(str(self.database), check_same_thread=False)
            # Explicit FULL synchronization is sufficient for this local demo.
            self._connection.execute("PRAGMA synchronous = FULL")
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS action_audit (
                    record_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    accepted_at TEXT NOT NULL,
                    execution_state TEXT NOT NULL
                        CHECK (execution_state IN ('prepared', 'completed', 'denied', 'uncertain')),
                    finalized_at TEXT,
                    outcome_code TEXT,
                    UNIQUE (agent_id, request_id)
                )
                """
            )
            self._connection.commit()
        except (OSError, sqlite3.Error):
            self.close()
            raise AuditUnavailable("audit database is unavailable") from None

    def prepare(
        self,
        envelope: dict[str, Any],
        *,
        agent_id: str,
        algorithm: str,
        public_key: bytes,
    ) -> str:
        """Retain public evidence only; callers must first verify and authorize."""
        record_id = str(uuid.uuid4())
        payload = envelope["payload"]
        with self._lock:
            try:
                if self._connection is None:
                    raise AuditUnavailable("audit database is closed")
                with self._connection:
                    self._connection.execute(
                        """
                        INSERT INTO action_audit
                            (record_id, request_id, agent_id, key_id, algorithm,
                             envelope_json, public_key, accepted_at, execution_state)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'prepared')
                        """,
                        (
                            record_id,
                            payload["request_id"],
                            agent_id,
                            payload["key_id"],
                            algorithm,
                            canonical_json(envelope).decode("utf-8"),
                            b64url_encode(public_key),
                            _utc_now(),
                        ),
                    )
            except (sqlite3.Error, CanonicalizationError):
                raise AuditUnavailable("audit request write failed") from None
        return record_id

    def finalize(self, record_id: str, state: str, *, outcome_code: str | None = None) -> None:
        if state not in {"completed", "denied", "uncertain"}:
            raise ValueError("invalid audit execution state")
        with self._lock:
            try:
                if self._connection is None:
                    raise AuditUnavailable("audit database is closed")
                with self._connection:
                    changed = self._connection.execute(
                        """
                        UPDATE action_audit
                        SET execution_state = ?, finalized_at = ?, outcome_code = ?
                        WHERE record_id = ? AND execution_state = 'prepared'
                        """,
                        (state, _utc_now(), outcome_code, record_id),
                    ).rowcount
                    if changed != 1:
                        raise AuditUnavailable("audit prepared record is unavailable")
            except sqlite3.Error:
                raise AuditUnavailable("audit outcome write failed") from None

    def close(self) -> None:
        with self._lock:
            connection, self._connection = self._connection, None
            if connection is not None:
                connection.close()

    def __enter__(self) -> "AuditStore":
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()


def _check_pin(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized):
        raise ValueError("public-key SHA256 must be 64 hexadecimal characters")
    return normalized


def _verify_record(row: sqlite3.Row, expected_pin: str | None) -> dict[str, Any]:
    """Verify under a retained key without asserting that the log is authentic."""
    fingerprint = None
    signature_valid = False
    binding_consistent = False
    try:
        public_key = b64url_decode(row["public_key"])
        fingerprint = public_key_sha256(public_key)
        envelope = json.loads(row["envelope_json"])
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
            raise ValueError("invalid retained envelope")
        payload = envelope["payload"]
        if not isinstance(payload, dict):
            raise ValueError("invalid retained payload")
        signature_valid = get_scheme(row["algorithm"]).verifier(public_key).verify(
            signing_bytes(payload), b64url_decode(envelope["signature"])
        )
        binding_consistent = all(
            payload.get(field) == row[field]
            for field in ("request_id", "agent_id", "key_id", "algorithm")
        )
    except (ValueError, TypeError, KeyError, RecursionError, CanonicalizationError):
        pass
    pin_matches = None if expected_pin is None else fingerprint == expected_pin
    return {
        "record_id": row["record_id"],
        "request_id": row["request_id"],
        "algorithm": row["algorithm"],
        "agent_id": row["agent_id"],
        "key_id": row["key_id"],
        "accepted_at": row["accepted_at"],
        "finalized_at": row["finalized_at"],
        "recorded_execution_state": row["execution_state"],
        "recorded_outcome_code": row["outcome_code"],
        "signature_valid": signature_valid,
        "binding_consistent": binding_consistent,
        "public_key_sha256": fingerprint,
        "key_pinned": pin_matches is True,
        "pin_matches": pin_matches,
        "identity_trust": "externally_pinned_public_key" if pin_matches is True else "recorded_key_only",
        "log_integrity": "not_authenticated",
        "outcome_integrity": "not_authenticated",
        "historical_only": True,
        "verification_passed": signature_valid and binding_consistent and pin_matches is not False,
    }


def verify_history(
    database: str | Path,
    *,
    request_id: str | None = None,
    expected_public_key_sha256: str | None = None,
) -> list[dict[str, Any]]:
    """Open an existing database read-only; never execute or freshness-check."""
    expected_pin = _check_pin(expected_public_key_sha256)
    connection = None
    try:
        connection = sqlite3.connect(Path(database).resolve().as_uri() + "?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        query = (
            "SELECT record_id, request_id, agent_id, key_id, algorithm, envelope_json, "
            "public_key, accepted_at, execution_state, finalized_at, outcome_code FROM action_audit"
        )
        parameters: tuple[str, ...] = ()
        if request_id is not None:
            query += " WHERE request_id = ?"
            parameters = (request_id,)
        query += " ORDER BY accepted_at, record_id"
        return [_verify_record(row, expected_pin) for row in connection.execute(query, parameters)]
    except (sqlite3.Error, OSError):
        raise AuditUnavailable("historical audit database cannot be read") from None
    finally:
        if connection is not None:
            connection.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=Path("runtime/audit.sqlite3"))
    parser.add_argument("--request-id")
    parser.add_argument("--public-key-sha256", help="independently retained public-key fingerprint")
    args = parser.parse_args()
    try:
        records = verify_history(
            args.database,
            request_id=args.request_id,
            expected_public_key_sha256=args.public_key_sha256,
        )
    except (AuditUnavailable, ValueError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}))
        raise SystemExit(1) from None
    passed = bool(records) and all(record["verification_passed"] for record in records)
    print(json.dumps({"status": "verified" if passed else "failed", "records": records}, indent=2))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
