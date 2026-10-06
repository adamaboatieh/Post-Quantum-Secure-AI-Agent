"""SQLite-backed atomic replay claims for a single-host prototype."""

from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol


class ReplayBackend(Protocol):
    """Trusted storage adapter; every accepted action must make an atomic claim.

    Swapping storage does not make replay protection optional. Implementations
    must preserve request-ID and nonce uniqueness and raise on storage failure.
    """

    def claim(self, *, agent_id: str, request_id: str, nonce: str) -> bool: ...


class ReplayStore:
    def __init__(self, database: str | Path = ":memory:") -> None:
        self._connection = sqlite3.connect(str(database), check_same_thread=False)
        self._lock = threading.Lock()
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS accepted_requests (
                agent_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                accepted_at TEXT NOT NULL,
                PRIMARY KEY (agent_id, request_id),
                UNIQUE (agent_id, nonce)
            )
            """
        )
        self._connection.commit()

    def claim(self, *, agent_id: str, request_id: str, nonce: str) -> bool:
        """Atomically claim a request and nonce; return False on any reuse."""

        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    """
                    INSERT INTO accepted_requests
                        (agent_id, request_id, nonce, accepted_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (agent_id, request_id, nonce, datetime.now(UTC).isoformat()),
                )
                self._connection.commit()
            except sqlite3.IntegrityError:
                self._connection.rollback()
                return False
            except sqlite3.Error:
                self._connection.rollback()
                raise
        return True

    def close(self) -> None:
        self._connection.close()
