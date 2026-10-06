"""Trusted authorization distinct from signature authentication."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.file_access import DEFAULT_MAX_FILE_BYTES, validate_read_path


class AuthorizationDenied(ValueError):
    """The requested action falls outside the configured policy."""


@dataclass(frozen=True)
class Policy:
    data_root: Path
    allowed_agents: frozenset[str] = frozenset({"agent-01"})
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES

    def authorize(self, agent_id: str, tool: str, arguments: dict[str, Any]) -> None:
        if agent_id not in self.allowed_agents:
            raise AuthorizationDenied("agent is not authorized")
        if tool != "read_file":
            raise AuthorizationDenied("tool is not authorized")
        if not isinstance(arguments, dict) or set(arguments) != {"path"}:
            raise AuthorizationDenied("read_file requires exactly one path")
        try:
            validate_read_path(arguments["path"])
        except ValueError as exc:
            raise AuthorizationDenied("path is outside the read_file policy") from exc
