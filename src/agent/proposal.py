"""Strict schema for untrusted model-produced tool proposals."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


class ProposalError(ValueError):
    """Model output is not the exact proposal schema."""


@dataclass(frozen=True)
class ToolProposal:
    tool: str
    arguments: dict[str, Any]

    @classmethod
    def parse(cls, value: str | dict[str, Any]) -> "ToolProposal":
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except (json.JSONDecodeError, RecursionError) as exc:
                raise ProposalError("model output is not valid JSON") from exc
        if not isinstance(value, dict) or set(value) != {"tool", "arguments"}:
            raise ProposalError("proposal must contain exactly tool and arguments")
        tool = value["tool"]
        arguments = value["arguments"]
        if not isinstance(tool, str) or not tool or len(tool) > 64:
            raise ProposalError("tool must be a short non-empty string")
        if not isinstance(arguments, dict):
            raise ProposalError("arguments must be an object")
        return cls(tool=tool, arguments=arguments)

    def as_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "arguments": self.arguments}
