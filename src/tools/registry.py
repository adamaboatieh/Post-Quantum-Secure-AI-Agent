"""Fixed assignment tool registry; requests cannot load arbitrary code."""

from __future__ import annotations

from policy.policy import Policy
from tools.read_file import read_file


def execute_tool(tool: str, arguments: dict, *, policy: Policy) -> dict:
    if tool != "read_file":
        raise ValueError("unknown tool")
    return read_file(
        arguments,
        data_root=policy.data_root,
        max_bytes=policy.max_file_bytes,
    )
