"""Untrusted model backends.

The offline backend makes the assignment reproducible. The HTTP backend can be
pointed at a compatible chat-completions service for a live LLM demonstration.
Neither backend receives policy objects, private keys, or signing services.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Protocol
from urllib.request import Request, urlopen


SYSTEM_PROMPT = """Return only one JSON object with exactly these fields:
{"tool":"read_file","arguments":{"path":"relative-name.txt"}}
Use read_file only when asked to read a text file. If the user asks for a
different capability, preserve that requested tool name so trusted policy can
deny it. Never claim that a request was authorized or signed."""


class ProposalBackend(Protocol):
    def propose(self, task: str) -> str | dict: ...


class DeterministicDemoModel:
    """Offline stand-in used for tests and the credential-free demo."""

    _filename = re.compile(r"(?P<path>(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\.txt)", re.I)

    def propose(self, task: str) -> dict:
        lowered = task.lower()
        if "delete" in lowered:
            return {"tool": "delete_database", "arguments": {"database": "demo"}}
        match = self._filename.search(task)
        if match:
            return {"tool": "read_file", "arguments": {"path": match.group("path")}}
        if "/etc/passwd" in lowered or "environment variable" in lowered:
            return {"tool": "read_file", "arguments": {"path": "/etc/passwd"}}
        return {"tool": "unsupported", "arguments": {"task": task[:200]}}


@dataclass(frozen=True)
class OpenAICompatibleModel:
    """Minimal live-model adapter; the response remains untrusted JSON text."""

    endpoint: str
    model: str
    api_key: str
    timeout_seconds: float = 30.0

    def propose(self, task: str) -> str:
        document = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": task},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0,
        }
        request = Request(
            self.endpoint,
            data=json.dumps(document).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urlopen(request, timeout=self.timeout_seconds) as response:
            body = json.loads(response.read().decode("utf-8"))
        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError("model response did not contain JSON proposal text") from exc
        if not isinstance(content, str):
            raise ValueError("model proposal content must be text")
        return content
