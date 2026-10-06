"""Read one bounded UTF-8 text file beneath the policy-owned data root."""

from __future__ import annotations

from pathlib import Path

from tools.file_access import FileReadDenied, read_bounded_file, validate_read_path


def read_file(arguments: dict, *, data_root: Path, max_bytes: int) -> dict[str, str]:
    if not isinstance(arguments, dict) or set(arguments) != {"path"}:
        raise FileReadDenied("file unavailable")
    parts = validate_read_path(arguments["path"])
    contents = read_bounded_file(data_root, parts, max_bytes=max_bytes)
    try:
        text = contents.decode("utf-8")
    except UnicodeError as exc:
        raise FileReadDenied("file unavailable") from exc
    return {"path": arguments["path"], "content": text}
