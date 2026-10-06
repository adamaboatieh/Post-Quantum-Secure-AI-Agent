"""Invariant portable-path and filesystem checks, independent of profiles."""
import os
import re
import stat
from pathlib import Path, PurePosixPath

DEFAULT_EXTENSIONS = frozenset({".txt"})
DEFAULT_MAX_FILE_BYTES = 64 * 1024
DEFAULT_MAX_PATH_LENGTH = 256

_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                     *(f"LPT{i}" for i in range(1, 10))}


class FileReadDenied(ValueError):
    """The requested file cannot be safely read."""


def validate_read_path(value: object, *, extensions=DEFAULT_EXTENSIONS,
                       max_path_length: int = DEFAULT_MAX_PATH_LENGTH) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or len(value) > max_path_length:
        raise FileReadDenied("invalid file path")
    if "\\" in value or ":" in value or "\x00" in value or "%" in value:
        raise FileReadDenied("invalid file path")
    path = PurePosixPath(value)
    if path.is_absolute() or value.startswith("/") or value.endswith("/"):
        raise FileReadDenied("invalid file path")
    parts = tuple(value.split("/"))
    if any(part in {"", ".", ".."} or not _COMPONENT.fullmatch(part)
           or part.endswith(".") or part.upper().split(".")[0] in _WINDOWS_RESERVED
           for part in parts):
        raise FileReadDenied("invalid file path")
    if path.suffix.lower() not in extensions:
        raise FileReadDenied("file extension is not allowed")
    return parts



def _is_link_or_special(path: Path) -> bool:
    metadata = path.lstat()
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _valid_regular(metadata, max_bytes: int) -> bool:
    return (stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
            and bool(metadata.st_ino) and 0 <= metadata.st_size <= max_bytes)


def read_bounded_file(data_root: Path, parts: tuple[str, ...], *, max_bytes: int) -> bytes:
    descriptor = None
    try:
        if _is_link_or_special(data_root):
            raise FileReadDenied("file unavailable")
        root = data_root.resolve(strict=True)
        if not root.is_dir():
            raise FileReadDenied("file unavailable")
        target = root.joinpath(*parts)
        current = root
        for part in parts:
            current = current / part
            if _is_link_or_special(current):
                raise FileReadDenied("file unavailable")
        resolved = target.resolve(strict=True)
        if not resolved.is_relative_to(root):
            raise FileReadDenied("file unavailable")
        before = resolved.stat()
        if not _valid_regular(before, max_bytes):
            raise FileReadDenied("file unavailable")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(resolved, flags)
        handle = os.fdopen(descriptor, "rb")
        descriptor = None
        with handle:
            opened = os.fstat(handle.fileno())
            if (not _valid_regular(opened, max_bytes)
                    or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
                raise FileReadDenied("file unavailable")
            contents = handle.read(max_bytes + 1)
            after = os.fstat(handle.fileno())
            if (len(contents) > max_bytes or not _valid_regular(after, max_bytes)
                    or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
                    or after.st_size != opened.st_size or after.st_mtime_ns != opened.st_mtime_ns):
                raise FileReadDenied("file unavailable")
        return contents
    except (OSError, UnicodeError, ValueError) as exc:
        raise FileReadDenied("file unavailable") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
