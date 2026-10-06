"""Generate disposable demo keys without overwriting existing material."""

from __future__ import annotations

from pathlib import Path

from signing.schemes import get_scheme


def generate_key_pair(algorithm: str, directory: Path) -> tuple[Path, Path] | None:
    scheme = get_scheme(algorithm)
    slug = scheme.algorithm.lower().replace("-", "_")
    private_path = directory / f"{slug}_private.pem"
    public_path = directory / f"{slug}_public.pem"
    if private_path.exists() or public_path.exists():
        return None
    signer = scheme.generate()
    directory.mkdir(parents=True, exist_ok=True)
    with private_path.open("xb") as stream:
        stream.write(signer.private_key_pem())
    with public_path.open("xb") as stream:
        stream.write(signer.public_key_pem())
    return private_path, public_path
