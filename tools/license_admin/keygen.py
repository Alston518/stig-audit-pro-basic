"""Secure Ed25519 key-pair generation for the software publisher."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from stig_audit_pro.licensing.manager import validate_key_id
from tools.license_admin.crypto import (
    private_key_pem,
    public_key_fingerprint,
    public_key_pem,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PUBLIC_KEY_REPOSITORY_DIR = (
    REPOSITORY_ROOT
    / "stig_audit_pro"
    / "resources"
    / "licensing"
    / "public_keys"
)


@dataclass(frozen=True)
class GeneratedKeyPair:
    key_id: str
    private_key_path: Path
    public_key_path: Path
    fingerprint: str
    repository_public_key_path: Path


def generate_key_pair(
    *,
    key_id: str,
    private_key_output: str | Path,
    public_key_output: str | Path,
    force: bool = False,
) -> GeneratedKeyPair:
    validate_key_id(key_id)
    private_path = Path(private_key_output).expanduser().resolve()
    public_path = Path(public_key_output).expanduser().resolve()
    repository_path = PUBLIC_KEY_REPOSITORY_DIR / f"{key_id}.pem"
    if _is_within(private_path, REPOSITORY_ROOT):
        raise ValueError(
            "Refusing to create a private signing key inside the application repository"
        )
    if private_path.exists() and not force:
        raise FileExistsError(
            f"Private key already exists: {private_path}. Use --force to overwrite it."
        )
    if public_path.exists() and not force:
        raise FileExistsError(
            f"Public key already exists: {public_path}. Use --force to overwrite it."
        )
    if private_path == public_path:
        raise ValueError("Private and public key output paths must be different")

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_TRUNC if force else os.O_EXCL
    descriptor = os.open(private_path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(private_key_pem(key))
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    os.chmod(private_path, stat.S_IRUSR | stat.S_IWUSR)
    public_path.write_bytes(public_key_pem(key.public_key()))
    return GeneratedKeyPair(
        key_id=key_id,
        private_key_path=private_path,
        public_key_path=public_path,
        fingerprint=public_key_fingerprint(key.public_key()),
        repository_public_key_path=repository_path,
    )


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent.resolve())
        return True
    except ValueError:
        return False
