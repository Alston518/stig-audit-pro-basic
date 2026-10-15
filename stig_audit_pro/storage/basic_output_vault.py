"""Password-unlocked, authenticated encrypted storage for Basic audit output.

This vault is NOT a general full-disk encryption feature. User-chosen plaintext
exports, editable site profiles, imported files, backups and OS swap remain
outside its protection.
"""
from __future__ import annotations

import base64
import json
import os
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from platformdirs import user_data_path

CHECK = b"stig-audit-pro-basic-vault-v1"
AAD = b"stig-audit-pro-basic-audit-output-v1"
MAGIC = b"STIGBASIC1"
MIN_PASSWORD_LENGTH = 12
# 32 MiB memory, chosen to limit offline password guessing
SCRYPT_N = 2 ** 15


class VaultError(RuntimeError):
    """Vault cannot be unlocked, opened or written safely."""


def default_vault_root() -> Path:
    return user_data_path("STIG Audit Pro Basic", appauthor=False, roaming=False) / "secure-outputs"


def _derive(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=8, p=1).derive(password.encode("utf-8"))


def _atomic_new(path: Path, data: bytes) -> None:
    """Commit a new file without overwriting any existing data."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


class BasicOutputVault:
    """Encrypts each report in memory, writing only AES-256-GCM ciphertext."""

    def __init__(self, root: Path, key: bytes):
        self.root = root.resolve()
        self._key = key

    @classmethod
    def open_or_create(cls, password: str, root: str | Path | None = None) -> "BasicOutputVault":
        path = (Path(root) if root is not None else default_vault_root()).expanduser().resolve()
        path.mkdir(parents=True, exist_ok=True)
        manifest = path / "vault.json"
        if not manifest.exists():
            if len(password) < MIN_PASSWORD_LENGTH:
                raise VaultError(f"New vault password must contain at least {MIN_PASSWORD_LENGTH} characters.")
            # Prevent silently creating a new key for orphaned encrypted reports.
            if any(path.glob("*.sapenc")):
                raise VaultError("Encrypted reports exist without vault metadata. Restore vault.json from backup.")
            salt = os.urandom(16)
            key = _derive(password, salt)
            nonce = os.urandom(12)
            metadata = {"version": 1, "salt": base64.b64encode(salt).decode(),
                        "nonce": base64.b64encode(nonce).decode(),
                        "check": base64.b64encode(AESGCM(key).encrypt(nonce, CHECK, AAD)).decode()}
            try:
                _atomic_new(manifest, (json.dumps(metadata, indent=2) + "\n").encode("utf-8"))
            except FileExistsError:
                # Another process initialized the same vault first. Never silently overwrite it.
                pass
        try:
            obj = json.loads(manifest.read_text(encoding="utf-8"))
            if obj["version"] != 1:
                raise VaultError("Unsupported vault version.")
            salt = base64.b64decode(obj["salt"], validate=True)
            nonce = base64.b64decode(obj["nonce"], validate=True)
            ciphertext = base64.b64decode(obj["check"], validate=True)
            if len(salt) != 16 or len(nonce) != 12:
                raise VaultError("Invalid vault metadata.")
            key = _derive(password, salt)
            verified = AESGCM(key).decrypt(nonce, ciphertext, AAD)
            if verified != CHECK:
                raise VaultError("Vault integrity check failed.")
        except (InvalidTag, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise VaultError("Incorrect password or damaged vault metadata.") from exc
        return cls(path, key)

    def save(self, filename: str, contents: bytes) -> Path:
        """Encrypt bytes before writing, with the export name concealed in ciphertext."""
        if not filename or Path(filename).name != filename or filename in {".", ".."}:
            raise ValueError("Report name must be a single safe filename.")
        if not isinstance(contents, bytes):
            raise TypeError("Report contents must be bytes.")
        envelope = json.dumps({"filename": filename,
                               "contents": base64.b64encode(contents).decode()}, separators=(",", ":")).encode()
        nonce = os.urandom(12)
        encrypted = MAGIC + nonce + AESGCM(self._key).encrypt(nonce, envelope, AAD)
        while True:
            destination = self.root / (uuid.uuid4().hex + ".sapenc")
            try:
                _atomic_new(destination, encrypted)
                return destination
            except FileExistsError:
                continue

    def read(self, selected: str | Path) -> tuple[str, bytes]:
        path = Path(selected).resolve()
        if path.parent != self.root or path.suffix != ".sapenc":
            raise VaultError("Only encrypted files from the selected vault may be decrypted.")
        try:
            encrypted = path.read_bytes()
        except OSError as exc:
            raise VaultError("Encrypted report not found or unreadable.") from exc
        if not encrypted.startswith(MAGIC) or len(encrypted) < len(MAGIC) + 28:
            raise VaultError("Unsupported or damaged encrypted report.")
        nonce = encrypted[len(MAGIC):len(MAGIC) + 12]
        try:
            payload = AESGCM(self._key).decrypt(nonce, encrypted[len(MAGIC) + 12:], AAD)
            obj = json.loads(payload)
            filename = obj["filename"]
            if not isinstance(filename, str) or not filename or Path(filename).name != filename or filename in {".", ".."}:
                raise VaultError("Unsafe filename in encrypted report.")
            contents = base64.b64decode(obj["contents"], validate=True)
            return filename, contents
        except (InvalidTag, ValueError, KeyError, TypeError) as exc:
            raise VaultError("Encrypted report integrity check failed.") from exc

__all__ = ["BasicOutputVault", "VaultError", "default_vault_root"]
