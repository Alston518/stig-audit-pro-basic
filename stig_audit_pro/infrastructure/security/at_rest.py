"""Passphrase-unlocked, authenticated encryption for app-managed files."""

from __future__ import annotations

import base64
import json
import os
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


MAGIC = b"SAPENC1\x00"
_CHECK = b"STIG Audit Pro Basic vault v1"


class VaultUnlockError(ValueError):
    """A passphrase, ciphertext, or file association is invalid."""


class AtRestVault:
    """Derive separate database and file keys from a user passphrase.

    The salt and verifier are public metadata. The derived keys exist only in
    process memory, and are never written to the vault metadata file.
    """

    def __init__(self, metadata_path: Path, master_key: bytes) -> None:
        self.metadata_path = metadata_path
        self._master_key = master_key
        self.database_key = self._subkey(b"database")
        self._file_key = self._subkey(b"files")

    @classmethod
    def open(
        cls, metadata_path: str | Path, passphrase: str, *, create: bool = False
    ) -> "AtRestVault":
        path = Path(metadata_path).expanduser().resolve()
        if not isinstance(passphrase, str) or not passphrase:
            raise VaultUnlockError("A passphrase is required to unlock audit data")
        if path.exists():
            try:
                metadata = json.loads(path.read_text(encoding="utf-8"))
                if metadata["version"] != 1:
                    raise ValueError("Unsupported vault version")
                salt = base64.b64decode(metadata["salt"], validate=True)
                verifier = base64.b64decode(metadata["verifier"], validate=True)
                if len(salt) != 16:
                    raise ValueError("Invalid vault salt")
            except (OSError, KeyError, TypeError, ValueError) as exc:
                raise VaultUnlockError("Vault metadata is invalid") from exc
            vault = cls(path, cls._derive(passphrase, salt))
            if vault.decrypt(verifier, "vault-check") != _CHECK:
                raise VaultUnlockError("Vault verification failed")
            return vault
        if not create:
            raise VaultUnlockError("Vault metadata is missing")
        salt = os.urandom(16)
        vault = cls(path, cls._derive(passphrase, salt))
        metadata = {
            "version": 1,
            "kdf": "scrypt-N32768-r8-p1",
            "salt": base64.b64encode(salt).decode("ascii"),
            "verifier": base64.b64encode(vault.encrypt(_CHECK, "vault-check")).decode("ascii"),
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with path.open("x", encoding="utf-8") as handle:
                json.dump(metadata, handle, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            return cls.open(path, passphrase)
        return vault

    @staticmethod
    def _derive(passphrase: str, salt: bytes) -> bytes:
        return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(
            passphrase.encode("utf-8")
        )

    def _subkey(self, purpose: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"STIG Audit Pro Basic/" + purpose
        ).derive(self._master_key)

    def encrypt(self, plaintext: bytes, association: str) -> bytes:
        nonce = os.urandom(12)
        return MAGIC + nonce + AESGCM(self._file_key).encrypt(
            nonce, plaintext, association.encode("utf-8")
        )

    def decrypt(self, ciphertext: bytes, association: str) -> bytes:
        if not ciphertext.startswith(MAGIC) or len(ciphertext) < len(MAGIC) + 12 + 16:
            raise VaultUnlockError("File is not encrypted audit data")
        nonce = ciphertext[len(MAGIC):len(MAGIC) + 12]
        try:
            return AESGCM(self._file_key).decrypt(
                nonce, ciphertext[len(MAGIC) + 12:], association.encode("utf-8")
            )
        except InvalidTag as exc:
            raise VaultUnlockError("Encrypted audit data failed authentication") from exc

    def read_file(self, path: Path, association: str) -> bytes:
        return self.decrypt(path.read_bytes(), association)

    def write_file(self, path: Path, plaintext: bytes, association: str, *, replace: bool) -> None:
        """Publish ciphertext atomically; never create a plaintext staging file."""

        if not replace and path.exists():
            raise FileExistsError(path)
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("xb") as handle:
                handle.write(self.encrypt(plaintext, association))
                handle.flush()
                os.fsync(handle.fileno())
            if replace:
                os.replace(temporary, path)
            else:
                # A hard link publishes the already-synced ciphertext without
                # replacing a file another process created in the meantime.
                # The staging file shares the directory and filesystem.
                os.link(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def encrypt_tree(self, root: Path) -> int:
        """Convert legacy run files in place, safely resumable after interruption."""

        root = root.resolve()
        if not root.exists():
            return 0
        count = 0
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                raise VaultUnlockError(f"Symlink in audit data: {path}")
            if not path.is_file():
                continue
            association = path.relative_to(root).as_posix()
            data = path.read_bytes()
            if data.startswith(MAGIC):
                self.decrypt(data, association)
                continue
            self.write_file(path, data, association, replace=True)
            count += 1
        return count
