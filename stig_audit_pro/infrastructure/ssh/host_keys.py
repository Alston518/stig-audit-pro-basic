"""Explicit SSH host-key enrollment and fail-closed trust storage."""

from __future__ import annotations

import base64
import json
import os
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from platformdirs import user_data_path


def default_trust_store_path() -> Path:
    return user_data_path("STIG Audit Pro Basic", appauthor=False, roaming=False) / "ssh-known-hosts"


class HostKeyTrustStore:
    """OpenSSH known-hosts file with an operator enrollment audit record."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = (Path(path) if path else default_trust_store_path()).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        self.metadata_path = self.path.with_suffix(self.path.suffix + ".json")

    def enroll(
        self,
        host: str,
        port: int,
        key_type: str,
        key_base64: str,
        *,
        verification_note: str,
        operator: str,
    ) -> str:
        if not verification_note.strip():
            raise ValueError("Independent host-key verification note is required")
        if not operator.strip():
            raise ValueError("Operator identity is required")
        key_base64 = key_base64.strip()
        try:
            raw_key = base64.b64decode(key_base64, validate=True)
        except Exception as exc:
            raise ValueError("Host key is not valid base64") from exc
        if not raw_key:
            raise ValueError("Host key is empty")
        fingerprint = self.fingerprint(key_type, raw_key)
        marker = f"[{host}]:{int(port)}" if int(port) != 22 else host
        line = f"{marker} {key_type} {key_base64}\n"
        existing = self.path.read_text(encoding="utf-8").splitlines()
        filtered = [item for item in existing if not item.startswith(marker + " ")]
        self._atomic_write("\n".join([*filtered, line.rstrip()]) + "\n")
        entries = self._load_metadata()
        entries.append({
            "host": host,
            "port": int(port),
            "algorithm": key_type,
            "fingerprint": fingerprint,
            "enrolled_at": datetime.now(timezone.utc).isoformat(),
            "operator": operator,
            "verification_note": verification_note.strip(),
            "event_id": str(uuid.uuid4()),
        })
        self._atomic_write_metadata(entries)
        return fingerprint

    @staticmethod
    def fingerprint(key_type: str, key_bytes: bytes) -> str:
        import hashlib

        digest = hashlib.sha256(key_bytes).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")

    @staticmethod
    def discover(host: str, port: int = 22, timeout: float = 10.0) -> tuple[str, str, str]:
        """Read the server key before authentication; credentials are not sent."""

        import paramiko

        sock = socket.create_connection((host, int(port)), timeout=timeout)
        transport = paramiko.Transport(sock)
        try:
            transport.start_client(timeout=timeout)
            key = transport.get_remote_server_key()
            key_type = key.get_name()
            key_base64 = key.get_base64()
            return key_type, key_base64, HostKeyTrustStore.fingerprint(key_type, key.asbytes())
        finally:
            transport.close()
            sock.close()

    def _load_metadata(self) -> list[dict[str, Any]]:
        try:
            value = json.loads(self.metadata_path.read_text(encoding="utf-8"))
            return value if isinstance(value, list) else []
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _atomic_write_metadata(self, value: list[dict[str, Any]]) -> None:
        self.metadata_path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(self.metadata_path, 0o600)
        except OSError:
            pass

    def _atomic_write(self, value: str) -> None:
        temporary = self.path.with_name(f".{self.path.name}.{uuid.uuid4().hex}.tmp")
        temporary.write_text(value, encoding="utf-8")
        os.replace(temporary, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass


__all__ = ["HostKeyTrustStore", "default_trust_store_path"]
