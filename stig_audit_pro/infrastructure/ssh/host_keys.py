"""Explicit SSH host-key enrollment and fail-closed trust storage."""

from __future__ import annotations

import base64
import json
import os
import socket
import uuid
from contextlib import contextmanager
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
        try:
            self.path.touch(mode=0o600, exist_ok=False)
        except FileExistsError:
            pass
        else:
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
        replace: bool = True,
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
        if not host or host.startswith(("#", "@", "|")) or "," in host or any(c.isspace() for c in host):
            raise ValueError("Invalid host name")
        line = f"{marker} {key_type} {key_base64}"
        with self._locked():
            previous = self.path.read_text(encoding="utf-8")
            remaining, removed = self._without_host(previous, marker)
            if removed and not replace:
                if self._hosts(previous).get(marker) == (f"{key_type} {fingerprint}",):
                    return fingerprint
                raise ValueError("A different SSH host key is already stored")
            self._save_change(previous, "\n".join([*remaining, line]) + "\n", {
                "action": "enrolled",
                "host": host,
                "port": int(port),
                "algorithm": key_type,
                "fingerprint": fingerprint,
                "enrolled_at": datetime.now(timezone.utc).isoformat(),
                "operator": operator,
                "verification_note": verification_note.strip(),
                "event_id": str(uuid.uuid4()),
            })
        return fingerprint

    def list_hosts(self) -> dict[str, tuple[str, ...]]:
        """List the host identifiers and fingerprints currently trusted."""
        return self._hosts(self.path.read_text(encoding="utf-8"))

    def remove(self, marker: str, *, operator: str, expected: tuple[str, ...] | None = None) -> bool:
        """Remove a host identifier while preserving aliases and other hosts."""
        if not operator.strip():
            raise ValueError("Operator identity is required")
        with self._locked():
            previous = self.path.read_text(encoding="utf-8")
            remaining, removed = self._without_host(previous, marker)
            if not removed:
                return False
            fingerprints = self._hosts(previous).get(marker, ())
            if expected is not None and expected != fingerprints:
                raise ValueError("The stored host key changed. Reopen the manager and review it.")
            self._save_change(previous, "\n".join(remaining) + ("\n" if remaining else ""), {
                "action": "removed",
                "host": marker,
                "fingerprints": fingerprints,
                "removed_at": datetime.now(timezone.utc).isoformat(),
                "operator": operator,
                "event_id": str(uuid.uuid4()),
            })
            return True

    @staticmethod
    def _without_host(text: str, marker: str) -> tuple[list[str], bool]:
        lines = []
        removed = False
        for line in text.splitlines():
            fields = line.split(maxsplit=1)
            if len(fields) == 2 and not line.lstrip().startswith(("#", "@")):
                aliases = fields[0].split(",")
                if marker in aliases:
                    removed = True
                    aliases = [alias for alias in aliases if alias != marker]
                    if aliases:
                        lines.append(f"{','.join(aliases)} {fields[1]}")
                    continue
            lines.append(line)
        return lines, removed

    @classmethod
    def _hosts(cls, text: str) -> dict[str, tuple[str, ...]]:
        hosts: dict[str, list[str]] = {}
        for line in text.splitlines():
            fields = line.split()
            if len(fields) < 3 or line.lstrip().startswith(("#", "@")):
                continue
            aliases, algorithm, encoded = fields[:3]
            try:
                fingerprint = cls.fingerprint(algorithm, base64.b64decode(encoded, validate=True))
            except ValueError:
                continue
            for alias in aliases.split(","):
                hosts.setdefault(alias, []).append(f"{algorithm} {fingerprint}")
        return {host: tuple(fingerprints) for host, fingerprints in hosts.items()}

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

    @contextmanager
    def _locked(self):
        """Serialize trust changes across app instances using the same store."""
        with self.path.with_suffix(self.path.suffix + ".lock").open("a+b") as lock:
            lock.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield  # Closing the handle releases the lock, including on errors.

    def _save_change(self, previous: str, current: str, entry: dict[str, Any]) -> None:
        history = [*self._load_metadata(), entry]
        self._atomic_write(self.path, current)
        try:
            self._atomic_write(self.metadata_path, json.dumps(history, indent=2) + "\n")
        except OSError:
            self._atomic_write(self.path, previous)
            raise

    @staticmethod
    def _atomic_write(path: Path, value: str) -> None:
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            temporary.write_text(value, encoding="utf-8")
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


__all__ = ["HostKeyTrustStore", "default_trust_store_path"]
