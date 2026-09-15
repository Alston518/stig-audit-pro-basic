"""Immutable, UUID-isolated evidence bundles with SHA-256 verification."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import threading
import uuid
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Mapping
from uuid import UUID

import yaml
from platformdirs import user_data_path

from stig_audit_pro.config import APP_VERSION
from stig_audit_pro.core.evidence import (
    EvidenceArtifact,
    EvidenceIntegrityStatus,
    EvidenceVerificationItem,
    EvidenceVerificationResult,
)

if TYPE_CHECKING:
    from stig_audit_pro.infrastructure.persistence.repositories import AuditRunRepository


_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")
_SECRET_KEYS = {
    "authentication_secret",
    "credentials",
    "enable_password",
    "enable_secret",
    "license_private_key",
    "password",
    "private_key",
    "private_license_material",
    "secret",
    "ssh_password",
    "token",
}


class EvidenceStoreError(RuntimeError):
    """Base class for evidence bundle failures."""


class RunAlreadyExistsError(EvidenceStoreError):
    pass


class RunNotFoundError(EvidenceStoreError):
    pass


class RunFinalizedError(EvidenceStoreError):
    pass


def default_evidence_root() -> Path:
    """Return the per-user root beneath which UUID run bundles are stored."""

    return user_data_path("STIG Audit Pro", appauthor=False, roaming=False) / "work" / "runs"


def _canonical_run_id(run_id: str | UUID) -> str:
    try:
        return str(UUID(str(run_id)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("run_id must be a UUID") from exc


def _utc(value: datetime | None = None) -> datetime:
    candidate = value or datetime.now(timezone.utc)
    if candidate.tzinfo is None:
        return candidate.replace(tzinfo=timezone.utc)
    return candidate.astimezone(timezone.utc)


def _json_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return _utc(value).isoformat()
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_value(item) for item in value]
    if is_dataclass(value):
        return _json_value(asdict(value))
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _json_value(model_dump(mode="python"))
    return value


def _without_secrets(value: Any) -> Any:
    """Remove credential-shaped fields from persisted non-evidence metadata."""

    value = _json_value(value)
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")
            if normalized_key in _SECRET_KEYS:
                continue
            cleaned[key] = _without_secrets(item)
        return cleaned
    if isinstance(value, list):
        return [_without_secrets(item) for item in value]
    return value


def _safe_name(value: str, *, fallback: str) -> str:
    cleaned = _SAFE_NAME.sub("_", value.strip()).strip("_.-")
    return cleaned[:160] or fallback


class EvidenceStore:
    """Write and verify immutable command evidence under one directory per run.

    The root and optional database repository are injected, making tests and
    portable/offline deployments independent of a user's real application
    data.  A run is finalized by creating ``manifest.json``; all subsequent
    writes to that run fail closed.
    """

    def __init__(
        self,
        root: str | Path | None = None,
        repository: "AuditRunRepository | None" = None,
    ) -> None:
        self.root = (default_evidence_root() if root is None else Path(root)).expanduser()
        self.root.mkdir(parents=True, exist_ok=True)
        self.root = self.root.resolve()
        self.repository = repository
        self._lock = threading.RLock()

    def run_path(self, run_id: str | UUID) -> Path:
        canonical = _canonical_run_id(run_id)
        path = (self.root / canonical).resolve()
        if path.parent != self.root:
            raise ValueError("run_id resolves outside the evidence root")
        return path

    def create_run(
        self,
        run_id: str | UUID,
        *,
        check_snapshot: Any | None = None,
        profile_snapshot: Any | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Path:
        run_dir = self.run_path(run_id)
        with self._lock:
            try:
                run_dir.mkdir(parents=False, exist_ok=False)
            except FileExistsError as exc:
                raise RunAlreadyExistsError(f"Evidence run already exists: {run_id}") from exc
            (run_dir / "devices").mkdir()
            if check_snapshot is not None:
                self._write_snapshot(run_dir / "checks.snapshot.yaml", check_snapshot)
            if profile_snapshot is not None:
                self._write_snapshot(run_dir / "profile.snapshot.yaml", profile_snapshot)
            if metadata is not None:
                self._atomic_write_new(
                    run_dir / "run.json", self._json_bytes(_without_secrets(metadata))
                )
        return run_dir

    # Application services may use begin_run terminology.
    begin_run = create_run

    def write_snapshot(self, run_id: str | UUID, name: str, content: Any) -> Path:
        if name not in {"checks.snapshot.yaml", "profile.snapshot.yaml"}:
            raise ValueError("Unsupported snapshot name")
        run_dir = self._writable_run(run_id)
        path = run_dir / name
        with self._lock:
            self._write_snapshot(path, content)
        return path

    def prepare_device(
        self,
        run_id: str | UUID,
        target_ip: str,
        *,
        hostname: str | None = None,
        device_facts: Mapping[str, Any] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Path:
        run_dir = self._writable_run(run_id)
        if not str(target_ip).strip():
            raise ValueError("target_ip must not be blank")
        with self._lock:
            device_dir = self._find_device_dir(run_dir, target_ip)
            if device_dir is None:
                base = _safe_name(str(target_ip), fallback="device")
                device_dir = run_dir / "devices" / base
                if device_dir.exists():
                    suffix = hashlib.sha256(str(target_ip).encode("utf-8")).hexdigest()[:8]
                    device_dir = run_dir / "devices" / f"{base}-{suffix}"
                device_dir.mkdir(parents=False, exist_ok=False)
                (device_dir / "evidence").mkdir()
                payload: dict[str, Any] = {
                    "target_ip": str(target_ip),
                    "hostname": hostname,
                    "device_facts": dict(device_facts or {}),
                    "evidence_artifacts": [],
                }
            else:
                payload = self._read_json(device_dir / "device.json", default={})
                if hostname is not None:
                    payload["hostname"] = hostname
                if device_facts:
                    payload["device_facts"] = {
                        **dict(payload.get("device_facts") or {}),
                        **dict(device_facts),
                    }
            if metadata:
                payload.update(dict(metadata))
            self._atomic_replace(
                device_dir / "device.json", self._json_bytes(_without_secrets(payload))
            )
            return device_dir

    def write_evidence(
        self,
        run_id: str | UUID,
        device: str,
        command: str,
        output: str,
        *,
        collected_at: datetime | None = None,
        run_device_id: int | None = None,
    ) -> EvidenceArtifact:
        """Atomically store the exact UTF-8 bytes and return their metadata."""

        if not isinstance(output, str):
            raise TypeError("Evidence output must be text so exact UTF-8 bytes are defined")
        if not command.strip():
            raise ValueError("command must not be blank")
        canonical = _canonical_run_id(run_id)
        run_dir = self._writable_run(canonical)
        encoded = output.encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        timestamp = _utc(collected_at)

        with self._lock:
            device_dir = self._find_device_dir(run_dir, device)
            if device_dir is None:
                device_dir = self.prepare_device(canonical, device)
            evidence_dir = device_dir / "evidence"
            base_name = _safe_name(" ".join(command.split()), fallback="command")
            destination = evidence_dir / f"{base_name}.txt"
            sequence = 2
            while destination.exists():
                destination = evidence_dir / f"{base_name}-{sequence}.txt"
                sequence += 1
            self._atomic_write_new(destination, encoded)

            relative_path = destination.relative_to(self.root).as_posix()
            artifact = EvidenceArtifact(
                run_id=canonical,
                run_device_id=run_device_id,
                command=command,
                relative_path=relative_path,
                sha256=digest,
                collected_at=timestamp,
                byte_length=len(encoded),
            )
            device_metadata_path = device_dir / "device.json"
            device_metadata = self._read_json(device_metadata_path, default={})
            artifacts = list(device_metadata.get("evidence_artifacts") or [])
            artifacts.append(artifact.model_dump(mode="json"))
            device_metadata["evidence_artifacts"] = artifacts
            self._atomic_replace(device_metadata_path, self._json_bytes(device_metadata))

            if self.repository is not None:
                resolved_device_id = run_device_id
                if resolved_device_id is None:
                    target_ip = str(device_metadata.get("target_ip") or device)
                    record = self.repository.find_device(canonical, target_ip)
                    resolved_device_id = record.id if record is not None else None
                if resolved_device_id is not None:
                    row = self.repository.add_evidence_artifact(
                        resolved_device_id, artifact
                    )
                    artifact = artifact.model_copy(
                        update={
                            "artifact_id": row.id,
                            "run_device_id": resolved_device_id,
                        }
                    )
                    artifacts[-1] = artifact.model_dump(mode="json")
                    device_metadata["evidence_artifacts"] = artifacts
                    self._atomic_replace(
                        device_metadata_path, self._json_bytes(device_metadata)
                    )
            return artifact

    # A readable alias for offline-import adapters.
    import_evidence = write_evidence

    def write_results(self, run_id: str | UUID, device: str, results: Any) -> Path:
        run_dir = self._writable_run(run_id)
        with self._lock:
            device_dir = self._find_device_dir(run_dir, device)
            if device_dir is None:
                device_dir = self.prepare_device(run_id, device)
            path = device_dir / "results.json"
            self._atomic_write_new(path, self._json_bytes(_without_secrets(results)))
            return path

    def finalize_run(
        self, run_id: str | UUID, manifest: Mapping[str, Any] | None = None
    ) -> Path:
        """Create the run manifest last, making the evidence bundle read-only."""

        canonical = _canonical_run_id(run_id)
        run_dir = self._writable_run(canonical)
        with self._lock:
            devices = self._device_metadata(run_dir)
            evidence = [
                artifact
                for device in devices
                for artifact in device.get("evidence_artifacts", [])
            ]
            draft = self._read_json(run_dir / "run.json", default={})
            supplied = dict(manifest or {})
            payload: dict[str, Any] = {
                **draft,
                **supplied,
                "run_id": canonical,
                "application_version": supplied.get(
                    "application_version", supplied.get("app_version", APP_VERSION)
                ),
                "targets": supplied.get(
                    "targets", [device.get("target_ip") for device in devices]
                ),
                "detected_hostnames": supplied.get(
                    "detected_hostnames",
                    [device.get("hostname") for device in devices if device.get("hostname")],
                ),
                "device_facts": supplied.get(
                    "device_facts",
                    {
                        str(device.get("target_ip")): device.get("device_facts", {})
                        for device in devices
                    },
                ),
                "commands_actually_executed": supplied.get(
                    "commands_actually_executed",
                    list(dict.fromkeys(item.get("command") for item in evidence)),
                ),
                "evidence_artifacts": evidence,
            }
            payload.setdefault("commands_requested", payload["commands_actually_executed"])
            payload = _without_secrets(payload)
            path = run_dir / "manifest.json"
            self._atomic_write_new(path, self._json_bytes(payload))
            return path

    write_manifest = finalize_run

    def load_manifest(self, run_id: str | UUID) -> dict[str, Any]:
        path = self._existing_run(run_id) / "manifest.json"
        if not path.is_file():
            raise FileNotFoundError(path)
        return self._read_json(path, default={})

    def verify_evidence(self, run_id: str | UUID) -> EvidenceVerificationResult:
        canonical = _canonical_run_id(run_id)
        run_dir = self._existing_run(canonical)
        manifest_path = run_dir / "manifest.json"
        if manifest_path.is_file():
            metadata = self._read_json(manifest_path, default={})
            artifacts = metadata.get("evidence_artifacts") or metadata.get("evidence") or []
        else:
            artifacts = [
                artifact
                for device in self._device_metadata(run_dir)
                for artifact in device.get("evidence_artifacts", [])
            ]
        items = [self._verify_artifact(canonical, artifact) for artifact in artifacts]
        return EvidenceVerificationResult(run_id=canonical, artifacts=items)

    def verify_artifact(
        self, run_id: str | UUID, artifact: EvidenceArtifact | Mapping[str, Any]
    ) -> EvidenceVerificationItem:
        return self._verify_artifact(_canonical_run_id(run_id), _json_value(artifact))

    def read_evidence(self, relative_path: str | Path) -> str:
        path = self._safe_artifact_path(str(relative_path))
        return path.read_text(encoding="utf-8")

    def purge_raw_evidence(self, run_id: str | UUID) -> int:
        """Delete only raw outputs, retaining manifests, hashes, and results."""

        run_dir = self._existing_run(run_id)
        removed = 0
        with self._lock:
            for evidence_dir in (run_dir / "devices").glob("*/evidence"):
                if not evidence_dir.is_dir() or evidence_dir.is_symlink():
                    continue
                for path in evidence_dir.iterdir():
                    if path.is_file() and not path.is_symlink():
                        path.unlink()
                        removed += 1
        return removed

    # Compatibility with UI wording.
    purge_run_evidence = purge_raw_evidence

    def delete_run(self, run_id: str | UUID) -> bool:
        """Delete exactly one validated UUID bundle from the configured root."""

        run_dir = self.run_path(run_id)
        with self._lock:
            if not run_dir.exists() and not run_dir.is_symlink():
                return False
            if run_dir.is_symlink():
                run_dir.unlink()
            else:
                shutil.rmtree(run_dir)
            return True

    def _writable_run(self, run_id: str | UUID) -> Path:
        path = self._existing_run(run_id)
        if (path / "manifest.json").exists():
            raise RunFinalizedError(f"Evidence run is finalized: {run_id}")
        return path

    def _existing_run(self, run_id: str | UUID) -> Path:
        path = self.run_path(run_id)
        if not path.is_dir() or path.is_symlink():
            raise RunNotFoundError(f"Unknown evidence run: {run_id}")
        return path

    def _find_device_dir(self, run_dir: Path, identity: str) -> Path | None:
        devices_dir = run_dir / "devices"
        direct = devices_dir / _safe_name(str(identity), fallback="device")
        if direct.is_dir() and not direct.is_symlink():
            return direct
        for candidate in devices_dir.iterdir():
            if not candidate.is_dir() or candidate.is_symlink():
                continue
            metadata = self._read_json(candidate / "device.json", default={})
            if identity in {
                metadata.get("target_ip"),
                metadata.get("hostname"),
                candidate.name,
            }:
                return candidate
        return None

    def _device_metadata(self, run_dir: Path) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        devices_dir = run_dir / "devices"
        if not devices_dir.is_dir():
            return result
        for device_dir in sorted(devices_dir.iterdir(), key=lambda item: item.name):
            if device_dir.is_dir() and not device_dir.is_symlink():
                result.append(self._read_json(device_dir / "device.json", default={}))
        return result

    def _verify_artifact(
        self, run_id: str, artifact: Mapping[str, Any]
    ) -> EvidenceVerificationItem:
        relative_path = str(artifact.get("relative_path") or "")
        expected = str(artifact.get("sha256") or "").lower()
        artifact_id = artifact.get("artifact_id") or artifact.get("id")
        try:
            path = self._safe_artifact_path(relative_path, expected_run_id=run_id)
        except (ValueError, OSError) as exc:
            return EvidenceVerificationItem(
                artifact_id=artifact_id,
                relative_path=relative_path or f"{run_id}/invalid-evidence-path",
                expected_sha256=expected if re.fullmatch(r"[0-9a-f]{64}", expected) else "0" * 64,
                status=EvidenceIntegrityStatus.UNREADABLE,
                error=str(exc),
            )
        if not path.exists():
            return EvidenceVerificationItem(
                artifact_id=artifact_id,
                relative_path=relative_path,
                expected_sha256=expected,
                status=EvidenceIntegrityStatus.MISSING,
            )
        try:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            return EvidenceVerificationItem(
                artifact_id=artifact_id,
                relative_path=relative_path,
                expected_sha256=expected,
                status=EvidenceIntegrityStatus.UNREADABLE,
                error=str(exc),
            )
        status = (
            EvidenceIntegrityStatus.VALID
            if actual == expected
            else EvidenceIntegrityStatus.MODIFIED
        )
        return EvidenceVerificationItem(
            artifact_id=artifact_id,
            relative_path=relative_path,
            expected_sha256=expected,
            actual_sha256=actual,
            status=status,
        )

    def _safe_artifact_path(
        self, relative_path: str, *, expected_run_id: str | None = None
    ) -> Path:
        candidate = Path(relative_path.replace("\\", "/"))
        if candidate.is_absolute() or not candidate.parts or ".." in candidate.parts:
            raise ValueError("Unsafe evidence path")
        if expected_run_id is not None and candidate.parts[0] != expected_run_id:
            # Accept legacy run-relative paths, but scope them to this run.
            candidate = Path(expected_run_id) / candidate
        resolved = (self.root / candidate).resolve()
        if resolved == self.root or self.root not in resolved.parents:
            raise ValueError("Evidence path resolves outside the configured root")
        if expected_run_id is not None:
            expected_root = self.run_path(expected_run_id)
            if resolved != expected_root and expected_root not in resolved.parents:
                raise ValueError("Evidence path belongs to a different audit run")
        return resolved

    @staticmethod
    def _read_json(path: Path, *, default: Any) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return default

    @staticmethod
    def _json_bytes(value: Any) -> bytes:
        return (
            json.dumps(_json_value(value), indent=2, sort_keys=True, ensure_ascii=False)
            + "\n"
        ).encode("utf-8")

    def _write_snapshot(self, path: Path, content: Any) -> None:
        if isinstance(content, bytes):
            encoded = content
        elif isinstance(content, str):
            encoded = content.encode("utf-8")
        else:
            encoded = yaml.safe_dump(
                _without_secrets(content),
                sort_keys=True,
                allow_unicode=True,
                default_flow_style=False,
            ).encode("utf-8")
        self._atomic_write_new(path, encoded)

    @staticmethod
    def _atomic_write_new(path: Path, data: bytes) -> None:
        if path.exists():
            raise FileExistsError(path)
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            if path.exists():
                raise FileExistsError(path)
            os.rename(temporary, path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _atomic_replace(path: Path, data: bytes) -> None:
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def verify_evidence(
    run_id: str | UUID, *, root: str | Path | None = None
) -> EvidenceVerificationResult:
    """Convenience API matching the product-level integrity operation."""

    return EvidenceStore(root).verify_evidence(run_id)
