"""Validated local backup and restore for persistent application data."""

from __future__ import annotations

import json
import hashlib
import os
import shutil
import sqlite3
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from stig_audit_pro.config import APP_VERSION
from stig_audit_pro.core.archive_safety import MAX_ARCHIVE_BYTES, validate_zip
from stig_audit_pro.infrastructure.persistence.migrations import CURRENT_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class BackupSource:
    name: str
    path: Path


@dataclass(frozen=True, slots=True)
class BackupInspection:
    application_version: str
    created_at: str
    includes_evidence: bool
    entry_count: int


class BackupService:
    """Back up only explicitly supplied product-owned files and directories."""

    def __init__(self, *, database_path: str | Path, sources: Iterable[BackupSource], evidence_root: str | Path | None = None) -> None:
        self.database_path = Path(database_path).resolve()
        self.sources = tuple(sources)
        self.evidence_root = Path(evidence_root).resolve() if evidence_root else None

    def create(self, destination: str | Path, *, include_evidence: bool = False) -> Path:
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        manifest = {"schema_version": 1, "application_version": APP_VERSION, "created_at": datetime.now(timezone.utc).isoformat(), "includes_evidence": include_evidence, "entries": [], "sha256": {}}
        temporary = target.with_suffix(target.suffix + ".tmp")
        with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
            self._add_path(archive, self.database_path, "database/stig-audit-pro.sqlite3", manifest)
            for source in self.sources:
                self._add_path(archive, source.path.resolve(), f"data/{self._safe_name(source.name)}", manifest)
            if include_evidence and self.evidence_root:
                self._add_path(archive, self.evidence_root, "evidence", manifest)
            archive.writestr("backup-manifest.json", json.dumps(manifest, indent=2) + "\n")
        temporary.replace(target)
        return target

    def inspect(self, archive_path: str | Path) -> BackupInspection:
        """Validate a backup without changing any application data."""

        source = Path(archive_path)
        if not source.is_file() or source.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ValueError("Backup archive is missing or exceeds the supported size limit")
        with zipfile.ZipFile(source) as archive:
            infos = validate_zip(archive)
            try:
                manifest = json.loads(archive.read("backup-manifest.json"))
            except (KeyError, json.JSONDecodeError) as exc:
                raise ValueError("Not a valid STIG Audit Pro backup") from exc
            if manifest.get("schema_version") != 1:
                raise ValueError("Unsupported backup schema version")
            entries = manifest.get("entries")
            if not isinstance(entries, list) or not all(
                isinstance(item, str) for item in entries
            ):
                raise ValueError("Backup entry index is invalid")
            actual = {
                info.filename
                for info in infos
                if not info.is_dir() and info.filename != "backup-manifest.json"
            }
            if actual != set(entries):
                raise ValueError("Backup contents do not match its entry index")
            hashes = manifest.get("sha256")
            if hashes is not None:
                if not isinstance(hashes, dict) or set(hashes) != actual:
                    raise ValueError("Backup hash index is invalid")
                for name, expected in hashes.items():
                    digest = hashlib.sha256(archive.read(name)).hexdigest()
                    if digest != expected:
                        raise ValueError(f"Backup entry failed integrity verification: {name}")
            allowed = {"database", "data"}
            if manifest.get("includes_evidence"):
                allowed.add("evidence")
            for name in actual:
                parts = Path(name.replace("\\", "/")).parts
                if parts[0] not in allowed:
                    raise ValueError(f"Backup contains an unsupported entry: {name}")
                if parts[0] == "data" and (
                    len(parts) < 2
                    or parts[1] not in {
                        self._safe_name(source.name) for source in self.sources
                    }
                ):
                    raise ValueError(f"Backup contains an unknown data set: {name}")
            if "database/stig-audit-pro.sqlite3" not in actual:
                raise ValueError("Backup does not contain the application database")
            return BackupInspection(
                application_version=str(manifest.get("application_version") or "unknown"),
                created_at=str(manifest.get("created_at") or "unknown"),
                includes_evidence=bool(manifest.get("includes_evidence")),
                entry_count=len(actual),
            )

    def restore_in_place(self, archive_path: str | Path) -> Path:
        """Restore only the exact destinations configured for this service.

        A validated safety backup is created first. All replacement targets are
        moved aside and rolled back if any publication step fails.
        """

        inspection = self.inspect(archive_path)
        if self.database_path.parent is None:
            raise ValueError("A filesystem database is required for restore")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        safety_directory = self.database_path.parent / "backups"
        safety_directory.mkdir(parents=True, exist_ok=True)
        safety = self.create(
            safety_directory / f"before-restore-{stamp}.zip",
            include_evidence=inspection.includes_evidence,
        )

        restore_root = self.database_path.parent
        with tempfile.TemporaryDirectory(
            prefix=".stig-audit-pro-restore-", dir=restore_root
        ) as temp_dir:
            staging = Path(temp_dir) / "staging"
            rollback = Path(temp_dir) / "rollback"
            staging.mkdir()
            rollback.mkdir()
            with zipfile.ZipFile(archive_path) as archive:
                for info in validate_zip(archive):
                    if info.is_dir() or info.filename == "backup-manifest.json":
                        continue
                    target = (staging / info.filename).resolve()
                    target.relative_to(staging.resolve())
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info) as source, target.open("xb") as output:
                        shutil.copyfileobj(source, output)

            staged_database = staging / "database" / "stig-audit-pro.sqlite3"
            self._validate_database(staged_database)
            publications: list[tuple[Path, Path]] = [
                (staged_database, self.database_path)
            ]
            for source in self.sources:
                staged_source = staging / "data" / self._safe_name(source.name)
                if staged_source.exists():
                    publications.append((staged_source, source.path.resolve()))
            staged_evidence = staging / "evidence"
            if inspection.includes_evidence and self.evidence_root and staged_evidence.exists():
                publications.append((staged_evidence, self.evidence_root))

            replaced: list[tuple[Path, Path | None]] = []
            try:
                for index, (staged, destination) in enumerate(publications):
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    prior: Path | None = None
                    if destination.exists() or destination.is_symlink():
                        prior = rollback / str(index)
                        os.replace(destination, prior)
                    try:
                        os.replace(staged, destination)
                    except Exception:
                        if prior is not None and prior.exists():
                            os.replace(prior, destination)
                        raise
                    replaced.append((destination, prior))
            except Exception:
                for destination, prior in reversed(replaced):
                    self._remove_exact(destination)
                    if prior is not None and prior.exists():
                        os.replace(prior, destination)
                raise
        return safety

    def restore(self, archive_path: str | Path, *, destination_root: str | Path) -> Path:
        source = Path(archive_path)
        if source.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ValueError("Backup archive exceeds the supported size limit")
        root = Path(destination_root).resolve()
        root.mkdir(parents=True, exist_ok=True)
        safety = root.parent / f"{root.name}-before-restore-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        if root.exists() and any(root.iterdir()):
            shutil.copytree(root, safety)
        with zipfile.ZipFile(source) as archive:
            infos = validate_zip(archive)
            try:
                manifest = json.loads(archive.read("backup-manifest.json"))
            except (KeyError, json.JSONDecodeError) as exc:
                raise ValueError("Not a valid STIG Audit Pro backup") from exc
            if manifest.get("schema_version") != 1:
                raise ValueError("Unsupported backup schema version")
            with tempfile.TemporaryDirectory(dir=root.parent) as temp_dir:
                staging = Path(temp_dir)
                for info in infos:
                    if info.is_dir():
                        continue
                    destination = (staging / info.filename).resolve()
                    destination.relative_to(staging.resolve())
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info) as input_stream, destination.open("xb") as output_stream:
                        shutil.copyfileobj(input_stream, output_stream)
                restored = staging / "restored"
                restored.mkdir()
                for item in staging.iterdir():
                    if item.name != "restored":
                        shutil.move(str(item), restored / item.name)
                for item in restored.iterdir():
                    destination = root / item.name
                    if destination.exists():
                        if destination.is_dir():
                            shutil.rmtree(destination)
                        else:
                            destination.unlink()
                    shutil.move(str(item), destination)
        return safety

    @staticmethod
    def _safe_name(value: str) -> str:
        cleaned = "".join(character if character.isalnum() or character in "._-" else "-" for character in value).strip(".-")
        if not cleaned:
            raise ValueError("Backup source requires a safe name")
        return cleaned

    @staticmethod
    def _remove_exact(path: Path) -> None:
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)

    @staticmethod
    def _validate_database(path: Path) -> None:
        try:
            connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
            try:
                result = connection.execute("PRAGMA quick_check").fetchone()
                if not result or result[0] != "ok":
                    raise ValueError("Backup database failed SQLite integrity validation")
                row = connection.execute(
                    "SELECT version FROM schema_version WHERE id = 1"
                ).fetchone()
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise ValueError("Backup database is not a valid STIG Audit Pro database") from exc
        if row is None or int(row[0]) > CURRENT_SCHEMA_VERSION:
            raise ValueError("Backup database schema is unsupported by this application")

    @classmethod
    def _add_path(cls, archive: zipfile.ZipFile, source: Path, prefix: str, manifest: dict) -> None:
        if not source.exists() or source.is_symlink():
            return
        files = [source] if source.is_file() else [item for item in source.rglob("*") if item.is_file() and not item.is_symlink()]
        for item in files:
            relative = Path(prefix) if source.is_file() else Path(prefix) / item.relative_to(source)
            archive.write(item, relative.as_posix())
            manifest["entries"].append(relative.as_posix())
            manifest["sha256"][relative.as_posix()] = cls._file_sha256(item)

    @staticmethod
    def _file_sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()


__all__ = ["BackupInspection", "BackupService", "BackupSource"]
