"""Portable, integrity-verifiable historical audit packages."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from pathlib import PurePosixPath
from uuid import UUID

from stig_audit_pro.config import APP_VERSION
from stig_audit_pro.core.archive_safety import MAX_ARCHIVE_BYTES, validate_zip


@dataclass(frozen=True, slots=True)
class AuditPackageVerification:
    valid: bool
    run_id: str | None
    status: str
    problems: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ImportedAuditPackage:
    run_id: str
    run_directory: Path
    includes_evidence: bool


class AuditPackageService:
    def export(self, *, run_id: str, run_directory: str | Path, destination: str | Path, include_evidence: bool = False) -> Path:
        source = Path(run_directory).resolve()
        required = ("manifest.json", "checks.snapshot.yaml", "profile.snapshot.yaml")
        missing = [name for name in required if not (source / name).is_file()]
        if missing:
            raise ValueError(f"Audit run is missing required files: {', '.join(missing)}")
        entries: dict[str, str] = {}
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
            candidates = [item for item in source.rglob("*") if item.is_file() and not item.is_symlink()]
            for item in candidates:
                relative = item.relative_to(source).as_posix()
                if not include_evidence and "/evidence/" in f"/{relative}":
                    continue
                data = item.read_bytes()
                entries[relative] = hashlib.sha256(data).hexdigest()
                archive.writestr(f"audit/{relative}", data)
            package_manifest = {"schema_version": 1, "application_version": APP_VERSION, "run_id": run_id, "classification": "IMPORTED_HISTORICAL_AUDIT", "created_at": datetime.now(timezone.utc).isoformat(), "includes_evidence": include_evidence, "entries": entries}
            archive.writestr("package-manifest.json", json.dumps(package_manifest, indent=2) + "\n")
        temporary.replace(target)
        return target

    def verify(self, package_path: str | Path) -> AuditPackageVerification:
        source = Path(package_path)
        if source.stat().st_size > MAX_ARCHIVE_BYTES:
            return AuditPackageVerification(False, None, "INVALID", ("Package exceeds the supported size limit",))
        problems: list[str] = []
        try:
            with zipfile.ZipFile(source) as archive:
                validate_zip(archive)
                payload = json.loads(archive.read("package-manifest.json"))
                if payload.get("schema_version") != 1:
                    problems.append("Unsupported package schema version")
                entries = payload.get("entries", {})
                if not isinstance(entries, dict):
                    problems.append("Package entry index is invalid")
                    entries = {}
                declared = {f"audit/{name}" for name in entries}
                actual = {
                    info.filename
                    for info in archive.infolist()
                    if not info.is_dir() and info.filename.startswith("audit/")
                }
                for unexpected in sorted(actual - declared):
                    problems.append(f"Undeclared package entry: {unexpected}")
                for name, expected in entries.items():
                    try:
                        actual = hashlib.sha256(archive.read(f"audit/{name}")).hexdigest()
                    except KeyError:
                        problems.append(f"Missing: {name}")
                        continue
                    if actual != expected:
                        problems.append(f"Modified: {name}")
                return AuditPackageVerification(not problems, payload.get("run_id"), "VALID" if not problems else "MODIFIED", tuple(problems))
        except Exception as exc:
            return AuditPackageVerification(False, None, "INVALID", (str(exc),))

    def import_to(
        self,
        package_path: str | Path,
        *,
        evidence_root: str | Path,
    ) -> ImportedAuditPackage:
        """Verify and atomically install one historical run bundle.

        This method only installs the immutable files. ``RunService`` owns the
        separate reconstruction of structured SQLite history.
        """

        verification = self.verify(package_path)
        if not verification.valid or not verification.run_id:
            detail = "; ".join(verification.problems) or verification.status
            raise ValueError(f"Audit package verification failed: {detail}")
        try:
            run_id = str(UUID(verification.run_id))
        except (ValueError, TypeError) as exc:
            raise ValueError("Audit package run ID is not a valid UUID") from exc

        root = Path(evidence_root).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        destination = (root / run_id).resolve()
        if destination.parent != root:
            raise ValueError("Audit package destination is outside the evidence store")
        if destination.exists() or destination.is_symlink():
            raise FileExistsError(f"Audit run already exists: {run_id}")

        staging_parent = Path(tempfile.mkdtemp(prefix=".audit-import-", dir=root))
        staged_run = staging_parent / run_id
        staged_run.mkdir()
        try:
            with zipfile.ZipFile(package_path) as archive:
                infos = validate_zip(archive)
                package_manifest = json.loads(archive.read("package-manifest.json"))
                for info in infos:
                    if info.is_dir() or not info.filename.startswith("audit/"):
                        continue
                    relative = PurePosixPath(info.filename).relative_to("audit")
                    if not relative.parts:
                        continue
                    target = (staged_run / Path(*relative.parts)).resolve()
                    target.relative_to(staged_run.resolve())
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info) as source, target.open("xb") as output:
                        shutil.copyfileobj(source, output)

            required = ("manifest.json", "checks.snapshot.yaml", "profile.snapshot.yaml")
            missing = [name for name in required if not (staged_run / name).is_file()]
            if missing:
                raise ValueError(
                    f"Audit package is missing required files: {', '.join(missing)}"
                )
            manifest = json.loads((staged_run / "manifest.json").read_text(encoding="utf-8"))
            if str(manifest.get("run_id") or "") != run_id:
                raise ValueError("Audit package and audit manifest run IDs do not match")
            os.replace(staged_run, destination)
            return ImportedAuditPackage(
                run_id=run_id,
                run_directory=destination,
                includes_evidence=bool(package_manifest.get("includes_evidence")),
            )
        finally:
            shutil.rmtree(staging_parent, ignore_errors=True)


__all__ = [
    "AuditPackageService",
    "AuditPackageVerification",
    "ImportedAuditPackage",
]
