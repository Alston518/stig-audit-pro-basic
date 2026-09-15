"""Create sanitized diagnostics archives without raw evidence or credentials."""

from __future__ import annotations

import json
import platform
import re
import sys
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from stig_audit_pro.config import APP_VERSION
from stig_audit_pro.infrastructure.persistence.migrations import get_schema_version
from stig_audit_pro.infrastructure.persistence.repositories import ActivityLogRepository, StigPersistenceRepository


_SECRET_PATTERN = re.compile(
    r"(?i)(password|enable[_ -]?secret|passphrase|api[_ -]?key|token|private[_ -]?key)\s*[:=]\s*([^\s,;]+)"
)
_SSH_LIBRARY_LINE = re.compile(r"\b(?:paramiko|netmiko|scp)(?:\.[A-Za-z0-9_]+)*\b", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class SupportBundlePreview:
    included: tuple[str, ...]
    excluded: tuple[str, ...]


class SupportBundleService:
    def __init__(self, database, *, log_paths: Iterable[str | Path] = ()) -> None:
        self.database = database
        self.log_paths = tuple(Path(item) for item in log_paths)

    def preview(self) -> SupportBundlePreview:
        return SupportBundlePreview(
            included=("Application/runtime information", "Database schema version", "Installed STIG metadata", "Recent sanitized activity", "Sanitized application logs"),
            excluded=("Passwords and secrets", "License signing keys", "Raw device evidence", "Full running configurations"),
        )

    def create(self, destination: str | Path) -> Path:
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        runtime = {
            "application_version": APP_VERSION,
            "python_version": sys.version,
            "operating_system": platform.platform(),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "database_schema_version": get_schema_version(self.database.engine),
        }
        stigs = [
            {key: getattr(item, key) for key in ("family", "benchmark_id", "title", "version", "release", "source_sha256", "imported_at")}
            for item in StigPersistenceRepository(self.database).list_benchmarks()
        ]
        activities = [
            {"timestamp": item.timestamp, "action": item.action, "object_type": item.object_type, "object_id": item.object_id, "details": item.details}
            for item in ActivityLogRepository(self.database).list_recent(limit=250)
        ]
        temporary = target.with_suffix(target.suffix + ".tmp")
        with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("runtime.json", self._json(runtime))
            archive.writestr("installed_stigs.json", self._json(stigs))
            archive.writestr("recent_activity.json", self._json(activities))
            for index, log_path in enumerate(self.log_paths):
                if log_path.is_file() and log_path.stat().st_size <= 10 * 1024 * 1024:
                    archive.writestr(
                        f"logs/log-{index + 1}.txt",
                        self.redact(
                            log_path.read_text(encoding="utf-8", errors="replace"),
                            suppress_ssh_diagnostics=True,
                        ),
                    )
            archive.writestr("README.txt", "This support bundle excludes credentials and raw device evidence by default.\n")
        temporary.replace(target)
        return target

    @staticmethod
    def redact(value: str, *, suppress_ssh_diagnostics: bool = False) -> str:
        cleaned = value
        if suppress_ssh_diagnostics:
            cleaned = "\n".join(
                "[REDACTED THIRD-PARTY SSH DIAGNOSTIC]"
                if _SSH_LIBRARY_LINE.search(line)
                else line
                for line in value.splitlines()
            )
        return _SECRET_PATTERN.sub(
            lambda match: f"{match.group(1)}=[REDACTED]", cleaned
        )

    @classmethod
    def _json(cls, value) -> str:
        return cls.redact(json.dumps(value, indent=2, default=str, ensure_ascii=False)) + "\n"


__all__ = ["SupportBundlePreview", "SupportBundleService"]
