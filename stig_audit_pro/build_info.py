"""Build metadata shown in the Basic GUI."""

from __future__ import annotations

import sys
from pathlib import Path

from stig_audit_pro.config import APP_VERSION


def _metadata_paths() -> list[Path]:
    executable_dir = Path(sys.executable).resolve().parent
    source_root = Path(__file__).resolve().parents[1]
    bundle_root = Path(getattr(sys, "_MEIPASS", source_root))
    return [
        executable_dir / "BUILD_INFO.txt",
        executable_dir.parent / "BUILD_INFO.txt",
        bundle_root / "BUILD_INFO.txt",
        source_root / "BUILD_INFO.txt",
    ]


def load_build_metadata() -> dict[str, str]:
    """Read release metadata without making startup depend on Git."""

    metadata: dict[str, str] = {"version": APP_VERSION, "date": "Development build", "id": "source"}
    for path in _metadata_paths():
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            key, separator, value = line.partition(":")
            if not separator:
                continue
            normalized = key.strip().casefold()
            value = value.strip()
            if normalized in {"package date", "build date", "updated", "date"} and value:
                metadata["date"] = value
            elif normalized in {"commit", "build", "build id"} and value:
                metadata["id"] = value[:12]
            elif normalized in {"version", "app version"} and value:
                metadata["version"] = value
        break
    return metadata


__all__ = ["load_build_metadata"]
