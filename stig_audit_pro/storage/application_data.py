"""Upgrade-safe working copies of bundled editable product data."""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

from stig_audit_pro.licensing.paths import application_data_dir


def writable_data_directory() -> Path:
    """Return the per-user root for checks, profiles, groups, and STIG files."""

    return application_data_dir() / "data"


def bootstrap_writable_data(
    bundled_data_directory: str | Path,
    *,
    destination: str | Path | None = None,
) -> Path:
    """Copy missing bundled defaults without replacing customer-owned files.

    The source may be a repository checkout or PyInstaller's bundled data
    directory. Symlinks are ignored and each file is published atomically.
    """

    source = Path(bundled_data_directory).expanduser().resolve()
    target = (
        writable_data_directory()
        if destination is None
        else Path(destination).expanduser()
    ).resolve()
    target.mkdir(parents=True, exist_ok=True)
    if not source.is_dir() or source == target:
        return target

    for item in sorted(source.rglob("*")):
        if item.is_symlink():
            continue
        relative = item.relative_to(source)
        selected = (target / relative).resolve()
        selected.relative_to(target)
        if item.is_dir():
            selected.mkdir(parents=True, exist_ok=True)
            continue
        if not item.is_file() or selected.exists():
            continue
        selected.parent.mkdir(parents=True, exist_ok=True)
        temporary = selected.with_name(f".{selected.name}.{uuid.uuid4().hex}.tmp")
        try:
            shutil.copy2(item, temporary)
            try:
                os.rename(temporary, selected)
            except FileExistsError:
                # Another startup won the race. Its completed file is kept.
                pass
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    return target


__all__ = ["bootstrap_writable_data", "writable_data_directory"]
