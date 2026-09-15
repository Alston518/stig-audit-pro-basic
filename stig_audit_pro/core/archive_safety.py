"""Shared limits and path validation for untrusted ZIP imports."""

from __future__ import annotations

import stat
import zipfile
from pathlib import PurePosixPath


MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_ENTRY_BYTES = 25 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 250 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 10_000


class UnsafeArchiveError(ValueError):
    pass


def validate_zip(archive: zipfile.ZipFile) -> tuple[zipfile.ZipInfo, ...]:
    infos = tuple(archive.infolist())
    if len(infos) > MAX_ARCHIVE_ENTRIES:
        raise UnsafeArchiveError("Archive contains too many files")
    total = 0
    for info in infos:
        normalized = info.filename.replace("\\", "/")
        path = PurePosixPath(normalized)
        if (
            not normalized or normalized.startswith("/") or path.is_absolute()
            or ".." in path.parts or ":" in path.parts[0]
        ):
            raise UnsafeArchiveError(f"Archive contains an unsafe path: {info.filename}")
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise UnsafeArchiveError(f"Archive contains a symbolic link: {info.filename}")
        if info.flag_bits & 0x1:
            raise UnsafeArchiveError("Encrypted archives are not supported")
        if info.file_size > MAX_ENTRY_BYTES:
            raise UnsafeArchiveError(f"Archive entry is too large: {info.filename}")
        total += info.file_size
        if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise UnsafeArchiveError("Archive expands beyond the supported size limit")
        if info.compress_size and info.file_size / info.compress_size > 1000:
            raise UnsafeArchiveError(f"Archive entry has an unsafe compression ratio: {info.filename}")
    return infos


__all__ = [
    "MAX_ARCHIVE_BYTES", "MAX_ARCHIVE_ENTRIES", "MAX_ENTRY_BYTES",
    "MAX_TOTAL_UNCOMPRESSED_BYTES", "UnsafeArchiveError", "validate_zip",
]
