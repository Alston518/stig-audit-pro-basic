"""Platform-specific locations used by offline licensing."""

from __future__ import annotations

from pathlib import Path

from platformdirs import user_data_path

from stig_audit_pro.config import LICENSE_FILENAME


def application_data_dir() -> Path:
    """Return the per-user, non-roaming STIG Audit Pro data directory."""

    return user_data_path("STIG Audit Pro", appauthor=False, roaming=False)


def default_license_path() -> Path:
    return application_data_dir() / LICENSE_FILENAME


def log_directory() -> Path:
    return application_data_dir() / "logs"
