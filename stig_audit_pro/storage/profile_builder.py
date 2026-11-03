"""Build and safely publish standalone Basic site profiles."""

from __future__ import annotations

import os
import re
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

import yaml

from stig_audit_pro.core.models import SiteProfile
from stig_audit_pro.core.yaml_loader import deep_merge


class ProfileBuildError(ValueError):
    """Raised when a site profile cannot be materialized or validated."""


def safe_profile_filename(profile_name: str) -> str:
    """Return a stable YAML filename for a user-facing profile name."""

    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", profile_name.strip()).strip("_")
    if not safe:
        raise ProfileBuildError("Profile name must contain a letter or number")
    return f"{safe}.yaml"


def materialize_profile(
    base_data: Mapping[str, Any],
    overrides: Mapping[str, Any],
    profile_name: str,
) -> dict[str, Any]:
    """Flatten a base profile and site overrides into one standalone mapping.

    Mapping values merge recursively. Lists, scalars, and explicit empty lists
    replace the corresponding base value. The resulting profile never retains
    an ``inherits`` key, so it remains reproducible without the base file.
    """

    name = profile_name.strip()
    if not name:
        raise ProfileBuildError("Profile name must not be empty")
    if not isinstance(base_data, Mapping) or not isinstance(overrides, Mapping):
        raise ProfileBuildError("Profile data must be mappings")

    merged = deep_merge(dict(base_data), dict(overrides))
    merged.pop("inherits", None)
    merged["profile_name"] = name
    return merged


def validate_profile_data(
    data: Mapping[str, Any], profiles_dir: str | Path | None = None
) -> SiteProfile:
    """Validate a standalone profile through the domain model."""

    del profiles_dir  # Reserved for callers that share loader-style signatures.
    if not isinstance(data, Mapping):
        raise ProfileBuildError("profile validation failed: expected a mapping")
    if data.get("inherits"):
        raise ProfileBuildError(
            "profile validation failed: saved site profiles must be standalone"
        )
    try:
        return SiteProfile.model_validate(dict(data))
    except Exception as exc:  # Pydantic raises several validation subclasses.
        raise ProfileBuildError(f"profile validation failed: {exc}") from exc


def save_profile(
    path: str | Path, data: Mapping[str, Any], profiles_dir: str | Path | None = None
) -> Path:
    """Validate and atomically publish a standalone YAML profile."""

    destination = Path(path).expanduser().resolve()
    if destination.suffix.casefold() not in {".yaml", ".yml"}:
        raise ProfileBuildError("Profile files must use .yaml or .yml")
    prepared = deepcopy(dict(data))
    prepared.pop("inherits", None)
    validate_profile_data(prepared, profiles_dir)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            yaml.safe_dump(prepared, handle, sort_keys=False, allow_unicode=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except (OSError, yaml.YAMLError) as exc:
        raise ProfileBuildError(f"Could not save profile {destination}: {exc}") from exc
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def load_profile_data(path: str | Path) -> dict[str, Any]:
    """Load raw profile YAML for editing without applying inheritance."""

    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ProfileBuildError(f"Could not read profile {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ProfileBuildError(f"Profile {path} must contain a top-level mapping")
    return deepcopy(data)


__all__ = [
    "ProfileBuildError",
    "load_profile_data",
    "materialize_profile",
    "safe_profile_filename",
    "save_profile",
    "validate_profile_data",
]
