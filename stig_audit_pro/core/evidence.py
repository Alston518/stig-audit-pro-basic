"""Domain models for immutable evidence metadata and integrity verification."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
import re
from typing import Self
from uuid import UUID

from pydantic import ConfigDict, BaseModel, Field, computed_field, field_validator, model_validator


_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class EvidenceIntegrityStatus(str, Enum):
    VALID = "VALID"
    MISSING = "MISSING"
    MODIFIED = "MODIFIED"
    UNREADABLE = "UNREADABLE"


def _canonical_run_id(value: object) -> str:
    try:
        return str(UUID(str(value)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("run_id must be a UUID") from exc


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _relative_path(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    path = Path(normalized)
    if not normalized or path.is_absolute() or ".." in path.parts:
        raise ValueError("evidence path must be a safe relative path")
    return normalized


def _sha256(value: str) -> str:
    normalized = value.strip().lower()
    if not _SHA256_PATTERN.fullmatch(normalized):
        raise ValueError("SHA-256 must contain exactly 64 hexadecimal characters")
    return normalized


class EvidenceArtifact(BaseModel):
    """Metadata for exact UTF-8 command-output bytes stored outside the database."""

    model_config = ConfigDict(extra="forbid")

    artifact_id: int | None = None
    run_id: str | None = None
    run_device_id: int | None = None
    command: str
    relative_path: str
    sha256: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    byte_length: int = Field(ge=0)

    @field_validator("run_id", mode="before")
    @classmethod
    def validate_run_id(cls, value: object | None) -> str | None:
        return None if value is None else _canonical_run_id(value)

    @field_validator("command")
    @classmethod
    def command_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("command must not be blank")
        return value

    @field_validator("relative_path")
    @classmethod
    def path_must_be_relative(cls, value: str) -> str:
        return _relative_path(value)

    @field_validator("sha256")
    @classmethod
    def hash_must_be_sha256(cls, value: str) -> str:
        return _sha256(value)

    @field_validator("collected_at", mode="after")
    @classmethod
    def timestamp_must_be_utc(cls, value: datetime) -> datetime:
        return _utc_datetime(value)


class EvidenceVerificationItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_id: int | None = None
    relative_path: str
    expected_sha256: str
    actual_sha256: str | None = None
    status: EvidenceIntegrityStatus
    error: str | None = None

    @field_validator("relative_path")
    @classmethod
    def path_must_be_relative(cls, value: str) -> str:
        return _relative_path(value)

    @field_validator("expected_sha256")
    @classmethod
    def expected_hash_must_be_sha256(cls, value: str) -> str:
        return _sha256(value)

    @field_validator("actual_sha256")
    @classmethod
    def actual_hash_must_be_sha256(cls, value: str | None) -> str | None:
        return None if value is None else _sha256(value)


class EvidenceVerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    artifacts: list[EvidenceVerificationItem] = Field(default_factory=list)
    aggregate: EvidenceIntegrityStatus = EvidenceIntegrityStatus.VALID

    @field_validator("run_id", mode="before")
    @classmethod
    def validate_run_id(cls, value: object) -> str:
        return _canonical_run_id(value)

    @model_validator(mode="after")
    def calculate_aggregate(self) -> Self:
        statuses = {artifact.status for artifact in self.artifacts}
        # Prefer the status that requires the strongest operator intervention
        # when a run contains a mix of integrity outcomes.
        for status in (
            EvidenceIntegrityStatus.UNREADABLE,
            EvidenceIntegrityStatus.MODIFIED,
            EvidenceIntegrityStatus.MISSING,
        ):
            if status in statuses:
                self.aggregate = status
                break
        else:
            self.aggregate = EvidenceIntegrityStatus.VALID
        return self

    @computed_field
    @property
    def is_valid(self) -> bool:
        return self.aggregate == EvidenceIntegrityStatus.VALID


__all__ = [
    "EvidenceArtifact",
    "EvidenceIntegrityStatus",
    "EvidenceVerificationItem",
    "EvidenceVerificationResult",
]
