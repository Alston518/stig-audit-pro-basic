"""Stable domain result objects emitted by the check engine."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from stig_audit_pro.config import VALID_STATUSES

StatusLiteral = Literal[
    "NotAFinding",
    "Open",
    "Not_Applicable",
    "Not_Reviewed",
    "Error",
    "Skipped",
]


class FindingObject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    object_type: str
    object_name: str
    details: str = ""


class CheckResult(BaseModel):
    """Evaluation result independent of any report/checklist representation.

    Raw evidence is intentionally referenced by artifact ID instead of copied
    into every result record.
    """

    model_config = ConfigDict(extra="forbid")

    ip: str
    hostname: str
    vuln_id: str
    stig_family: str
    title: str
    severity: str
    status: StatusLiteral
    run_id: str | None = None
    rule_id: str | None = None
    stig_id: str | None = None
    check_id: str | None = None
    check_type: str | None = None
    failed_objects: list[FindingObject] = Field(default_factory=list)
    passed_objects: list[FindingObject] = Field(default_factory=list)
    finding_details: str = ""
    comments: str = ""
    evaluation_reason: str = ""
    commands_used: list[str] = Field(default_factory=list)
    evidence_artifact_ids: list[int] = Field(default_factory=list)
    profile_values_used: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None
    parser_warnings: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        if value not in VALID_STATUSES:
            raise ValueError(f"unsupported status: {value}")
        return value

    @field_validator("timestamp", mode="after")
    @classmethod
    def timestamp_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @property
    def passed(self) -> bool:
        return self.status == "NotAFinding"


__all__ = ["CheckResult", "FindingObject", "StatusLiteral"]
