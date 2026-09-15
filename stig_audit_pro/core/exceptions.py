"""Exception models and result override helper."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from stig_audit_pro.config import VALID_STATUSES
from stig_audit_pro.core.result_model import CheckResult


class ExceptionRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hostname: str = "*"
    ip: str = "*"
    vuln_id: str
    object_type: str = "*"
    object_name: str = "*"
    force_status: str
    reason: str

    @field_validator("force_status")
    @classmethod
    def status_must_be_supported(cls, value: str) -> str:
        if value not in VALID_STATUSES:
            raise ValueError(f"unsupported force_status: {value}")
        return value


class ExceptionLibrary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    exceptions: list[ExceptionRule] = Field(default_factory=list)


def _matches(pattern: str, value: str) -> bool:
    return pattern == "*" or pattern.lower() == value.lower()


def exception_applies(rule: ExceptionRule, result: CheckResult) -> bool:
    if not _matches(rule.hostname, result.hostname):
        return False
    if not _matches(rule.ip, result.ip):
        return False
    if not _matches(rule.vuln_id, result.vuln_id):
        return False
    if rule.object_type == "*" and rule.object_name == "*":
        return True

    objects = [*result.failed_objects, *result.passed_objects]
    for obj in objects:
        if _matches(rule.object_type, obj.object_type) and _matches(
            rule.object_name, obj.object_name
        ):
            return True
    return False


def apply_exceptions(result: CheckResult, rules: list[ExceptionRule]) -> CheckResult:
    for rule in rules:
        if exception_applies(rule, result):
            result.status = rule.force_status
            suffix = f" Exception applied: {rule.reason}"
            result.comments = f"{result.comments}{suffix}" if result.comments else suffix.strip()
            return result
    return result
