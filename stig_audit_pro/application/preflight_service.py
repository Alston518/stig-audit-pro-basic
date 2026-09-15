"""Plain-language readiness validation performed before any network access."""

from __future__ import annotations

import ipaddress
import re
import shutil
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from stig_audit_pro.core.command_policy import CommandPolicy, DEFAULT_COMMAND_POLICY
from stig_audit_pro.core.models import CheckDefinition, SiteProfile
from stig_audit_pro.infrastructure.persistence.database import Database


class PreflightSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    BLOCKING = "BLOCKING"


class PreflightIssue(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    code: str
    severity: PreflightSeverity
    message: str
    guidance: str = ""
    technical_details: str = ""


class PreflightResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    issues: list[PreflightIssue] = Field(default_factory=list)

    @property
    def ready(self) -> bool:
        return not any(item.severity is PreflightSeverity.BLOCKING for item in self.issues)

    @property
    def blocking_issues(self) -> list[PreflightIssue]:
        return [item for item in self.issues if item.severity is PreflightSeverity.BLOCKING]

    @property
    def warnings(self) -> list[PreflightIssue]:
        return [item for item in self.issues if item.severity is PreflightSeverity.WARNING]


class PreflightService:
    """Validate an audit definition without opening an SSH connection."""

    def __init__(self, command_policy: CommandPolicy = DEFAULT_COMMAND_POLICY) -> None:
        self.command_policy = command_policy

    def validate(
        self,
        *,
        targets: Iterable[Any],
        checks: Iterable[CheckDefinition],
        profile: SiteProfile | Mapping[str, Any] | None,
        stig_families: Iterable[str],
        database: Database | None = None,
        evidence_root: str | Path | None = None,
        report_directory: str | Path | None = None,
        minimum_free_bytes: int = 100 * 1024 * 1024,
    ) -> PreflightResult:
        issues: list[PreflightIssue] = []
        target_list = list(targets)
        check_list = list(checks)
        families = [str(item).strip() for item in stig_families if str(item).strip()]

        if not target_list:
            issues.append(self._blocking("NO_DEVICES", "No devices are selected.", "Add or select at least one Cisco IOS-XE device."))
        seen: set[str] = set()
        duplicates: set[str] = set()
        for target in target_list:
            address = str(getattr(target, "ip", target if isinstance(target, str) else "")).strip()
            key = address.casefold()
            if key in seen:
                duplicates.add(address)
            seen.add(key)
            if not self._valid_address(address):
                issues.append(self._blocking(
                    "INVALID_DEVICE", f"'{address or '(blank)'}' is not a valid IP address or hostname.",
                    "Correct the device address before starting the audit.",
                ))
        if duplicates:
            issues.append(self._blocking(
                "DUPLICATE_DEVICES", f"The device list contains duplicates: {', '.join(sorted(duplicates))}.",
                "Remove duplicates so each device is assessed once.",
            ))

        if not families:
            issues.append(self._blocking("NO_STIG", "No STIG release is selected.", "Select at least one installed STIG release."))
        if not check_list:
            issues.append(self._blocking("NO_CHECKS", "No checks are available for the selected STIG.", "Import the STIG and load a matching check pack."))

        parsed_profile: SiteProfile | None = None
        if profile is None:
            issues.append(self._blocking("NO_PROFILE", "No Site Profile is selected.", "Choose or create a Site Profile."))
        else:
            try:
                parsed_profile = profile if isinstance(profile, SiteProfile) else SiteProfile.model_validate(profile)
            except Exception as exc:
                issues.append(self._blocking("INVALID_PROFILE", "The selected Site Profile is not valid.", "Open the profile and correct the highlighted values.", str(exc)))

        for check in check_list:
            try:
                self.command_policy.validate_many(check.commands)
            except Exception as exc:
                issues.append(self._blocking(
                    "UNSAFE_COMMAND", f"Check {check.vuln_id} requests a command that is not approved by the read-only policy.",
                    "Open the Check editor and use only approved evidence commands.", str(exc),
                ))

        if parsed_profile is not None:
            missing = self._missing_profile_values(check_list, parsed_profile)
            if missing:
                issues.append(self._blocking(
                    "PROFILE_VALUES_MISSING",
                    f"The selected Site Profile does not define values required by checks: {', '.join(sorted(missing))}.",
                    "Open the Site Profile and provide the missing site-specific values.",
                ))

        if database is not None:
            try:
                with database.engine.connect() as connection:
                    connection.execute(text("SELECT 1"))
                if not database.foreign_keys_enabled():
                    raise RuntimeError("SQLite foreign-key enforcement is disabled")
            except Exception as exc:
                issues.append(self._blocking("DATABASE_UNAVAILABLE", "Audit history storage is not available.", "Open Administration > Diagnostics and verify the database.", str(exc)))

        for code, label, selected in (
            ("EVIDENCE_UNWRITABLE", "evidence storage", evidence_root),
            ("REPORT_UNWRITABLE", "report output folder", report_directory),
        ):
            if selected is None:
                continue
            try:
                path = Path(selected).expanduser().resolve()
                path.mkdir(parents=True, exist_ok=True)
                probe = path / ".stig-audit-pro-write-test"
                probe.touch(exist_ok=False)
                probe.unlink()
                if code == "EVIDENCE_UNWRITABLE" and shutil.disk_usage(path).free < minimum_free_bytes:
                    issues.append(PreflightIssue(
                        code="LOW_DISK_SPACE", severity=PreflightSeverity.WARNING,
                        message="Evidence storage has less than 100 MB free.",
                        guidance="Free disk space or select another evidence location before a large audit.",
                    ))
            except Exception as exc:
                issues.append(self._blocking(code, f"The {label} is not writable.", "Choose a writable folder or ask an administrator to correct permissions.", str(exc)))

        manual = sum(1 for check in check_list if not check.automated or check.check_type == "manual_review")
        if manual:
            issues.append(PreflightIssue(
                code="MANUAL_CHECKS", severity=PreflightSeverity.WARNING,
                message=f"{manual} selected check{'s' if manual != 1 else ''} require a reviewer decision.",
                guidance="Complete these items from Results after automated evaluation finishes.",
            ))
        review_required = sum(
            1 for check in check_list
            if str(check.review_status or check.automation_status or "").upper() in {"REVIEW_REQUIRED", "STALE"}
        )
        if review_required:
            issues.append(PreflightIssue(
                code="AUTOMATION_REVIEW_REQUIRED", severity=PreflightSeverity.WARNING,
                message=f"{review_required} automated check{'s' if review_required != 1 else ''} need review against the selected STIG release.",
                guidance="Open the STIG Update Center to review changed DISA procedures before relying on these checks.",
            ))
        elif check_list and not any(check.last_reviewed_stig_fingerprint for check in check_list if check.automated):
            issues.append(PreflightIssue(
                code="AUTOMATION_STATUS_UNKNOWN", severity=PreflightSeverity.WARNING,
                message="Automation review status is not recorded for this check pack.",
                guidance="An administrator should map and review automation against the installed STIG release.",
            ))
        if not issues:
            issues.append(PreflightIssue(code="READY", severity=PreflightSeverity.INFO, message="Ready to audit.", guidance="All required readiness checks passed."))
        return PreflightResult(issues=issues)

    @staticmethod
    def _valid_address(value: str) -> bool:
        if not value or len(value) > 253 or any(char.isspace() for char in value):
            return False
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            labels = value.rstrip(".").split(".")
            return bool(labels) and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels)

    @staticmethod
    def _missing_profile_values(checks: list[CheckDefinition], profile: SiteProfile) -> set[str]:
        payload = profile.model_dump(mode="python")
        rendered = "\n".join(str(check.model_dump(mode="python")) for check in checks)
        names = set(re.findall(r"\{\{\s*([A-Za-z_][\w.]*)", rendered))
        names.difference_update({"item", "value", "object", "match"})
        missing: set[str] = set()
        for name in names:
            value: Any = payload
            if "." not in name and name not in payload and name in payload.get("variables", {}):
                value = payload["variables"]
            for part in name.split("."):
                if not isinstance(value, Mapping) or part not in value:
                    missing.add(name)
                    break
                value = value[part]
            else:
                if value is None or value == "" or value == [] or value == {}:
                    missing.add(name)
        return missing

    @staticmethod
    def _blocking(code: str, message: str, guidance: str, details: str = "") -> PreflightIssue:
        return PreflightIssue(code=code, severity=PreflightSeverity.BLOCKING, message=message, guidance=guidance, technical_details=details)


__all__ = ["PreflightIssue", "PreflightResult", "PreflightService", "PreflightSeverity"]
