"""Deterministic readiness classification for local STIG automation."""

from __future__ import annotations

from enum import Enum
from typing import Any


class AutomationConfidence(str, Enum):
    VERIFIED = "VERIFIED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    UNTESTED = "UNTESTED"
    MANUAL = "MANUAL"
    MISSING = "MISSING"
    RETIRED = "RETIRED"


def classify_automation(
    *,
    mapping: Any | None,
    current_rule_fingerprint: str | None,
    yaml_valid: bool,
    commands_valid: bool,
    fixtures_complete: bool,
    fixtures_passing: bool,
    rule_retired: bool = False,
) -> AutomationConfidence:
    if mapping is None:
        return AutomationConfidence.MISSING
    if rule_retired:
        return AutomationConfidence.RETIRED
    automated = bool(getattr(mapping, "automated", False)) and getattr(mapping, "check_type", "") != "manual_review"
    if not automated:
        return AutomationConfidence.MANUAL
    reviewed = getattr(mapping, "last_reviewed_stig_fingerprint", None)
    if not current_rule_fingerprint or reviewed != current_rule_fingerprint:
        return AutomationConfidence.REVIEW_REQUIRED
    if not yaml_valid or not commands_valid or not fixtures_complete or not fixtures_passing:
        return AutomationConfidence.UNTESTED
    return AutomationConfidence.VERIFIED


__all__ = ["AutomationConfidence", "classify_automation"]
