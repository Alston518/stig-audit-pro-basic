"""Generate starter manual-review checks from imported STIG metadata."""

from __future__ import annotations

import os
import re
import uuid
from pathlib import Path
from typing import Iterable

import yaml

from stig_audit_pro.core.models import CheckDefinition, CheckLibrary
from stig_audit_pro.stig.stig_metadata import StigBenchmarkMetadata, StigRuleMetadata

GENERATED_LIBRARY_NAME = "generated_stig_manual_starters"
SEVERITY_TO_CATEGORY = {
    "high": "cat1",
    "medium": "cat2",
    "low": "cat3",
}


def build_manual_starter_library(
    metadata_items: Iterable[StigBenchmarkMetadata],
    existing_checks: Iterable[CheckDefinition],
) -> CheckLibrary:
    metadata_list = list(metadata_items)
    existing_keys = _existing_rule_keys(existing_checks)
    generated: list[CheckDefinition] = []
    seen_generated: set[str] = set()
    for metadata in metadata_list:
        for rule in metadata.rules:
            key = _rule_key(rule)
            if not key or key in existing_keys or key in seen_generated:
                continue
            seen_generated.add(key)
            generated.append(_manual_check_from_rule(metadata, rule, key))
    versions = sorted(
        {
            f"{item.version}-{item.release}".strip("-")
            for item in metadata_list
            if item.version or item.release
        }
    )
    return CheckLibrary(
        schema_version=1,
        library_name=GENERATED_LIBRARY_NAME,
        library_version="+".join(versions) or "generated",
        checks=generated,
    )


def write_manual_starter_library(library: CheckLibrary, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = _model_dump(library)
    destination.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return destination


def generate_missing_starter_checks(
    metadata_items: Iterable[StigBenchmarkMetadata],
    existing_checks: Iterable[CheckDefinition],
    destination: str | Path,
) -> Path:
    """Create a release-labelled manual starter library without overwriting.

    ``destination`` may be a YAML filename or directory. Existing files always
    fail closed; generated starters never alter existing automation.
    """

    metadata = list(metadata_items)
    library = build_manual_starter_library(metadata, existing_checks)
    selected = Path(destination)
    if selected.suffix.lower() not in {".yaml", ".yml"}:
        family = "_".join(sorted({item.family for item in metadata if item.family})) or "stig"
        release = "_".join(
            sorted(
                {
                    "_".join(part for part in (item.version, item.release) if part)
                    for item in metadata
                }
            )
        ) or "baseline"
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{family}_{release}").strip("_.")
        selected = selected / f"generated_{safe}_manual.yaml"
    if selected.exists():
        raise FileExistsError(f"Starter check library already exists: {selected}")
    selected.parent.mkdir(parents=True, exist_ok=True)
    payload = _model_dump(library)
    encoded = yaml.safe_dump(payload, sort_keys=False).encode("utf-8")
    temporary = selected.with_name(f".{selected.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if selected.exists():
            raise FileExistsError(f"Starter check library already exists: {selected}")
        os.rename(temporary, selected)
    finally:
        temporary.unlink(missing_ok=True)
    return selected


def _manual_check_from_rule(
    metadata: StigBenchmarkMetadata,
    rule: StigRuleMetadata,
    key: str,
) -> CheckDefinition:
    return CheckDefinition(
        vuln_id=key,
        title=rule.title or key,
        stig_family=metadata.family or "UNKNOWN",
        severity=_severity_to_category(rule.severity),
        automated=False,
        check_type="manual_review",
        commands=[],
        stig_id=rule.stig_id or None,
        group_id=rule.group_id or rule.vuln_id or None,
        rule_id=rule.rule_id or None,
        source_benchmark=metadata.title or metadata.benchmark_id or None,
        source_version=metadata.version or None,
        source_release=metadata.release or metadata.release_info or None,
        result={
            "pass_status": "NotAFinding",
            "fail_status": "Not_Reviewed",
            "error_status": "Error",
        },
        evidence={
            "include_command_output": False,
            "include_failed_objects": False,
            "pass_comment": "Manual review completed and requirement was marked NotAFinding.",
            "fail_comment": "Manual review required. Review the STIG requirement and customer/site tailoring.",
            "error_comment": "Manual review check could not be prepared.",
            "finding_details_template": "manual_review",
        },
    )


def _existing_rule_keys(checks: Iterable[CheckDefinition]) -> set[str]:
    keys: set[str] = set()
    for check in checks:
        keys.add(check.vuln_id)
        if check.stig_id:
            keys.add(check.stig_id)
        if check.rule_id:
            keys.add(check.rule_id)
    return keys


def _rule_key(rule: StigRuleMetadata) -> str:
    return rule.vuln_id or rule.group_id or rule.stig_id or rule.rule_id


def _severity_to_category(severity: str) -> str:
    return SEVERITY_TO_CATEGORY.get(severity.lower().strip(), severity or "unknown")


def _model_dump(value: object) -> object:
    if hasattr(value, "model_dump"):
        return value.model_dump(exclude_none=True)  # type: ignore[attr-defined]
    if hasattr(value, "dict"):
        return value.dict(exclude_none=True)  # type: ignore[attr-defined]
    return value


__all__ = [
    "GENERATED_LIBRARY_NAME",
    "build_manual_starter_library",
    "generate_missing_starter_checks",
    "write_manual_starter_library",
]
