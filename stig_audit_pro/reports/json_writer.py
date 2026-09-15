"""Stable, schema-versioned JSON audit reports."""

from __future__ import annotations

import json
from collections import Counter
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping

from pydantic import BaseModel

from stig_audit_pro.config import APP_VERSION
from stig_audit_pro.core.result_model import CheckResult


REPORT_SCHEMA_VERSION = 1


def _json_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_value(item) for item in value]
    return value


def build_json_report(
    results: Iterable[CheckResult],
    *,
    audit_run: Any | None = None,
    devices: Iterable[Any] = (),
    stig_metadata: Iterable[Any] = (),
    evidence_artifacts: Iterable[Any] = (),
) -> dict[str, Any]:
    result_list = list(results)
    statuses = Counter(result.status for result in result_list)
    devices_list = list(devices)
    if not devices_list:
        devices_list = [
            {"target_ip": ip, "hostname": hostname}
            for ip, hostname in sorted({(r.ip, r.hostname) for r in result_list})
        ]
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generator": {"name": "STIG Audit Pro", "version": APP_VERSION},
        "audit": _json_value(audit_run) if audit_run is not None else {},
        "devices": _json_value(devices_list),
        "stig": _json_value(list(stig_metadata)),
        "summary": {
            "device_count": len(devices_list),
            "total_checks": len(result_list),
            "status_counts": dict(sorted(statuses.items())),
            "open": statuses["Open"],
            "not_a_finding": statuses["NotAFinding"],
            "not_applicable": statuses["Not_Applicable"],
            "not_reviewed": statuses["Not_Reviewed"],
            "errors": statuses["Error"] + statuses["Skipped"],
        },
        "results": [result.model_dump(mode="json") for result in result_list],
        "evidence": [_json_value(artifact) for artifact in evidence_artifacts],
    }


def write_json_report(
    results: Iterable[CheckResult],
    path: str | Path,
    **metadata: Any,
) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = build_json_report(results, **metadata)
    destination.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return destination


__all__ = ["REPORT_SCHEMA_VERSION", "build_json_report", "write_json_report"]
