"""Audit run-to-run comparison and export."""

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable, Mapping

from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.reports.spreadsheet_safety import safe_spreadsheet_row


class RunChange(str, Enum):
    NEW_FINDING = "NEW_FINDING"
    RESOLVED = "RESOLVED"
    PERSISTENT_FINDING = "PERSISTENT_FINDING"
    UNCHANGED_PASS = "UNCHANGED_PASS"
    STATUS_CHANGED = "STATUS_CHANGED"
    NEWLY_APPLICABLE = "NEWLY_APPLICABLE"
    NO_LONGER_APPLICABLE = "NO_LONGER_APPLICABLE"
    NOT_COMPARABLE = "NOT_COMPARABLE"


@dataclass(frozen=True, slots=True)
class ResultComparison:
    device: str
    vuln_id: str
    previous_status: str | None
    current_status: str | None
    classification: RunChange
    previous_rule_id: str | None = None
    current_rule_id: str | None = None
    reason: str = ""


@dataclass(slots=True)
class RunComparison:
    previous_run_id: str | None
    current_run_id: str | None
    items: list[ResultComparison] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        counts = Counter(item.classification.value for item in self.items)
        return {
            "previous_open": sum(item.previous_status == "Open" for item in self.items),
            "current_open": sum(item.current_status == "Open" for item in self.items),
            "new": counts[RunChange.NEW_FINDING.value],
            "resolved": counts[RunChange.RESOLVED.value],
            "persistent": counts[RunChange.PERSISTENT_FINDING.value],
            "errors": sum(
                item.previous_status in {"Error", "Skipped"}
                or item.current_status in {"Error", "Skipped"}
                for item in self.items
            ),
            **{key.lower(): value for key, value in sorted(counts.items())},
        }


def compare_runs(
    previous: Iterable[CheckResult],
    current: Iterable[CheckResult],
    *,
    previous_run_id: str | None = None,
    current_run_id: str | None = None,
    previous_rule_fingerprints: Mapping[str, str] | None = None,
    current_rule_fingerprints: Mapping[str, str] | None = None,
) -> RunComparison:
    old = {_key(result): result for result in previous}
    new = {_key(result): result for result in current}
    old_fingerprints = previous_rule_fingerprints or {}
    new_fingerprints = current_rule_fingerprints or {}
    items: list[ResultComparison] = []
    for key in sorted(set(old) | set(new)):
        before, after = old.get(key), new.get(key)
        vuln_id = key[1]
        fingerprint_changed = (
            vuln_id in old_fingerprints
            and vuln_id in new_fingerprints
            and old_fingerprints[vuln_id] != new_fingerprints[vuln_id]
        )
        classification, reason = _classify(before, after, fingerprint_changed)
        items.append(ResultComparison(
            device=key[0], vuln_id=vuln_id,
            previous_status=before.status if before else None,
            current_status=after.status if after else None,
            classification=classification,
            previous_rule_id=before.rule_id if before else None,
            current_rule_id=after.rule_id if after else None,
            reason=reason,
        ))
    return RunComparison(previous_run_id, current_run_id, items)


def _key(result: CheckResult) -> tuple[str, str]:
    return result.ip, result.vuln_id


def _classify(
    before: CheckResult | None, after: CheckResult | None, fingerprint_changed: bool,
) -> tuple[RunChange, str]:
    if fingerprint_changed:
        return RunChange.NOT_COMPARABLE, "The STIG rule fingerprint changed between runs."
    if before is None:
        return RunChange.NEWLY_APPLICABLE, "The device/vulnerability pair is new in the current run."
    if after is None:
        return RunChange.NO_LONGER_APPLICABLE, "The device/vulnerability pair is absent from the current run."
    old, new = before.status, after.status
    if old in {"Error", "Skipped"} or new in {"Error", "Skipped"}:
        return RunChange.NOT_COMPARABLE, "At least one evaluation ended in an error."
    if old == "Open" and new == "Open":
        return RunChange.PERSISTENT_FINDING, "The finding remains open."
    if old == "Open" and new == "NotAFinding":
        return RunChange.RESOLVED, "The prior finding now passes."
    if old != "Open" and new == "Open":
        return RunChange.NEW_FINDING, "A finding is open that was not open previously."
    if old == "NotAFinding" and new == "NotAFinding":
        return RunChange.UNCHANGED_PASS, "The check passes in both runs."
    if old == "Not_Applicable" and new != "Not_Applicable":
        return RunChange.NEWLY_APPLICABLE, "The check is now applicable."
    if old != "Not_Applicable" and new == "Not_Applicable":
        return RunChange.NO_LONGER_APPLICABLE, "The check is no longer applicable."
    return RunChange.STATUS_CHANGED, f"Status changed from {old} to {new}."


def export_run_comparison_json(comparison: RunComparison, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "previous_run_id": comparison.previous_run_id,
        "current_run_id": comparison.current_run_id,
        "summary": comparison.summary,
        "items": [
            {**asdict(item), "classification": item.classification.value}
            for item in comparison.items
        ],
    }
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


def export_run_comparison_csv(comparison: RunComparison, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "device", "vuln_id", "previous_status", "current_status", "classification",
        "previous_rule_id", "current_rule_id", "reason",
    ]
    with destination.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in comparison.items:
            row = asdict(item)
            row["classification"] = item.classification.value
            writer.writerow(safe_spreadsheet_row(row))
    return destination


def export_run_comparison_excel(comparison: RunComparison, path: str | Path) -> Path:
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill
        from openpyxl.worksheet.table import Table, TableStyleInfo
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("openpyxl is required for Excel comparison exports") from exc
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    workbook = Workbook()
    summary = workbook.active
    summary.title = "Summary"
    summary.append(["Metric", "Count"])
    for name, value in comparison.summary.items():
        summary.append([name.replace("_", " ").title(), value])
    details = workbook.create_sheet("Changes")
    headers = [
        "Device", "Vuln ID", "Previous Status", "Current Status", "Classification",
        "Previous Rule ID", "Current Rule ID", "Reason",
    ]
    details.append(headers)
    for item in comparison.items:
        details.append(safe_spreadsheet_row([
            item.device, item.vuln_id, item.previous_status, item.current_status,
            item.classification.value, item.previous_rule_id, item.current_rule_id, item.reason,
        ]))
    for sheet in workbook.worksheets:
        for cell in sheet[1]:
            cell.font = Font(color="FFFFFF", bold=True)
            cell.fill = PatternFill("solid", fgColor="17365D")
        sheet.freeze_panes = "A2"
        sheet.auto_filter.ref = sheet.dimensions
    if details.max_row > 1:
        table = Table(displayName="RunComparisonChanges", ref=details.dimensions)
        table.tableStyleInfo = TableStyleInfo(name="TableStyleMedium2", showRowStripes=True)
        details.add_table(table)
    workbook.save(destination)
    return destination


__all__ = [
    "ResultComparison", "RunChange", "RunComparison", "compare_runs",
    "export_run_comparison_csv", "export_run_comparison_excel",
    "export_run_comparison_json",
]
