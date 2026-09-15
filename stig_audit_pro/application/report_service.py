"""Central report generation service independent of GUI widget state."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.reports.audit_report import write_csv_report, write_text_report
from stig_audit_pro.reports.excel_writer import write_excel_report
from stig_audit_pro.reports.json_writer import write_json_report
from stig_audit_pro.stig.cklb_writer import write_completed_cklb


class ReportService:
    """Generate reproducible files from persisted/internal result models."""

    def write_text(self, results: Iterable[CheckResult], path: str | Path) -> Path:
        return write_text_report(list(results), path)

    def write_csv(self, results: Iterable[CheckResult], path: str | Path) -> Path:
        return write_csv_report(list(results), path)

    def write_json(self, results: Iterable[CheckResult], path: str | Path, **metadata: Any) -> Path:
        return write_json_report(list(results), path, **metadata)

    def write_excel(self, results: Iterable[CheckResult], path: str | Path, **metadata: Any) -> Path:
        return write_excel_report(list(results), path, **metadata)

    def write_cklb(
        self, source: Any, path: str | Path, results: Iterable[CheckResult],
        asset: Any, **options: Any,
    ) -> Any:
        return write_completed_cklb(source, path, list(results), asset, **options)


__all__ = ["ReportService"]
