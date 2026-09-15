"""Application service for versioned STIG import, diff, coverage, and review."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from stig_audit_pro.core.models import CheckDefinition
from stig_audit_pro.stig.check_generator import generate_missing_starter_checks
from stig_audit_pro.stig.stig_diff import (
    StigDiff,
    export_stig_diff_csv,
    export_stig_diff_json,
    export_stig_diff_xlsx,
)
from stig_audit_pro.stig.stig_metadata import StigBenchmarkMetadata
from stig_audit_pro.stig.stig_repository import (
    StigCoverage,
    StigImportResult,
    StigRepository,
)


class StigLifecycleService:
    def __init__(
        self,
        repository: StigRepository | None = None,
        *,
        checks_dir: str | Path | None = None,
    ) -> None:
        self.repository = repository or StigRepository()
        self.checks_dir = Path(checks_dir or self.repository.default_checks_dir)

    def import_release(self, source: str | Path, family: str = "") -> StigImportResult:
        return self.repository.import_source(
            source, family, checks_dir=self.checks_dir
        )

    def import_releases(self, source: str | Path, family: str = "") -> list[StigImportResult]:
        return self.repository.import_sources(
            source, family=family, checks_dir=self.checks_dir
        )

    def installed_releases(
        self, family: str | None = None, benchmark_id: str | None = None
    ) -> list[StigBenchmarkMetadata]:
        return self.repository.list_releases(
            family=family, benchmark_id=benchmark_id
        )

    def compare_to_previous(self, benchmark_id: int) -> StigDiff:
        current = self.repository.get_benchmark(benchmark_id)
        if current is None:
            raise KeyError(f"Unknown STIG release: {benchmark_id}")
        previous = self.repository.previous_release(benchmark_id)
        from stig_audit_pro.stig.stig_diff import compare_stig_releases

        return compare_stig_releases(
            previous, current, checks_dir=self.checks_dir
        )

    def compare(self, previous_id: int, current_id: int) -> StigDiff:
        return self.repository.compare(
            previous_id, current_id, checks_dir=self.checks_dir
        )

    def coverage(self, benchmark_id: int) -> StigCoverage:
        return self.repository.coverage(benchmark_id, checks_dir=self.checks_dir)

    def build_missing_starters(
        self,
        benchmark_id: int,
        existing_checks: Iterable[CheckDefinition],
        destination: str | Path,
    ) -> Path:
        benchmark = self.repository.get_benchmark(benchmark_id)
        if benchmark is None:
            raise KeyError(f"Unknown STIG release: {benchmark_id}")
        return generate_missing_starter_checks(
            [benchmark], existing_checks, destination
        )

    def mark_automation_reviewed(
        self,
        mapping_id: int,
        benchmark_id: int,
        vuln_id: str,
    ):
        benchmark = self.repository.get_benchmark(benchmark_id)
        if benchmark is None:
            raise KeyError(f"Unknown STIG release: {benchmark_id}")
        rule = benchmark.rule_by_vuln(vuln_id)
        if rule is None:
            raise KeyError(f"Vulnerability {vuln_id} is not in the selected release")
        return self.repository.mark_automation_reviewed(
            mapping_id,
            stig_fingerprint=rule.rule_fingerprint,
            reviewed_release=benchmark.release_label,
        )

    @staticmethod
    def export_diff(diff: StigDiff, path: str | Path) -> Path:
        suffix = Path(path).suffix.lower()
        if suffix == ".json":
            return export_stig_diff_json(diff, path)
        if suffix == ".csv":
            return export_stig_diff_csv(diff, path)
        if suffix == ".xlsx":
            return export_stig_diff_xlsx(diff, path)
        raise ValueError("STIG differences can be exported as JSON, CSV, or XLSX")


__all__ = ["StigLifecycleService"]
