"""Versioned local STIG library backed by the embedded SQLite repository."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from pydantic import BaseModel, ConfigDict

from stig_audit_pro.core.models import CheckDefinition
from stig_audit_pro.core.yaml_loader import load_check_library
from stig_audit_pro.infrastructure.persistence import Database
from stig_audit_pro.infrastructure.persistence.repositories import StigPersistenceRepository
from stig_audit_pro.stig.stig_comparator import load_stig_benchmarks
from stig_audit_pro.stig.stig_diff import (
    DiffStatus,
    StigDiff,
    analyze_yaml_impact,
    compare_stig_releases,
    export_stig_diff_json,
)
from stig_audit_pro.stig.stig_metadata import (
    StigBenchmarkMetadata,
    StigRuleMetadata,
    normalize_identifier,
)


@dataclass(frozen=True, slots=True)
class StigImportResult:
    benchmark: StigBenchmarkMetadata
    previous: StigBenchmarkMetadata | None
    diff: StigDiff

    @property
    def baseline(self) -> bool:
        return self.diff.status == DiffStatus.NO_PREVIOUS_RELEASE


class StigCoverage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    benchmark_db_id: int | None = None
    family: str
    benchmark_id: str
    release: str
    total_rules: int
    automated: int
    manual_review: int
    missing_check: int
    changed_review_required: int
    retired_mapping: int
    automation_mapping_percent: float
    current_reviewed_automation_percent: float

    @property
    def automation_coverage(self) -> float:
        return self.current_reviewed_automation_percent


class StigRepository:
    """Store multiple benchmark releases without overwriting earlier imports."""

    def __init__(self, database_or_path: Database | str | Path | None = None) -> None:
        self.database = (
            database_or_path
            if isinstance(database_or_path, Database)
            else Database(database_or_path)
        )
        self.persistence = StigPersistenceRepository(self.database)
        self.default_checks_dir = Path(__file__).resolve().parents[2] / "data" / "checks"
        data_path = self.database.path.parent if self.database.path else Path.cwd()
        self.diff_root = data_path / "stig-diffs"

    def import_source(
        self,
        path: str | Path,
        family: str = "",
        *,
        checks_dir: str | Path | None = None,
    ) -> StigImportResult:
        results = self.import_sources(path, family=family, checks_dir=checks_dir)
        if not results:
            raise ValueError("No STIG benchmark was imported")
        if len(results) > 1 and not family:
            # Preserve all releases but return a deterministic primary result
            # for the historical single-result API.
            results.sort(key=lambda item: (item.benchmark.family, item.benchmark.benchmark_id))
        return results[0]

    def import_sources(
        self,
        path: str | Path,
        *,
        family: str = "",
        checks_dir: str | Path | None = None,
    ) -> list[StigImportResult]:
        source = Path(path)
        try:
            source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        except OSError as exc:
            raise ValueError(f"Could not read STIG source {source}: {exc}") from exc
        benchmarks = load_stig_benchmarks(source, family=family or None)
        imported: list[StigImportResult] = []
        for benchmark in benchmarks:
            benchmark.source_sha256 = source_hash
            benchmark.source_path = str(source)
            benchmark.calculate_fingerprints()
            stored = self.save_benchmark(benchmark)
            previous = self.previous_release(stored.database_id or 0)
            diff = compare_stig_releases(
                previous,
                stored,
                checks_dir=checks_dir or self.default_checks_dir,
            )
            self._save_diff(stored, previous, diff)
            imported.append(StigImportResult(stored, previous, diff))
        return imported

    def save_benchmark(self, benchmark: StigBenchmarkMetadata) -> StigBenchmarkMetadata:
        benchmark.calculate_fingerprints()
        record = self.persistence.add_benchmark(benchmark, rules=benchmark.rules)
        return self._from_record(record)

    def list_releases(
        self,
        *,
        family: str | None = None,
        benchmark_id: str | None = None,
    ) -> list[StigBenchmarkMetadata]:
        return [
            self._from_record(record)
            for record in self.persistence.list_benchmarks(
                family=family, benchmark_id=benchmark_id
            )
        ]

    def get_benchmark(self, benchmark_db_id: int) -> StigBenchmarkMetadata | None:
        record = self.persistence.get_benchmark(benchmark_db_id)
        return self._from_record(record) if record is not None else None

    def previous_release(
        self, benchmark_or_id: int | StigBenchmarkMetadata
    ) -> StigBenchmarkMetadata | None:
        benchmark_id = (
            benchmark_or_id.database_id
            if isinstance(benchmark_or_id, StigBenchmarkMetadata)
            else benchmark_or_id
        )
        if not benchmark_id:
            return None
        record = self.persistence.previous_benchmark(int(benchmark_id))
        return self._from_record(record) if record is not None else None

    def compare(
        self,
        previous_id: int,
        current_id: int,
        *,
        checks_dir: str | Path | None = None,
    ) -> StigDiff:
        previous = self.get_benchmark(previous_id)
        current = self.get_benchmark(current_id)
        if previous is None or current is None:
            raise KeyError("Both STIG releases must exist in the local library")
        if (
            previous.family != current.family
            or previous.benchmark_id != current.benchmark_id
        ):
            raise ValueError("STIG releases must share a family and benchmark ID")
        return compare_stig_releases(
            previous, current, checks_dir=checks_dir or self.default_checks_dir
        )

    def sync_check_mappings(
        self,
        benchmark_id: int,
        *,
        checks_dir: str | Path | None = None,
    ) -> int:
        benchmark = self.get_benchmark(benchmark_id)
        if benchmark is None:
            raise KeyError(f"Unknown STIG benchmark: {benchmark_id}")
        checks = self._load_checks(checks_dir or self.default_checks_dir)
        created = 0
        for check, path in checks:
            matching = self._matching_rules(check, benchmark.rules)
            if len(matching) != 1:
                continue
            rule = matching[0]
            existing = [
                item for item in self.persistence.list_mappings(vuln_id=check.vuln_id)
                if item.check_file == path.as_posix()
                and item.check_id == (check.check_id or check.vuln_id)
                and item.stig_rule_id == getattr(rule, "database_id", None)
            ]
            if existing:
                continue
            self.persistence.add_mapping(
                stig_rule_id=getattr(rule, "database_id", None),
                vuln_id=check.vuln_id,
                rule_id=check.rule_id,
                stig_id=check.stig_id,
                check_file=path.as_posix(),
                check_id=check.check_id or check.vuln_id,
                check_type=check.check_type,
                source_benchmark=check.source_benchmark,
                source_version=check.source_version,
                source_release=check.source_release,
                automation_status=(
                    "AUTOMATED"
                    if check.automated and check.check_type != "manual_review"
                    else "MANUAL_REVIEW"
                ),
                review_status=check.review_status,
                last_reviewed_stig_fingerprint=check.last_reviewed_stig_fingerprint,
                reviewed_release=check.reviewed_release,
                reviewed_at=check.reviewed_at,
            )
            created += 1
        return created

    def mark_automation_reviewed(
        self,
        mapping_id: int,
        *,
        stig_fingerprint: str,
        reviewed_release: str | None = None,
        reviewed_at: datetime | None = None,
    ):
        return self.persistence.mark_mapping_reviewed(
            mapping_id,
            stig_fingerprint=stig_fingerprint,
            reviewed_release=reviewed_release,
            reviewed_at=reviewed_at or datetime.now(timezone.utc),
        )

    def coverage(
        self,
        benchmark_or_id: int | StigBenchmarkMetadata,
        *,
        checks_dir: str | Path | None = None,
    ) -> StigCoverage:
        benchmark = (
            benchmark_or_id
            if isinstance(benchmark_or_id, StigBenchmarkMetadata)
            else self.get_benchmark(benchmark_or_id)
        )
        if benchmark is None:
            raise KeyError(f"Unknown STIG benchmark: {benchmark_or_id}")
        # Mappings are the durable administrator-review record. Synchronize
        # discovered YAML checks before measuring coverage, but never alter the
        # YAML itself or infer that a check was reviewed.
        self.sync_check_mappings(
            benchmark.database_id or 0,
            checks_dir=checks_dir or self.default_checks_dir,
        )
        checks = self._load_checks(checks_dir or self.default_checks_dir)
        automated = manual = missing = stale = 0
        matched_check_ids: set[int] = set()
        for rule in benchmark.rules:
            matches = [
                (index, check)
                for index, (check, _path) in enumerate(checks)
                if self._check_matches_rule(check, rule)
            ]
            if not matches:
                missing += 1
                continue
            if len(matches) > 1:
                stale += 1
                matched_check_ids.update(index for index, _check in matches)
                continue
            index, check = matches[0]
            matched_check_ids.add(index)
            if not check.automated or check.check_type == "manual_review":
                manual += 1
            else:
                automated += 1
                mappings = self.persistence.list_mappings(
                    stig_rule_id=rule.database_id
                )
                reviewed_current = any(
                    mapping.last_reviewed_stig_fingerprint == rule.rule_fingerprint
                    for mapping in mappings
                )
                if not reviewed_current:
                    stale += 1
        retired = len(checks) - len(matched_check_ids)
        total = len(benchmark.rules)
        current = max(0, automated - stale)
        return StigCoverage(
            benchmark_db_id=benchmark.database_id,
            family=benchmark.family,
            benchmark_id=benchmark.benchmark_id,
            release=benchmark.release_label,
            total_rules=total,
            automated=automated,
            manual_review=manual,
            missing_check=missing,
            changed_review_required=stale,
            retired_mapping=retired,
            automation_mapping_percent=round(automated / total * 100, 2) if total else 0.0,
            current_reviewed_automation_percent=(
                round(current / total * 100, 2) if total else 0.0
            ),
        )

    def _save_diff(
        self,
        current: StigBenchmarkMetadata,
        previous: StigBenchmarkMetadata | None,
        diff: StigDiff,
    ) -> Path:
        self.diff_root.mkdir(parents=True, exist_ok=True)
        old = previous.database_id if previous else "baseline"
        destination = self.diff_root / f"{old}-to-{current.database_id}.json"
        return export_stig_diff_json(diff, destination)

    @staticmethod
    def _from_record(record) -> StigBenchmarkMetadata:
        rules: list[StigRuleMetadata] = []
        for rule in record.rules:
            model = StigRuleMetadata(
                vuln_id=rule.vuln_id,
                rule_id=rule.rule_id or "",
                stig_id=rule.stig_id or "",
                group_id=rule.group_id or "",
                severity=rule.severity or "",
                title=rule.title or "",
                check_text=rule.check_text or "",
                fix_text=rule.fix_text or "",
                rule_fingerprint=rule.rule_fingerprint,
                check_fingerprint=rule.check_fingerprint or "",
                fix_fingerprint=rule.fix_fingerprint or "",
                field_fingerprints=dict(rule.field_fingerprints or {}),
                database_id=rule.id,
            )
            rules.append(model)
        return StigBenchmarkMetadata(
            database_id=record.id,
            source_filename=record.source_filename or "",
            source_sha256=record.source_sha256,
            family=record.family,
            benchmark_id=record.benchmark_id,
            title=record.title or "",
            version=record.version or "",
            release=record.release or "",
            release_info=record.release_info or "",
            release_date=record.release_date or "",
            imported_at=record.imported_at,
            benchmark_fingerprint=record.benchmark_fingerprint,
            rules=rules,
        )

    @staticmethod
    def _load_checks(root: str | Path) -> list[tuple[CheckDefinition, Path]]:
        path = Path(root)
        files = sorted(path.glob("*.yaml")) if path.is_dir() else [path]
        loaded: list[tuple[CheckDefinition, Path]] = []
        for item in files:
            library = load_check_library(item)
            loaded.extend((check, item) for check in library.checks)
        return loaded

    @classmethod
    def _matching_rules(
        cls, check: CheckDefinition, rules: Iterable[StigRuleMetadata]
    ) -> list[StigRuleMetadata]:
        return [rule for rule in rules if cls._check_matches_rule(check, rule)]

    @staticmethod
    def _check_matches_rule(check: CheckDefinition, rule: StigRuleMetadata) -> bool:
        for field_name in ("vuln_id", "rule_id", "stig_id"):
            check_value = normalize_identifier(getattr(check, field_name, ""))
            rule_value = normalize_identifier(getattr(rule, field_name, ""))
            if check_value and rule_value and check_value == rule_value:
                return True
        return False


__all__ = ["StigCoverage", "StigImportResult", "StigRepository"]
