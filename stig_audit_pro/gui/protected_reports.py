"""Path-only workspace for encrypted Basic reports."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
from typing import Iterable


PROTECTED_SUFFIX = ".sapenc"
REPORT_TYPES = {".txt": "TXT", ".ckl": "CKL", ".csv": "CSV", ".html": "HTML", ".pdf": "PDF"}
TYPE_ORDER = {name: index for index, name in enumerate(("TXT", "CKL", "CSV", "HTML", "PDF"))}
IPV4_TARGET = re.compile(r"(?<!\d)(\d{1,3}(?:-\d{1,3}){3})-[0-9a-f]{12}(?:_|\.)", re.IGNORECASE)


@dataclass(frozen=True)
class ProtectedReportRef:
    """Operator-facing metadata derived without decrypting a report."""

    path: Path
    original_name: str
    device: str
    report_type: str


@dataclass(frozen=True)
class ImportBatch:
    added: int
    duplicates: int
    rejected: tuple[tuple[Path, str], ...]


def _report_ref(raw_path: str | Path) -> ProtectedReportRef:
    path = Path(raw_path).expanduser().resolve()
    if path.suffix.casefold() != PROTECTED_SUFFIX:
        raise ValueError("Choose a protected Basic report (.sapenc)")
    original_name = path.name[: -len(PROTECTED_SUFFIX)]
    original_suffix = Path(original_name).suffix.casefold()
    try:
        report_type = REPORT_TYPES[original_suffix]
    except KeyError as exc:
        raise ValueError("Unsupported protected report type") from exc

    match = IPV4_TARGET.search(original_name)
    if match:
        candidate = match.group(1).replace("-", ".")
        try:
            device = str(ipaddress.ip_address(candidate))
        except ValueError:
            device = Path(original_name).stem
    else:
        device = Path(original_name).stem
    return ProtectedReportRef(path=path, original_name=original_name, device=device, report_type=report_type)


class ProtectedReportWorkspace:
    """Track protected paths and selector metadata without reading plaintext."""

    def __init__(self) -> None:
        self._reports: list[ProtectedReportRef] = []
        self._paths: set[Path] = set()

    def add(self, paths: Iterable[str | Path]) -> ImportBatch:
        added = 0
        duplicates = 0
        rejected: list[tuple[Path, str]] = []
        for raw_path in paths:
            candidate = Path(raw_path).expanduser().resolve()
            if candidate in self._paths:
                duplicates += 1
                continue
            try:
                report = _report_ref(candidate)
            except ValueError as exc:
                rejected.append((candidate, str(exc)))
                continue
            self._reports.append(report)
            self._paths.add(report.path)
            added += 1
        return ImportBatch(added=added, duplicates=duplicates, rejected=tuple(rejected))

    def clear(self) -> None:
        self._reports.clear()
        self._paths.clear()

    def reports(self) -> tuple[ProtectedReportRef, ...]:
        return tuple(self._reports)

    def devices(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(report.device for report in self._reports))

    def _options(self, device: str) -> tuple[tuple[str, ProtectedReportRef], ...]:
        reports = [report for report in self._reports if report.device == device]
        reports.sort(key=lambda report: (TYPE_ORDER.get(report.report_type, 99), report.original_name.casefold()))
        counts: dict[str, int] = {}
        for report in reports:
            counts[report.report_type] = counts.get(report.report_type, 0) + 1

        used: dict[str, int] = {}
        options: list[tuple[str, ProtectedReportRef]] = []
        for report in reports:
            label = report.report_type
            if counts[report.report_type] > 1:
                label = f"{report.report_type} — {report.original_name}"
            used[label] = used.get(label, 0) + 1
            if used[label] > 1:
                label = f"{label} ({used[label]})"
            options.append((label, report))
        return tuple(options)

    def type_options(self, device: str) -> tuple[str, ...]:
        return tuple(label for label, _report in self._options(device))

    def resolve(self, device: str, type_option: str) -> ProtectedReportRef:
        for label, report in self._options(device):
            if label == type_option:
                return report
        raise KeyError(f"No imported {type_option} report for {device}")
