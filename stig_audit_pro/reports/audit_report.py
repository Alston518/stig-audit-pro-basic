"""Plain text and CSV audit report writers."""

from __future__ import annotations

import csv
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from textwrap import TextWrapper

from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.reports.spreadsheet_safety import safe_spreadsheet_row

REPORT_STATUSES = ("NotAFinding", "Open", "Error", "Skipped", "Not_Applicable", "Not_Reviewed")
REPORT_WIDTH = 88
STATUS_DISPLAY = {
    "NotAFinding": ("PASS", "Not a Finding"),
    "Open": ("FAIL", "Open"),
    "Error": ("ERROR", "Error"),
    "Skipped": ("SKIP", "Skipped"),
    "Not_Applicable": ("N/A", "Not Applicable"),
    "Not_Reviewed": ("REVIEW", "Not Reviewed"),
}
STATUS_PRIORITY = {
    "Open": 0,
    "Error": 1,
    "Not_Reviewed": 2,
    "Skipped": 3,
    "Not_Applicable": 4,
    "NotAFinding": 5,
}


def build_text_report(
    results: list[CheckResult],
    generated_at: datetime | None = None,
    title: str = "STIG Audit Pro Scan Report",
) -> str:
    generated = generated_at or datetime.now(timezone.utc)
    status_counts = Counter(result.status for result in results)
    device_keys = {(result.ip, result.hostname) for result in results}
    scorable = status_counts["NotAFinding"] + status_counts["Open"] + status_counts["Error"]
    compliance = round((status_counts["NotAFinding"] / scorable) * 100) if scorable else 0

    lines = _banner(title)
    lines.extend(
        [
            _field("Generated", generated.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")),
            _field("Devices", str(len(device_keys))),
            _field("Checks", str(len(results))),
            _field("Automated compliance", f"{compliance}%"),
            "",
            *_section("STATUS SUMMARY"),
        ]
    )
    for status in REPORT_STATUSES:
        marker, label = STATUS_DISPLAY[status]
        tag = f"[{marker}]"
        lines.append(f"{tag:<9}{label:<20}{status_counts[status]:>5}")

    lines.extend(["", *_section("DEVICE SUMMARY")])
    if results:
        for key, device_results in _group_by_device(results).items():
            device_counts = Counter(result.status for result in device_results)
            ip, hostname = key
            host_text = hostname if hostname and hostname != "unknown" else "unknown"
            device_scorable = (
                device_counts["NotAFinding"]
                + device_counts["Open"]
                + device_counts["Error"]
            )
            device_compliance = (
                round((device_counts["NotAFinding"] / device_scorable) * 100)
                if device_scorable
                else 0
            )
            lines.extend(
                [
                    f"{host_text} ({ip})",
                    (
                        f"  Checks: {len(device_results)}  |  Compliance: {device_compliance}%  |  "
                        f"[PASS] {device_counts['NotAFinding']}  "
                        f"[FAIL] {device_counts['Open']}  "
                        f"[ERROR] {device_counts['Error']}  "
                        f"[REVIEW] {device_counts['Not_Reviewed']}"
                    ),
                ]
            )
    else:
        lines.append("No results.")

    lines.extend(["", *_section("OPEN FINDINGS - QUICK VIEW")])
    open_results = [result for result in results if result.status == "Open"]
    if open_results:
        for result in open_results:
            lines.extend(
                _wrap_text(
                    f"[FAIL] {result.ip} | {result.vuln_id} | "
                    f"{result.severity.upper()} | {result.title}",
                    initial_indent="",
                    subsequent_indent="       ",
                )
            )
    else:
        lines.append("None")

    lines.extend(["", *_section("DETAILED CHECK RESULTS")])
    if results:
        lines.append("Checks are grouped by device; findings and errors are listed first.")
        ordered_results = sorted(
            results,
            key=lambda result: (
                result.ip,
                result.hostname,
                STATUS_PRIORITY.get(result.status, 99),
                result.vuln_id,
            ),
        )
        for index, result in enumerate(ordered_results, start=1):
            lines.extend(_check_block(result, index=index, total=len(ordered_results)))
    else:
        lines.append("No checks to display.")

    return "\n".join(lines).rstrip() + "\n"


def write_text_report(results: list[CheckResult], path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(build_text_report(results), encoding="utf-8")
    return destination


def write_csv_report(results: list[CheckResult], path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "ip",
                "hostname",
                "vuln_id",
                "stig_family",
                "severity",
                "status",
                "title",
                "failed_objects",
                "passed_objects",
                "comments",
                "finding_details",
                "commands_used",
                "timestamp",
            ],
        )
        writer.writeheader()
        for result in results:
            writer.writerow(
                safe_spreadsheet_row({
                    "ip": result.ip,
                    "hostname": result.hostname,
                    "vuln_id": result.vuln_id,
                    "stig_family": result.stig_family,
                    "severity": result.severity,
                    "status": result.status,
                    "title": result.title,
                    "failed_objects": _objects_to_text(result.failed_objects),
                    "passed_objects": _objects_to_text(result.passed_objects),
                    "comments": result.comments,
                    "finding_details": result.finding_details,
                    "commands_used": "; ".join(result.commands_used),
                    "timestamp": result.timestamp.isoformat(),
                })
            )
    return destination


def _group_by_device(results: list[CheckResult]) -> dict[tuple[str, str], list[CheckResult]]:
    grouped: dict[tuple[str, str], list[CheckResult]] = defaultdict(list)
    for result in results:
        grouped[(result.ip, result.hostname)].append(result)
    return dict(sorted(grouped.items(), key=lambda item: item[0]))


def _banner(title: str) -> list[str]:
    border = "=" * REPORT_WIDTH
    return [border, title.center(REPORT_WIDTH), border]


def _section(title: str) -> list[str]:
    return [title, "-" * REPORT_WIDTH]


def _field(label: str, value: str) -> str:
    return f"{label:<22}: {value}"


def _check_block(result: CheckResult, *, index: int, total: int) -> list[str]:
    marker, status_label = STATUS_DISPLAY.get(result.status, ("?", result.status))
    hostname = result.hostname if result.hostname and result.hostname != "unknown" else "unknown"
    lines = [
        "",
        "=" * REPORT_WIDTH,
        f"CHECK {index} OF {total}   [{marker}] {status_label.upper()}",
        "-" * REPORT_WIDTH,
        _field("Device", f"{hostname} ({result.ip})"),
        _field("Vulnerability", result.vuln_id),
        _field("Severity", result.severity.upper()),
        _field("STIG family", result.stig_family),
    ]
    lines.extend(_labeled_text("Title", result.title or "Untitled check"))

    if result.failed_objects:
        lines.extend(_object_lines("Failed objects", result.failed_objects))
    if result.passed_objects:
        lines.extend(_object_lines("Passed objects", result.passed_objects))

    details = result.finding_details.strip()
    if details:
        lines.extend(_labeled_text("Finding details", details))
    comments = result.comments.strip()
    if comments and comments != details:
        lines.extend(_labeled_text("Comments", comments))
    if result.error_message:
        lines.extend(_labeled_text("Error message", result.error_message.strip()))
    if result.parser_warnings:
        lines.extend(_list_lines("Parser warnings", result.parser_warnings))
    if result.commands_used:
        lines.extend(_list_lines("Commands used", result.commands_used))
    if not any(
        (
            result.failed_objects,
            result.passed_objects,
            details,
            comments,
            result.error_message,
            result.parser_warnings,
            result.commands_used,
        )
    ):
        lines.append(_field("Evidence", "No details captured."))
    return lines


def _labeled_text(label: str, value: str) -> list[str]:
    prefix = f"{label:<22}: "
    return _wrap_text(value, initial_indent=prefix, subsequent_indent=" " * len(prefix))


def _list_lines(label: str, values: list[str]) -> list[str]:
    lines = [f"{label:<22}:"]
    for value in values:
        lines.extend(_wrap_text(value, initial_indent="  - ", subsequent_indent="    "))
    return lines


def _object_lines(label: str, objects: object) -> list[str]:
    values = [
        f"{obj.object_type}: {obj.object_name}"
        + (f" ({obj.details})" if obj.details else "")
        for obj in objects
    ]
    return _list_lines(label, values)


def _wrap_text(value: str, *, initial_indent: str, subsequent_indent: str) -> list[str]:
    wrapper = TextWrapper(
        width=REPORT_WIDTH,
        initial_indent=initial_indent,
        subsequent_indent=subsequent_indent,
        replace_whitespace=False,
        drop_whitespace=True,
        break_long_words=False,
        break_on_hyphens=False,
    )
    output: list[str] = []
    for paragraph in value.splitlines() or [""]:
        output.extend(wrapper.wrap(paragraph) or [initial_indent.rstrip()])
        wrapper.initial_indent = subsequent_indent
    return output


def _objects_to_text(objects: object) -> str:
    return "; ".join(
        f"{obj.object_type}:{obj.object_name}" + (f" ({obj.details})" if obj.details else "")
        for obj in objects
    )
