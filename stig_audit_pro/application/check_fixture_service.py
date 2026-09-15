"""Run administrator-maintained check fixtures through the production evaluator."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from stig_audit_pro.core.check_engine import CheckEngine
from stig_audit_pro.core.models import CheckDefinition, SiteProfile


def command_filename(command: str) -> str:
    safe = "".join(character if character.isalnum() else "_" for character in command.lower())
    return "_".join(part for part in safe.split("_") if part) + ".txt"


@dataclass(frozen=True, slots=True)
class FixtureResult:
    name: str
    expected_status: str
    actual_status: str | None
    passed: bool
    message: str = ""
    fixture_path: Path | None = None


@dataclass(frozen=True, slots=True)
class CheckFixtureSummary:
    vuln_id: str
    results: tuple[FixtureResult, ...]

    @property
    def passed(self) -> bool:
        return bool(self.results) and all(item.passed for item in self.results)

    @property
    def complete(self) -> bool:
        statuses = {item.expected_status for item in self.results}
        return "NotAFinding" in statuses and "Open" in statuses


class CheckFixtureService:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def run_check(self, check: CheckDefinition, profile: SiteProfile) -> CheckFixtureSummary:
        directory = self.root / check.stig_family.lower() / check.vuln_id
        results: list[FixtureResult] = []
        if not directory.is_dir():
            return CheckFixtureSummary(check.vuln_id, ())
        for expected_path in sorted(directory.rglob("expected.json")):
            name = expected_path.parent.relative_to(directory).as_posix()
            try:
                expected = json.loads(expected_path.read_text(encoding="utf-8"))
                expected_status = str(expected["status"])
                outputs = {}
                for command in check.commands:
                    if command == "terminal length 0":
                        continue
                    output_path = expected_path.parent / command_filename(command)
                    if not output_path.is_file():
                        raise FileNotFoundError(f"Missing {output_path.name}")
                    outputs[command] = output_path.read_text(encoding="utf-8", errors="replace")
                actual = CheckEngine(profile).evaluate(check, outputs=outputs, ip="fixture", hostname="fixture")
                results.append(FixtureResult(name, expected_status, actual.status, actual.status == expected_status, "" if actual.status == expected_status else f"Expected {expected_status}; actual {actual.status}", expected_path.parent))
            except Exception as exc:
                results.append(FixtureResult(name, "unknown", None, False, str(exc), expected_path.parent))
        return CheckFixtureSummary(check.vuln_id, tuple(results))


__all__ = ["CheckFixtureService", "CheckFixtureSummary", "FixtureResult", "command_filename"]
