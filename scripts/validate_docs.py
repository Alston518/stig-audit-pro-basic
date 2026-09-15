"""Validate required v0.2 documentation and local Markdown links."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "docs/INDEX.md",
    "docs/architecture/ARCHITECTURE.md",
    "docs/architecture/DATA_MODEL.md",
    "docs/architecture/SCAN_LIFECYCLE.md",
    "docs/operator/GETTING_STARTED.md",
    "docs/operator/FILES_AND_FOLDERS.md",
    "docs/operator/FIRST_AUDIT.md",
    "docs/operator/DEVICE_MANAGEMENT.md",
    "docs/operator/SITE_PROFILES.md",
    "docs/operator/RUNNING_AN_AUDIT.md",
    "docs/operator/REVIEWING_FINDINGS.md",
    "docs/operator/MANUAL_REVIEWS.md",
    "docs/operator/TROUBLESHOOTING.md",
    "docs/CURRENT_LIMITATIONS.md",
    "docs/FEATURE_PRESERVATION_INVENTORY.md",
    "docs/operator/ADMINISTRATOR_GUIDE.md",
    "docs/operator/REPORTING_GUIDE.md",
    "docs/operator/STIG_UPDATE_GUIDE.md",
    "docs/operator/STIG_DIFF_GUIDE.md",
    "docs/operator/AUDIT_HISTORY_GUIDE.md",
    "docs/developers/DEVELOPMENT_SETUP.md",
    "docs/developers/CHECK_AUTHORING_GUIDE.md",
    "docs/developers/PARSER_AUTHORING_GUIDE.md",
    "docs/developers/TESTING_GUIDE.md",
    "docs/developers/DATABASE_GUIDE.md",
    "docs/assurance/SECURITY_BOUNDARY.md",
    "docs/assurance/COMMAND_REFERENCE.md",
    "docs/assurance/EVIDENCE_HANDLING.md",
    "docs/assurance/STIG_TRACEABILITY.md",
    "docs/assurance/THREAT_MODEL.md",
    "docs/releases/CHANGELOG.md",
    "docs/releases/V0.2_ENTERPRISE_READINESS_REPORT.md",
    "docs/architecture/diagrams/component.puml",
    "docs/architecture/diagrams/audit_sequence.puml",
    "docs/architecture/diagrams/stig_import_diff_sequence.puml",
    "docs/architecture/diagrams/data_model.puml",
)
LINK = re.compile(r"\[[^]]+\]\((?!https?://|mailto:|#)([^)]+)\)")


def main() -> int:
    errors: list[str] = []
    for relative in REQUIRED:
        path = ROOT / relative
        if not path.is_file() or not path.read_text(encoding="utf-8").strip():
            errors.append(f"Missing or empty required document: {relative}")
    for path in [ROOT / "README.md", *ROOT.joinpath("docs").rglob("*.md")]:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for match in LINK.finditer(text):
            target = match.group(1).split("#", 1)[0].strip("<>")
            if not target or target.startswith("/") or " " in target and not target.startswith("../"):
                continue
            if not (path.parent / target).resolve().exists():
                errors.append(f"Broken local link in {path.relative_to(ROOT)}: {target}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Validated {len(REQUIRED)} required documentation files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
