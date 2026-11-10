"""Fail a Basic build containing Pro services or non-SSH network clients."""

from __future__ import annotations

import ast
import sys
from pathlib import Path


FORBIDDEN = (
    "stig_audit_pro.gui.main_window",
    "stig_audit_pro.application.run_service",
    "stig_audit_pro.application.backup_service",
    "stig_audit_pro.stig.source_manager",
    "stig_audit_pro.infrastructure.persistence",
    "stig_audit_pro.reports.excel_writer",
    "sqlalchemy", "openpyxl", "requests", "urllib.request",
    "http.client", "http.server", "ftplib", "smtplib", "xmlrpc.client",
    "xmlrpc.server",
)


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "build/ci-work")
    analysis_path = root / "STIG Audit Basic" / "Analysis-00.toc"
    if not analysis_path.is_file():
        raise SystemExit(f"Missing Basic build analysis: {analysis_path}")
    analysis = ast.literal_eval(analysis_path.read_text(encoding="utf-8"))
    offenders: set[str] = set()
    for section in analysis:
        if not isinstance(section, list):
            continue
        for entry in section:
            if not isinstance(entry, tuple) or len(entry) < 3:
                continue
            name, _, kind = entry[:3]
            if kind not in {"PYMODULE", "PYSOURCE", "EXTENSION", "BINARY"} or not isinstance(name, str):
                continue
            if any(name == forbidden or name.startswith(forbidden + ".") for forbidden in FORBIDDEN):
                offenders.add(name)
    if offenders:
        sample = ", ".join(sorted(offenders)[:30])
        raise SystemExit(f"{len(offenders)} forbidden Basic bundle modules: {sample}")
    print("Basic bundle contains only approved Live SSH network code and no Pro services.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
