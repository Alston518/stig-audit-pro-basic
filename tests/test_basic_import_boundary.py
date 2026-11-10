"""Basic keeps Live SSH while excluding Pro-only and other network clients."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRO_ONLY = (
    "stig_audit_pro.gui.main_window",
    "stig_audit_pro.application.run_service",
    "stig_audit_pro.stig.source_manager",
    "stig_audit_pro.reports.excel_writer",
    "stig_audit_pro.infrastructure.persistence",
)
UNAPPROVED_NETWORK = (
    "requests", "urllib.request", "http.client", "ftplib", "smtplib",
    "telnetlib", "xmlrpc.client", "xmlrpc.server",
)


def test_importing_basic_does_not_load_pro_only_modules():
    code = (
        "import sys; import stig_audit_pro.basic_app; "
        "print('\\n'.join(sorted(sys.modules)))"
    )
    result = subprocess.run([sys.executable, "-c", code], cwd=ROOT,
                            capture_output=True, text=True, check=True)
    loaded = set(result.stdout.splitlines())
    assert not [name for name in PRO_ONLY if any(
        module == name or module.startswith(name + ".") for module in loaded
    )]


def test_basic_entrypoint_imports_no_unapproved_network_client():
    paths = [ROOT / "app.py", ROOT / "stig_audit_pro/basic_app.py"]
    offenders = []
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8-sig"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if any(name == banned or name.startswith(banned + ".") for banned in UNAPPROVED_NETWORK):
                    offenders.append(f"{path.name}:{node.lineno} {name}")
    assert not offenders, "Unapproved Basic network imports: " + ", ".join(offenders)
