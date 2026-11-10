from __future__ import annotations

import subprocess
import sys


def test_imported_pattern_cannot_stall_evaluation():
    code = '''
from stig_audit_pro.core.check_engine import CheckEngine
from stig_audit_pro.core.models import CheckDefinition
from stig_audit_pro.core.yaml_loader import load_profile
profile = load_profile("data/profiles/base_iosxe_access.yaml")
check = CheckDefinition(vuln_id="V-1", title="regex", stig_family="IOSXE_L2", severity="cat2", check_type="command_regex", commands=["show version"], conditions={"pattern": "(a+)+$", "command": "show version"})
print(CheckEngine(profile).evaluate(check, {"show version": "a" * 4000 + "!"}, "192.0.2.10").status)
'''
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "Error"
