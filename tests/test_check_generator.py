from __future__ import annotations

from stig_audit_pro.core.models import CheckDefinition
from stig_audit_pro.stig.check_generator import build_manual_starter_library, write_manual_starter_library
from stig_audit_pro.stig.xccdf_importer import parse_xccdf_file
from tests.conftest import PROJECT_ROOT


def test_build_manual_starter_library_from_stig_metadata():
    metadata = parse_xccdf_file(PROJECT_ROOT / "tests" / "fixtures" / "sample_xccdf.xml", family="IOSXE_L2")

    library = build_manual_starter_library([metadata], existing_checks=[])

    assert library.library_name == "generated_stig_manual_starters"
    assert len(library.checks) == 1
    check = library.checks[0]
    assert check.vuln_id == "V-123456"
    assert check.stig_id == "CISC-L2-000210"
    assert check.group_id == "V-123456"
    assert check.rule_id == "SV-123456r1_rule"
    assert check.severity == "cat2"
    assert check.automated is False
    assert check.check_type == "manual_review"
    assert check.result.fail_status == "Not_Reviewed"


def test_build_manual_starter_library_skips_existing_automation():
    metadata = parse_xccdf_file(PROJECT_ROOT / "tests" / "fixtures" / "sample_xccdf.xml", family="IOSXE_L2")
    existing = CheckDefinition(
        vuln_id="V-123456",
        title="Existing automated check",
        stig_family="IOSXE_L2",
        severity="cat2",
        automated=True,
        check_type="command_contains",
        commands=["show running-config"],
        conditions={"command": "show running-config", "contains": "hostname"},
    )

    library = build_manual_starter_library([metadata], existing_checks=[existing])

    assert library.checks == []


def test_write_manual_starter_library(tmp_path):
    metadata = parse_xccdf_file(PROJECT_ROOT / "tests" / "fixtures" / "sample_xccdf.xml", family="IOSXE_L2")
    library = build_manual_starter_library([metadata], existing_checks=[])
    path = write_manual_starter_library(library, tmp_path / "generated_stig_manual.yaml")

    text = path.read_text(encoding="utf-8")
    assert "generated_stig_manual_starters" in text
    assert "V-123456" in text
    assert "Not_Reviewed" in text
