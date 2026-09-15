from __future__ import annotations

from datetime import datetime, timezone

from stig_audit_pro.core.result_model import CheckResult, FindingObject
from stig_audit_pro.reports.audit_report import build_text_report, write_csv_report, write_text_report


def sample_results() -> list[CheckResult]:
    return [
        CheckResult(
            ip="10.50.10.26",
            hostname="SW-ACCESS-02",
            vuln_id="V-220667",
            stig_family="IOSXE_L2",
            title="Disabled interfaces must be shutdown and assigned to the unused VLAN",
            severity="medium",
            status="Open",
            failed_objects=[FindingObject(object_type="interface", object_name="GigabitEthernet1/0/2", details="access_vlan=10")],
            finding_details="Failed interface GigabitEthernet1/0/2",
            comments="Open finding.",
            commands_used=["show running-config", "show interfaces status"],
        ),
        CheckResult(
            ip="10.50.10.26",
            hostname="SW-ACCESS-02",
            vuln_id="V-220529",
            stig_family="IOSXE_L2",
            title="ACL deny statements must include log-input",
            severity="medium",
            status="NotAFinding",
            passed_objects=[FindingObject(object_type="acl_statement", object_name="USER-IN")],
            commands_used=["show ip access-lists"],
        ),
    ]


def test_build_text_report_includes_summary_and_findings():
    report = build_text_report(
        sample_results(),
        generated_at=datetime(2026, 7, 6, 12, 0, tzinfo=timezone.utc),
    )

    assert "STIG Audit Pro Scan Report" in report
    assert "Devices               : 1" in report
    assert "[FAIL]   Open                    1" in report
    assert "[PASS]   Not a Finding           1" in report
    assert "GigabitEthernet1/0/2" in report
    assert "V-220667" in report
    assert "[FAIL] OPEN" in report
    assert "[PASS] NOT A FINDING" in report
    assert "CHECK 1 OF 2" in report
    assert "CHECK 2 OF 2" in report
    assert "DETAILED CHECK RESULTS" in report
    assert report.count("=" * 88) == 4


def test_report_writers_create_txt_and_csv(tmp_path):
    txt_path = tmp_path / "audit-report.txt"
    csv_path = tmp_path / "audit-results.csv"

    write_text_report(sample_results(), txt_path)
    write_csv_report(sample_results(), csv_path)

    assert "OPEN FINDINGS - QUICK VIEW" in txt_path.read_text(encoding="utf-8")
    csv_text = csv_path.read_text(encoding="utf-8-sig")
    assert "ip,hostname,vuln_id" in csv_text
    assert "10.50.10.26" in csv_text
    assert "V-220667" in csv_text
