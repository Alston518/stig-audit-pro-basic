from __future__ import annotations

import json

from stig_audit_pro.core.models import AuditRun
from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.reports.json_writer import build_json_report, write_json_report


def _result(status: str = "Open") -> CheckResult:
    return CheckResult(
        ip="192.0.2.10", hostname="sw1", vuln_id="V-1", rule_id="SV-1",
        stig_id="CISC-1", stig_family="IOSXE_L2", title="Test",
        severity="medium", status=status, commands_used=["show version"],
        evidence_artifact_ids=[7], evaluation_reason="Expected text was absent.",
    )


def test_json_report_has_stable_schema_and_evidence_references(tmp_path):
    run = AuditRun(device_count=1, profile_name="site")
    artifact = {
        "artifact_id": 7, "command": "show version",
        "relative_path": "devices/sw1/evidence/show_version.txt",
        "sha256": "a" * 64, "byte_length": 42,
    }
    report = build_json_report([_result()], audit_run=run, evidence_artifacts=[artifact])
    assert report["schema_version"] == 1
    assert report["audit"]["run_id"] == run.run_id
    assert report["summary"]["open"] == 1
    assert report["results"][0]["evidence_artifact_ids"] == [7]
    assert report["evidence"][0]["sha256"] == "a" * 64
    assert "raw_output" not in json.dumps(report)

    path = write_json_report([_result()], tmp_path / "audit.json", audit_run=run)
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == 1
