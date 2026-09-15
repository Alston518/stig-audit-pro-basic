from __future__ import annotations

import json
from pathlib import Path

from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.stig.ckl_writer import CklAsset
from stig_audit_pro.stig.cklb_writer import (
    import_cklb_results,
    load_cklb,
    write_completed_cklb,
)


FIXTURE = Path(__file__).parent / "fixtures" / "representative.cklb"


def test_representative_cklb_import_and_population_round_trip(tmp_path):
    template = load_cklb(FIXTURE)
    assert template["cklb_version"] == "1.0"
    imported = import_cklb_results(FIXTURE)
    assert imported[0].vuln_id == "V-220665"
    assert imported[0].rule_id == "SV-220665r1_rule"
    assert imported[0].status == "Not_Reviewed"

    result = CheckResult(
        ip="192.0.2.20", hostname="sw-new", vuln_id="V-220665",
        rule_id="SV-220665r1_rule", stig_id="CISC-L2-000010",
        stig_family="IOSXE_L2", title="Test rule", severity="medium",
        status="NotAFinding", finding_details="Required state is present.",
        comments="Automated and reviewed.",
    )
    summary = write_completed_cklb(
        FIXTURE, tmp_path / "completed.cklb", [result],
        CklAsset("192.0.2.20", "sw-new", "192.0.2.20", "sw-new.example.test"),
    )
    payload = json.loads(summary.path.read_text(encoding="utf-8"))
    rule = payload["stigs"][0]["rules"][0]
    assert rule["status"] == "not_a_finding"
    assert rule["finding_details"] == "Required state is present."
    assert payload["target_data"]["host_name"] == "sw-new"
    assert "Existing assessor note" in rule["comments"]
    assert summary.updated_vuln_ids == ("V-220665",)
