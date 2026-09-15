from __future__ import annotations

from stig_audit_pro.application.run_comparison import RunChange, compare_runs
from stig_audit_pro.core.result_model import CheckResult


def _result(vuln: str, status: str, ip: str = "192.0.2.1") -> CheckResult:
    return CheckResult(
        ip=ip, hostname="sw1", vuln_id=vuln, stig_family="IOSXE_L2",
        title=vuln, severity="medium", status=status,
    )


def test_run_comparison_classifies_findings_and_applicability():
    previous = [
        _result("V-1", "Open"), _result("V-2", "Open"),
        _result("V-3", "NotAFinding"), _result("V-4", "Not_Applicable"),
        _result("V-5", "NotAFinding"), _result("V-6", "Open"),
    ]
    current = [
        _result("V-1", "NotAFinding"), _result("V-2", "Open"),
        _result("V-3", "Open"), _result("V-4", "NotAFinding"),
        _result("V-5", "NotAFinding"), _result("V-7", "Open"),
    ]
    comparison = compare_runs(previous, current)
    classes = {item.vuln_id: item.classification for item in comparison.items}
    assert classes == {
        "V-1": RunChange.RESOLVED,
        "V-2": RunChange.PERSISTENT_FINDING,
        "V-3": RunChange.NEW_FINDING,
        "V-4": RunChange.NEWLY_APPLICABLE,
        "V-5": RunChange.UNCHANGED_PASS,
        "V-6": RunChange.NO_LONGER_APPLICABLE,
        "V-7": RunChange.NEWLY_APPLICABLE,
    }
    assert comparison.summary["new"] == 1
    assert comparison.summary["resolved"] == 1


def test_changed_stig_rule_fingerprint_is_not_comparable():
    comparison = compare_runs(
        [_result("V-1", "Open")], [_result("V-1", "NotAFinding")],
        previous_rule_fingerprints={"V-1": "old"},
        current_rule_fingerprints={"V-1": "new"},
    )
    assert comparison.items[0].classification == RunChange.NOT_COMPARABLE
    assert "fingerprint" in comparison.items[0].reason
