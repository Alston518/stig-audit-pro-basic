from __future__ import annotations

from stig_audit_pro.core.check_engine import CheckEngine
from stig_audit_pro.core.models import CheckDefinition
from stig_audit_pro.core.result_model import DecisionState
from tests.conftest import load_profile


def _check(check_type: str, *, commands: list[str] | None = None, **kwargs) -> CheckDefinition:
    return CheckDefinition(
        vuln_id="V-INTEGRITY",
        title="Integrity test",
        stig_family="L2",
        severity="CAT II",
        check_type=check_type,
        commands=commands or ["show running-config"],
        **kwargs,
    )


def test_empty_output_is_evidence_error_even_when_error_mapping_is_misconfigured():
    check = _check(
        "command_not_contains",
        conditions={"contains": "no service password-encryption"},
        result={"error_status": "NotAFinding"},
    )

    result = CheckEngine(load_profile()).evaluate(
        check, outputs={"show running-config": ""}, ip="192.0.2.10"
    )

    assert result.status == "Error"
    assert result.automated_status == "Error"
    assert result.decision_state is DecisionState.EVIDENCE_ERROR
    assert "empty" in (result.error_message or "").lower()


def test_cli_invalid_command_marker_is_evidence_error():
    check = _check("command_contains", conditions={"contains": "hostname"})

    result = CheckEngine(load_profile()).evaluate(
        check,
        outputs={"show running-config": "% Invalid input detected at '^' marker."},
        ip="192.0.2.10",
    )

    assert result.status == "Error"
    assert result.decision_state is DecisionState.EVIDENCE_ERROR


def test_manual_review_stays_not_reviewed_without_command_evidence():
    check = _check("manual_review", commands=[])

    result = CheckEngine(load_profile()).evaluate(check, outputs={}, ip="192.0.2.10")

    assert result.status == "Not_Reviewed"
    assert result.automated_status == "Not_Reviewed"
    assert result.decision_state is DecisionState.MANUAL_REVIEW


def test_empty_trunk_scope_is_not_a_pass():
    check = _check("trunk_vlan_policy", conditions={"all": []})

    result = CheckEngine(load_profile()).evaluate(
        check, outputs={"show running-config": "hostname SW1\n"}, ip="192.0.2.10"
    )

    assert result.status == "Not_Applicable"
    assert result.decision_state is DecisionState.NOT_APPLICABLE


def test_supported_compliant_command_still_passes():
    check = _check("command_contains", conditions={"contains": "hostname"})

    result = CheckEngine(load_profile()).evaluate(
        check,
        outputs={"show running-config": "hostname SW1\n"},
        ip="192.0.2.10",
    )

    assert result.status == "NotAFinding"
    assert result.automated_status == "NotAFinding"
    assert result.decision_state is DecisionState.PASS
