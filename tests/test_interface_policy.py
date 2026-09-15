from __future__ import annotations

from tests.conftest import check_by_vuln, load_outputs, load_profile
from stig_audit_pro.core.check_engine import CheckEngine


def test_disabled_notconnect_ports_must_be_shutdown_and_unused_vlan_passes():
    engine = CheckEngine(load_profile())
    result = engine.evaluate(
        check_by_vuln("V-220667"),
        outputs=load_outputs("compliant"),
        ip="10.50.10.25",
    )

    assert result.status == "NotAFinding"
    assert not result.failed_objects
    assert {obj.object_name for obj in result.passed_objects} == {
        "GigabitEthernet1/0/2",
        "GigabitEthernet1/0/3",
    }


def test_disabled_notconnect_ports_must_be_shutdown_and_unused_vlan_fails():
    engine = CheckEngine(load_profile())
    result = engine.evaluate(
        check_by_vuln("V-220667"),
        outputs=load_outputs("noncompliant"),
        ip="10.50.10.26",
    )

    assert result.status == "Open"
    assert [obj.object_name for obj in result.failed_objects] == ["GigabitEthernet1/0/2"]
    assert "shutdown configured" in result.failed_objects[0].details
    assert "unused VLAN 999 assigned" in result.failed_objects[0].details
