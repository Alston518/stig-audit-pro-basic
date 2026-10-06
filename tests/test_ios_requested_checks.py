from pathlib import Path

import pytest

from stig_audit_pro.core.check_engine import CheckEngine
from stig_audit_pro.core.yaml_loader import load_check_library, load_profile


DATA = Path(__file__).resolve().parents[1] / "data"
PROFILE = load_profile(DATA / "profiles" / "base_ios_switch_access.yaml")


def check_from(library: str, vuln_id: str):
    return next(
        check
        for check in load_check_library(DATA / "checks" / f"{library}.yaml").checks
        if check.vuln_id == vuln_id
    )


def status(check, command: str, output: str, profile=PROFILE) -> str:
    return CheckEngine(profile).evaluate(check, {command: output}, ip="192.0.2.1").status


def test_ios_l2_qos_requires_global_mls_qos():
    check = check_from("ios_l2", "V-220625")
    assert check.automated
    assert status(check, "show running-config", "hostname switch\nmls qos\n") == "NotAFinding"
    assert status(check, "show running-config", "hostname switch\n") == "Open"


@pytest.mark.parametrize(
    ("vuln_id", "setting"),
    [
        ("V-220589", "min-length 15"),
        ("V-220590", "upper-case 1"),
        ("V-220591", "lower-case 1"),
        ("V-220592", "numeric-count 1"),
        ("V-220593", "special-case 1"),
        ("V-220594", "char-changes 8"),
    ],
)
def test_ios_password_setting_must_be_under_selected_policy(vuln_id, setting):
    check = check_from("ios_ndm", vuln_id)
    assert check.automated
    correct = f"aaa common-criteria policy {PROFILE.variables['local_password_policy']}\n {setting}\n"
    wrong_policy = f"aaa common-criteria policy OTHER_POLICY\n {setting}\n"
    assert status(check, "show running-config", correct) == "NotAFinding"
    assert status(check, "show running-config", wrong_policy) == "Open"
    assert status(check, "show running-config", "hostname switch\n") == "Open"


def test_ios_version_uses_configured_approved_release():
    check = check_from("ios_ndm", "V-220621")
    assert PROFILE.variables["supported_ios_versions"] == []
    approved_profile = PROFILE.model_copy(deep=True)
    approved_profile.variables["supported_ios_versions"] = ["15.2(7)E14"]
    assert status(check, "show version", "Cisco IOS Software, Version 15.2(7)E14, RELEASE SOFTWARE\n", approved_profile) == "NotAFinding"
    assert status(check, "show version", "Cisco IOS Software, Version 15.2(7)E13, RELEASE SOFTWARE\n", approved_profile) == "Open"
    assert status(check, "show version", "Cisco IOS Software, Version 15.2(7)E14a, RELEASE SOFTWARE\n", approved_profile) == "Open"
