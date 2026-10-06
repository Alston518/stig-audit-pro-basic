from pathlib import Path

import pytest

from stig_audit_pro.core.check_engine import CheckEngine
from stig_audit_pro.core.yaml_loader import load_check_library, load_profile


DATA = Path(__file__).resolve().parents[1] / "data"
PROFILE = load_profile(DATA / "profiles" / "base_ios_switch_access.yaml")


def get_check(library: str, vuln_id: str):
    return next(
        check
        for check in load_check_library(DATA / "checks" / f"{library}.yaml").checks
        if check.vuln_id == vuln_id
    )


def evaluate(library: str, vuln_id: str, outputs: dict[str, str]):
    return CheckEngine(PROFILE).evaluate(get_check(library, vuln_id), outputs, ip="192.0.2.1")


def test_ios_ntp_md5_authentication_is_always_open():
    first = "ntp authentication-key 475 md5 15431A0D1E0A1C171060302610 7"
    second = "ntp authentication-key 525 md5 005502071E091C151762696A2A 7"
    assert evaluate("ios_ndm", "V-220606", {"show running-config": f"{first}\n{second}\n"}).status == "Open"
    assert evaluate("ios_ndm", "V-220606", {"show running-config": f"{first}\n"}).status == "Open"
    assert evaluate("ios_ndm", "V-220606", {"show running-config": f"{first}\n{second[:-2]} 6\n"}).status == "Open"
    assert evaluate("ios_ndm", "V-220606", {"show running-config": "ntp authentication-key 99 md5 secret 7\n"}).status == "Open"
    assert evaluate("ios_ndm", "V-220606", {"show running-config": "hostname switch\n"}).status == "Open"
    assert evaluate("ios_ndm", "V-220606", {"show running-config": "ntp authentication-key 99 sha256 secret\n"}).status == "Not_Reviewed"


def test_ios_ntp_sources_require_two_profile_defined_servers():
    servers = PROFILE.variables["ntp_servers"]
    assert len(servers) >= 2
    both = "\n".join(f"ntp server {server}" for server in servers) + "\n"
    one = f"ntp server {servers[0]}\n"
    different = f"ntp server {servers[0]}\nntp server 192.0.2.99\n"
    assert evaluate("ios_ndm", "V-220601", {"show running-config": both}).status == "NotAFinding"
    assert evaluate("ios_ndm", "V-220601", {"show running-config": one}).status == "Open"
    assert evaluate("ios_ndm", "V-220601", {"show running-config": different}).status == "Open"


def test_ios_backup_check_uses_catalyst_center_tailoring():
    result = evaluate("ios_ndm", "V-220618", {})
    assert result.status == "NotAFinding"
    assert "Cisco Catalyst Center" in result.comments


def test_ios_certificate_check_is_temporarily_not_applicable():
    result = evaluate("ios_ndm", "V-220619", {})
    assert result.status == "Not_Applicable"
    assert "default" in result.comments.lower()


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("service timestamps log datetime msec localtime", "NotAFinding"),
        ("service timestamps log datetime msec localtime show-timezone year", "NotAFinding"),
        ("service timestamps log datetime msec localtime something else", "NotAFinding"),
        ("service timestamps log datetime localtime", "Open"),
    ],
)
def test_ios_log_timestamp_allows_any_suffix_after_required_prefix(line, expected):
    assert evaluate("ios_ndm", "V-220580", {"show running-config": line + "\n"}).status == expected


@pytest.mark.parametrize("vuln_id", ("V-220583", "V-220584", "V-220585"))
def test_ios_persistent_logging_privilege_is_conditional(vuln_id):
    cases = (
        ("hostname switch\n", "Not_Applicable"),
        ("no logging persistent\nfile privilege 5\n", "Not_Applicable"),
        ("logging persistent\nfile privilege 15\n", "NotAFinding"),
        ("logging persistent\nfile privilege 5\n", "Open"),
        ("logging persistent\n", "Open"),
        ("logging persistent\nfile privilege 15\nfile privilege 5\n", "Open"),
    )
    for config, expected in cases:
        assert evaluate("ios_ndm", vuln_id, {"show running-config": config}).status == expected


def cdp_neighbor(name: str) -> str:
    return (
        f"Device ID: {name}\n"
        "Platform: cisco C9200, Capabilities: Router Switch IGMP\n"
        "Interface: GigabitEthernet1/0/24, Port ID (outgoing port): GigabitEthernet1/0/1\n"
    )


@pytest.mark.parametrize(
    "neighbor",
    (
        "CORE-DIST-01",
        "C950048Y4C-dedu-carpa-650-B056-145",
        "DIST-9500-NEW",
        "CORE-9600-NEW",
    ),
)
def test_ios_root_guard_exempts_9500_and_9600_neighbors(neighbor):
    outputs = {
        "show running-config": "interface GigabitEthernet1/0/24\n!\n",
        "show cdp neighbors detail": cdp_neighbor(neighbor),
    }
    assert evaluate("ios_l2", "V-220629", outputs).status == "NotAFinding"


def test_ios_root_guard_required_on_access_switch_neighbor():
    outputs = {"show cdp neighbors detail": cdp_neighbor("ACCESS-C9200-01")}
    outputs["show running-config"] = "interface GigabitEthernet1/0/24\n!\n"
    assert evaluate("ios_l2", "V-220629", outputs).status == "Open"
    outputs["show running-config"] = "interface GigabitEthernet1/0/24\n spanning-tree guard root\n!\n"
    assert evaluate("ios_l2", "V-220629", outputs).status == "NotAFinding"
