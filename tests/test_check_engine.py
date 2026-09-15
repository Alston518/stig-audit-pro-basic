from __future__ import annotations

from collections import Counter

from stig_audit_pro.core.check_engine import CheckEngine
from stig_audit_pro.core.models import CheckDefinition, ManagementNetwork
from stig_audit_pro.core.yaml_loader import load_check_library
from tests.conftest import DATA_DIR, load_l2_checks, load_outputs, load_profile


def _results_by_vuln(kind: str):
    engine = CheckEngine(load_profile())
    results = engine.evaluate_all(
        load_l2_checks(),
        outputs=load_outputs(kind),
        ip="10.50.10.25" if kind == "compliant" else "10.50.10.26",
    )
    return {result.vuln_id: result for result in results}


def test_required_checks_pass_on_compliant_sample_outputs():
    results = _results_by_vuln("compliant")
    counts = Counter(result.status for result in results.values())

    assert counts["NotAFinding"] == 21
    assert counts["Not_Reviewed"] == 0
    assert counts["Not_Applicable"] == 0
    assert counts["Open"] == 1
    assert results["V-220649"].status == "NotAFinding"
    assert results["V-220650"].status == "NotAFinding"
    assert results["V-220651"].status == "Open"
    assert "pending QoS implementation" in results["V-220651"].comments
    assert results["V-220655"].status == "NotAFinding"
    assert results["V-220656"].status == "NotAFinding"
    assert results["V-220657"].status == "NotAFinding"
    assert results["V-220658"].status == "NotAFinding"
    assert results["V-220659"].status == "NotAFinding"
    assert results["V-220660"].status == "NotAFinding"
    assert results["V-220661"].status == "NotAFinding"
    assert results["V-220662"].status == "NotAFinding"
    assert results["V-220664"].status == "NotAFinding"
    assert results["V-220665"].status == "NotAFinding"
    assert results["V-220666"].status == "NotAFinding"
    assert results["V-220667"].status == "NotAFinding"
    assert results["V-220668"].status == "NotAFinding"
    assert results["V-220669"].status == "NotAFinding"
    assert results["V-220671"].status == "NotAFinding"
    assert results["V-220672"].status == "NotAFinding"
    assert results["V-220673"].status == "NotAFinding"


def test_required_checks_fail_on_noncompliant_sample_outputs():
    results = _results_by_vuln("noncompliant")
    counts = Counter(result.status for result in results.values())

    assert counts["Open"] == 20
    assert counts["Not_Reviewed"] == 0
    assert counts["NotAFinding"] == 2
    assert results["V-220649"].status == "Open"
    assert results["V-220650"].status == "Open"
    assert results["V-220651"].status == "Open"
    assert results["V-220655"].status == "Open"
    assert results["V-220655"].failed_objects[0].object_name == "GigabitEthernet1/0/24"
    assert results["V-220656"].status == "Open"
    assert any(
        finding.object_name == "GigabitEthernet1/0/2"
        for finding in results["V-220656"].failed_objects
    )
    assert results["V-220657"].status == "Open"
    assert results["V-220658"].status == "Open"
    assert any(
        finding.object_name == "GigabitEthernet1/0/2"
        for finding in results["V-220658"].failed_objects
    )
    assert results["V-220659"].status == "Open"
    assert results["V-220660"].status == "Open"
    assert any(
        finding.object_name == "GigabitEthernet1/0/2"
        for finding in results["V-220660"].failed_objects
    )
    assert results["V-220661"].status == "Open"
    assert results["V-220662"].status == "Open"
    assert any(
        finding.object_name == "GigabitEthernet1/0/2"
        for finding in results["V-220662"].failed_objects
    )
    assert results["V-220664"].status == "Open"
    assert results["V-220665"].status == "Open"
    assert results["V-220666"].status == "Open"
    assert results["V-220667"].status == "Open"
    assert results["V-220668"].status == "Open"
    assert results["V-220669"].status == "Open"
    assert results["V-220671"].status == "NotAFinding"
    assert results["V-220672"].status == "Open"
    assert results["V-220673"].status == "NotAFinding"
    assert results["V-220669"].failed_objects[0].object_name == "GigabitEthernet1/0/24"
    assert results["V-220659"].failed_objects
    assert results["V-220661"].failed_objects[0].object_name == "30"


def test_vlan1_management_check_allows_no_ip_and_stays_in_interface_block():
    engine = CheckEngine(load_profile())
    check = next(check for check in load_l2_checks() if check.vuln_id == "V-220670")
    outputs = {
        "show running-config": """\
interface Vlan1
 no ip address
 shutdown
!
interface Vlan20
 ip address 192.0.2.1 255.255.255.0
!
"""
    }

    result = engine.evaluate(check, outputs=outputs, ip="10.50.10.25")

    assert result.status == "NotAFinding"


def test_igmp_mld_snooping_check_detects_global_and_vlan_disables():
    engine = CheckEngine(load_profile())
    check = next(check for check in load_l2_checks() if check.vuln_id == "V-220663")

    compliant = engine.evaluate(
        check,
        outputs={"show running-config": "hostname ACCESS-SW01\nip igmp snooping\n"},
        ip="10.50.10.25",
    )
    assert compliant.status == "NotAFinding"

    disabled_commands = (
        "no ip igmp snooping",
        "no ip igmp snooping vlan 11",
        "no ip igmp snooping vlan 11,20,30",
        "no ipv6 mld snooping",
        "no ipv6 mld snooping vlan 11",
    )
    for command in disabled_commands:
        result = engine.evaluate(
            check,
            outputs={"show running-config": f"hostname ACCESS-SW01\n{command}\n"},
            ip="10.50.10.26",
        )
        assert result.status == "Open", command


def test_disabled_port_policy_exempts_dot1x_and_ignores_connected_ports():
    engine = CheckEngine(load_profile())
    original = next(check for check in load_l2_checks() if check.vuln_id == "V-220667")
    scope = {
        "interfaces": {
            "include": [
                {
                    "type": "physical",
                    "match": {
                        "switchport_mode": "access",
                        "admin_state": "disabled_or_notconnect",
                    },
                }
            ]
        }
    }
    conditions = {
        "exempt_strings": [
            {
                "string": "authentication port-control auto",
                "description": "802.1X authentication configured",
            }
        ],
        "required_patterns": original.conditions["required_patterns"],
    }
    check = original.model_copy(update={"scope": scope, "conditions": conditions})
    outputs = {
        "show running-config": """\
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
 authentication port-control auto
!
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 999
 shutdown
!
interface GigabitEthernet1/0/3
 switchport mode access
 switchport access vlan 10
 shutdown
!
interface GigabitEthernet1/0/4
 switchport mode access
 switchport access vlan 10
!
""",
        "show interfaces status": """\
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   DOT1X              notconnect   10         auto    auto  10/100/1000BaseTX
Gi1/0/2   UNUSED             disabled     999        auto    auto  10/100/1000BaseTX
Gi1/0/3   BAD-UNUSED         disabled     10         auto    auto  10/100/1000BaseTX
Gi1/0/4   USER               connected    10         a-full  a-100 10/100/1000BaseTX
""",
    }

    result = engine.evaluate(check, outputs=outputs, ip="10.50.10.25")

    assert result.status == "Open"
    assert [finding.object_name for finding in result.failed_objects] == ["GigabitEthernet1/0/3"]
    passed = {finding.object_name: finding.details for finding in result.passed_objects}
    assert passed["GigabitEthernet1/0/1"] == "exempt: 802.1X authentication configured"
    assert passed["GigabitEthernet1/0/2"] == "required interface config present"
    assert "GigabitEthernet1/0/4" not in passed


def test_user_facing_access_policy_checks_copper_and_ignores_sfp_ports():
    engine = CheckEngine(load_profile())
    original = next(check for check in load_l2_checks() if check.vuln_id == "V-220671")
    scope = {
        "interfaces": {
            "include": [
                {
                    "type": "physical",
                    "match": {"media_type": {"regex": "BaseTX"}},
                }
            ]
        }
    }
    conditions = {"required_strings": ["switchport mode access"]}
    check = original.model_copy(
        update={
            "check_type": "interface_config_policy",
            "commands": ["show running-config", "show interfaces status"],
            "automated": True,
            "scope": scope,
            "conditions": conditions,
            "result": original.result.model_copy(update={"fail_status": "Open"}),
        }
    )
    outputs = {
        "show running-config": """\
interface GigabitEthernet1/0/1
 switchport mode access
!
interface GigabitEthernet1/0/2
 switchport mode trunk
!
interface GigabitEthernet1/0/48
 switchport mode trunk
!
""",
        "show interfaces status": """\
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   USER               connected    10         a-full  a-100 10/100/1000BaseTX
Gi1/0/2   BAD-COPPER         connected    trunk      a-full  a-1G  10/100/1000BaseTX
Gi1/0/48  SFP-UPLINK         connected    trunk      a-full  a-1G  1000BaseSX SFP
""",
    }

    result = engine.evaluate(check, outputs=outputs, ip="10.50.10.25")

    assert result.status == "Open"
    assert [finding.object_name for finding in result.failed_objects] == ["GigabitEthernet1/0/2"]
    assert result.passed_objects[0].object_name == "GigabitEthernet1/0/1"


def test_endpoint_authentication_policy_reports_interface_and_radius_failures():
    engine = CheckEngine(load_profile())
    test_check = next(check for check in load_l2_checks() if check.vuln_id == "V-220649")
    outputs = {
        "show running-config": """\
aaa group server radius ISE-RADIUS
 server name ISE1-EDU-01
!
interface GigabitEthernet1/0/1
 switchport mode access
 authentication port-control auto
 dot1x pae authenticator
 mab
!
interface GigabitEthernet1/0/2
 authentication port-control auto
 dot1x pae authenticator
!
""",
        "show interfaces status": """\
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   USER1              connected    10         a-full  a-100 10/100/1000BaseTX
Gi1/0/2   USER2              connected    10         a-full  a-100 10/100/1000BaseTX
""",
    }

    result = engine.evaluate(test_check, outputs=outputs, ip="10.50.10.25")

    assert result.status == "Open"
    failures = {(finding.object_type, finding.object_name) for finding in result.failed_objects}
    assert ("interface", "GigabitEthernet1/0/2") in failures
    assert ("radius_server", "ISE2-EDU-02") in failures


def test_endpoint_authentication_policy_passes_complete_configuration():
    engine = CheckEngine(load_profile())
    test_check = next(check for check in load_l2_checks() if check.vuln_id == "V-220649")
    outputs = {
        "show running-config": """\
aaa group server radius ISE-RADIUS
 server name ISE1-EDU-01
 server name ISE2-EDU-02
!
interface GigabitEthernet1/0/1
 switchport mode access
 authentication port-control auto
 dot1x pae authenticator
 mab
!
""",
        "show interfaces status": """\
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   USER1              connected    10         a-full  a-100 10/100/1000BaseTX
""",
    }

    result = engine.evaluate(test_check, outputs=outputs, ip="10.50.10.25")

    assert result.status == "NotAFinding"
    assert result.failed_objects == []


def test_native_vlan_assignment_policy_uses_profile_vlan_and_reports_port():
    engine = CheckEngine(load_profile())
    test_check = next(
        check for check in load_l2_checks() if check.vuln_id == "V-220673"
    )
    outputs = {
        "show interfaces status": """\
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   USER               connected    10         a-full  a-100 10/100/1000BaseTX
Gi1/0/2   BAD-NATIVE         notconnect   333        auto    auto  10/100/1000BaseTX
Gi1/0/24  UPLINK             connected    trunk      a-full  a-1G  1000BaseSX
"""
    }

    result = engine.evaluate(test_check, outputs=outputs, ip="10.50.10.25")

    assert result.status == "Open"
    assert [finding.object_name for finding in result.failed_objects] == [
        "GigabitEthernet1/0/2"
    ]
    assert "access VLAN matches native VLAN 333" in result.failed_objects[0].details


def test_native_vlan_assignment_policy_passes_when_vlan_is_unused():
    engine = CheckEngine(load_profile())
    test_check = next(
        check for check in load_l2_checks() if check.vuln_id == "V-220673"
    )
    outputs = {
        "show interfaces status": """\
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   USER               connected    10         a-full  a-100 10/100/1000BaseTX
Gi1/0/2   UNUSED             disabled     999        auto    auto  10/100/1000BaseTX
Gi1/0/24  UPLINK             connected    trunk      a-full  a-1G  1000BaseSX
"""
    }

    result = engine.evaluate(test_check, outputs=outputs, ip="10.50.10.25")

    assert result.status == "NotAFinding"
    assert result.failed_objects == []


def test_native_vlan_assignment_policy_errors_when_status_output_is_empty():
    engine = CheckEngine(load_profile())
    test_check = next(
        check for check in load_l2_checks() if check.vuln_id == "V-220673"
    )

    result = engine.evaluate(
        test_check,
        outputs={"show interfaces status": ""},
        ip="10.50.10.25",
    )

    assert result.status == "Error"


def test_vlan1_management_check_rejects_configured_ip_address():
    engine = CheckEngine(load_profile())
    check = next(check for check in load_l2_checks() if check.vuln_id == "V-220670")
    outputs = {
        "show running-config": """\
interface Vlan1
 ip address 192.0.2.1 255.255.255.0
 no shutdown
!
"""
    }

    result = engine.evaluate(check, outputs=outputs, ip="10.50.10.26")

    assert result.status == "Open"


def test_root_guard_exempts_upstream_neighbor_but_checks_access_neighbor():
    engine = CheckEngine(load_profile())
    check = next(check for check in load_l2_checks() if check.vuln_id == "V-220655")
    outputs = {
        "show running-config": """\
interface GigabitEthernet1/0/23
 spanning-tree guard root
!
interface GigabitEthernet1/0/24
!\n""",
        "show cdp neighbors detail": """\
Device ID: IDF2-ACCESS01.example.mil
Platform: cisco C9200, Capabilities: Router Switch IGMP
Interface: GigabitEthernet1/0/23, Port ID (outgoing port): GigabitEthernet1/0/48
-------------------------
Device ID: CORE-DIST-01.example.mil
Platform: cisco C9500, Capabilities: Router Switch IGMP
Interface: GigabitEthernet1/0/24, Port ID (outgoing port): TenGigabitEthernet1/0/1
""",
    }

    result = engine.evaluate(check, outputs=outputs, ip="10.50.10.25")

    assert result.status == "NotAFinding"
    assert {obj.object_name for obj in result.passed_objects} == {
        "GigabitEthernet1/0/23",
        "GigabitEthernet1/0/24",
    }


def test_root_guard_only_upstream_neighbors_is_not_a_finding():
    engine = CheckEngine(load_profile())
    check = next(check for check in load_l2_checks() if check.vuln_id == "V-220655")
    outputs = {
        "show running-config": """\
interface GigabitEthernet1/0/24
!
""",
        "show cdp neighbors detail": """\
Device ID: CORE-DIST-01.example.mil
Platform: cisco C9500, Capabilities: Router Switch IGMP
Interface: GigabitEthernet1/0/24, Port ID (outgoing port): TenGigabitEthernet1/0/1
""",
    }

    result = engine.evaluate(check, outputs=outputs, ip="10.50.10.25")

    assert result.status == "NotAFinding"
    assert result.failed_objects == []
    assert result.passed_objects[0].object_name == "GigabitEthernet1/0/24"
    assert "Only configured upstream" in result.finding_details


def test_ndm_archive_checks_require_logging_enable_inside_log_config():
    archive_check_ids = {
        "V-220519",
        "V-220520",
        "V-220521",
        "V-220522",
        "V-220530",
        "V-220545",
        "V-220559",
        "V-220561",
    }
    checks = [
        check
        for check in load_check_library(DATA_DIR / "checks" / "iosxe_ndm.yaml").checks
        if check.vuln_id in archive_check_ids
    ]
    engine = CheckEngine(load_profile())

    compliant_output = """\
hostname TEST-SWITCH
archive
 log config
  logging enable
  hidekeys
!
"""
    misplaced_output = """\
hostname TEST-SWITCH
archive
 log config
  hidekeys
!
logging enable
"""

    compliant_results = engine.evaluate_all(
        checks,
        outputs={"show running-config": compliant_output},
        ip="10.50.10.25",
    )
    misplaced_results = engine.evaluate_all(
        checks,
        outputs={"show running-config": misplaced_output},
        ip="10.50.10.26",
    )

    assert len(compliant_results) == len(archive_check_ids)
    assert all(result.status == "NotAFinding" for result in compliant_results)
    assert all(result.status == "Open" for result in misplaced_results)
    assert all(
        any(
            finding.object_name == "logging enable under archive log config"
            for finding in result.failed_objects
        )
        for result in misplaced_results
    )


def test_completed_ndm_login_and_logging_checks_match_expected_config():
    completed_ids = {
        "V-220524",
        "V-220526",
        "V-220528",
        "V-220547",
        "V-220548",
        "V-220560",
    }
    checks = [
        check
        for check in load_check_library(DATA_DIR / "checks" / "iosxe_ndm.yaml").checks
        if check.vuln_id in completed_ids
    ]
    engine = CheckEngine(load_profile())
    compliant_output = """\
login block-for 900 attempts 3 within 120
login on-success log
login on-failure log
logging userinfo
service timestamps log datetime msec localtime show-timezone year
logging buffered 65536 informational
logging trap warnings
"""

    results = engine.evaluate_all(
        checks,
        outputs={"show running-config": compliant_output},
        ip="192.0.2.1",
    )

    assert len(results) == len(completed_ids)
    assert all(result.status == "NotAFinding" for result in results)

    timestamp_check = next(check for check in checks if check.vuln_id == "V-220528")
    missing_msec = engine.evaluate(
        timestamp_check,
        outputs={
            "show running-config": (
                "service timestamps log datetime localtime show-timezone year\n"
            )
        },
        ip="192.0.2.2",
    )

    assert missing_msec.status == "Open"


def test_profile_logging_servers_are_literal_and_require_two_hosts():
    profile = load_profile()
    profile.variables["logging_servers"] = ["192.0.2.10", "syslog1.example.mil"]
    engine = CheckEngine(profile)
    check = next(
        check
        for check in load_check_library(
            DATA_DIR / "checks" / "iosxe_ndm.yaml"
        ).checks
        if check.vuln_id == "V-220568"
    )

    compliant = engine.evaluate(
        check,
        outputs={
            "show running-config": (
                "logging host 192.0.2.10\n"
                "logging host syslog1.example.mil transport udp port 514\n"
            )
        },
        ip="192.0.2.1",
    )
    one_server = engine.evaluate(
        check,
        outputs={"show running-config": "logging host 192.0.2.10\n"},
        ip="192.0.2.2",
    )
    wildcard_lookalike = engine.evaluate(
        check,
        outputs={
            "show running-config": (
                "logging host 192X0Y2Z10\n"
                "logging host syslog1.example.mil\n"
            )
        },
        ip="192.0.2.3",
    )

    assert compliant.status == "NotAFinding"
    assert one_server.status == "Open"
    assert wildcard_lookalike.status == "Open"


def test_profile_ntp_servers_are_literal_and_require_two_servers():
    profile = load_profile()
    profile.variables["ntp_servers"] = ["192.0.2.20", "ntp1.example.mil"]
    engine = CheckEngine(profile)
    check = next(
        check
        for check in load_check_library(
            DATA_DIR / "checks" / "iosxe_ndm.yaml"
        ).checks
        if check.vuln_id == "V-220549"
    )

    compliant = engine.evaluate(
        check,
        outputs={
            "show running-config": (
                "ntp server 192.0.2.20\n"
                "ntp server ntp1.example.mil prefer\n"
            )
        },
        ip="192.0.2.1",
    )
    one_server = engine.evaluate(
        check,
        outputs={"show running-config": "ntp server 192.0.2.20\n"},
        ip="192.0.2.2",
    )
    unlisted_second = engine.evaluate(
        check,
        outputs={
            "show running-config": (
                "ntp server 192.0.2.20\n"
                "ntp server other.example.mil\n"
            )
        },
        ip="192.0.2.3",
    )
    wildcard_lookalike = engine.evaluate(
        check,
        outputs={
            "show running-config": (
                "ntp server 192X0Y2Z20\n"
                "ntp server ntp1.example.mil\n"
            )
        },
        ip="192.0.2.4",
    )

    assert compliant.status == "NotAFinding"
    assert one_server.status == "Open"
    assert unlisted_second.status == "Open"
    assert wildcard_lookalike.status == "Open"


def test_snmpv3_checks_accept_sha_and_aes_but_reject_weak_protocols():
    check_ids = {"V-220552", "V-220553"}
    checks = [
        check
        for check in load_check_library(
            DATA_DIR / "checks" / "iosxe_ndm.yaml"
        ).checks
        if check.vuln_id in check_ids
    ]
    engine = CheckEngine(load_profile())
    compliant_outputs = [
        (
            "Authentication Protocol: SHA\n"
            "Privacy Protocol: AES256\n"
        ),
        (
            "Authentication Protocol: SHA-1\n"
            "Privacy Protocol: AES-128\n"
        ),
        (
            "Authentication Protocol: SHA256\n"
            "Privacy Protocol: AES192\n"
        ),
        (
            "Authentication Protocol: SHA-2-384\n"
            "Privacy Protocol: AES 192\n"
        ),
        (
            "Authentication Protocol: HMAC-SHA-512\n"
            "Privacy Protocol: AES128\n"
        ),
    ]

    for output in compliant_outputs:
        results = engine.evaluate_all(
            checks,
            outputs={"show snmp user": output},
            ip="192.0.2.1",
        )
        assert len(results) == len(check_ids)
        assert all(result.status == "NotAFinding" for result in results)

    for output in (
        "Authentication Protocol: MD5\nPrivacy Protocol: 3DES\n",
        "Authentication Protocol: None\nPrivacy Protocol: None\n",
    ):
        results = engine.evaluate_all(
            checks,
            outputs={"show snmp user": output},
            ip="192.0.2.2",
        )
        assert all(result.status == "Open" for result in results)


def test_local_fallback_account_uses_policy_and_tacacs_first_order():
    profile = load_profile()
    engine = CheckEngine(profile)
    check = next(
        check
        for check in load_check_library(
            DATA_DIR / "checks" / "iosxe_ndm.yaml"
        ).checks
        if check.vuln_id == "V-220535"
    )
    configurations = {
        "compliant": (
            "username admin privilege 15 common-criteria-policy "
            "PASSWORD_POLICY password 7 HASH\n"
            "aaa authentication login default group ISE-TACACS local\n"
        ),
        "two_accounts": (
            "username admin privilege 15 common-criteria-policy "
            "PASSWORD_POLICY password 7 HASH1\n"
            "username backup privilege 15 common-criteria-policy "
            "PASSWORD_POLICY password 7 HASH2\n"
            "aaa authentication login default group ISE-TACACS local\n"
        ),
        "wrong_policy": (
            "username admin privilege 15 common-criteria-policy "
            "OTHER_POLICY password 7 HASH\n"
            "aaa authentication login default group ISE-TACACS local\n"
        ),
        "wrong_order": (
            "username admin privilege 15 common-criteria-policy "
            "PASSWORD_POLICY password 7 HASH\n"
            "aaa authentication login default local group ISE-TACACS\n"
        ),
    }

    results = {
        name: engine.evaluate(
            check,
            outputs={"show running-config": output},
            ip="192.0.2.1",
        )
        for name, output in configurations.items()
    }

    assert results["compliant"].status == "NotAFinding"
    assert results["two_accounts"].status == "Open"
    assert results["wrong_policy"].status == "Open"
    assert results["wrong_order"].status == "Open"
    assert all(
        "HASH" not in finding.details
        for finding in results["two_accounts"].failed_objects
    )


def test_common_criteria_controls_require_commands_inside_named_policy():
    requirements = {
        "V-220537": "min-length 15",
        "V-220538": "upper-case 1",
        "V-220539": "lower-case 1",
        "V-220540": "numeric-count 1",
        "V-220541": "special-case 1",
        "V-220542": "char-changes 8",
    }
    checks = [
        check
        for check in load_check_library(
            DATA_DIR / "checks" / "iosxe_ndm.yaml"
        ).checks
        if check.vuln_id in requirements
    ]
    engine = CheckEngine(load_profile())
    compliant = """\
aaa common-criteria policy PASSWORD_POLICY
 min-length 15
 max-length 127
 numeric-count 1
 upper-case 1
 lower-case 1
 special-case 1
 char-changes 8
!
"""

    compliant_results = engine.evaluate_all(
        checks,
        outputs={"show running-config": compliant},
        ip="192.0.2.1",
    )

    assert len(compliant_results) == len(requirements)
    assert all(result.status == "NotAFinding" for result in compliant_results)

    for check in checks:
        required = requirements[check.vuln_id]
        policy_without_requirement = [
            line for line in compliant.splitlines() if line.strip() != required
        ]
        misplaced = "\n".join(policy_without_requirement + ["!", required]) + "\n"
        misplaced_result = engine.evaluate(
            check,
            outputs={"show running-config": misplaced},
            ip="192.0.2.2",
        )
        wrong_policy_result = engine.evaluate(
            check,
            outputs={
                "show running-config": compliant.replace(
                    "policy PASSWORD_POLICY",
                    "policy OTHER_POLICY",
                )
            },
            ip="192.0.2.3",
        )

        assert misplaced_result.status == "Open"
        assert wrong_policy_result.status == "Open"


def test_ssh_algorithm_controls_require_exact_approved_lists():
    command = "show running-config | include ssh"
    check_ids = {"V-220555", "V-220556"}
    checks = [
        check
        for check in load_check_library(
            DATA_DIR / "checks" / "iosxe_ndm.yaml"
        ).checks
        if check.vuln_id in check_ids
    ]
    engine = CheckEngine(load_profile())
    compliant = (
        "ip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256\n"
        "ip ssh server algorithm encryption "
        "aes256-ctr aes192-ctr aes128-ctr\n"
    )

    compliant_results = engine.evaluate_all(
        checks,
        outputs={command: compliant},
        ip="192.0.2.1",
    )

    assert len(compliant_results) == len(check_ids)
    assert all(result.status == "NotAFinding" for result in compliant_results)

    noncompliant = (
        "ip ssh server algorithm mac hmac-sha2-256 hmac-sha2-512\n"
        "ip ssh server algorithm encryption "
        "aes256-ctr aes192-ctr aes128-ctr aes128-cbc\n"
    )
    noncompliant_results = engine.evaluate_all(
        checks,
        outputs={command: noncompliant},
        ip="192.0.2.2",
    )

    assert all(result.status == "Open" for result in noncompliant_results)


def test_prohibited_services_check_rejects_each_configured_service():
    check = next(
        check
        for check in load_check_library(
            DATA_DIR / "checks" / "iosxe_ndm.yaml"
        ).checks
        if check.vuln_id == "V-220534"
    )
    engine = CheckEngine(load_profile())
    prohibited_commands = [
        "boot network",
        "ip boot server",
        "ip bootp server",
        "ip dns server",
        "ip identd",
        "ip finger",
        "ip http server",
        "ip rcmd rcp-enable",
        "ip rcmd rsh-enable",
        "service config",
        "service finger",
        "service tcp-small-servers",
        "service udp-small-servers",
        "service pad",
        "service call-home",
    ]

    clean = engine.evaluate(
        check,
        outputs={
            "show running-config": (
                "no ip http server\n"
                "ip http secure-server\n"
                "no service pad\n"
            )
        },
        ip="192.0.2.1",
    )

    assert clean.status == "NotAFinding"
    for command in prohibited_commands:
        result = engine.evaluate(
            check,
            outputs={"show running-config": f"{command}\n"},
            ip="192.0.2.2",
        )
        assert result.status == "Open", command


def test_password_encryption_requires_positive_service_command():
    check = next(
        check
        for check in load_check_library(
            DATA_DIR / "checks" / "iosxe_ndm.yaml"
        ).checks
        if check.vuln_id == "V-220543"
    )
    engine = CheckEngine(load_profile())

    enabled = engine.evaluate(
        check,
        outputs={"show running-config": "service password-encryption\n"},
        ip="192.0.2.1",
    )
    disabled = engine.evaluate(
        check,
        outputs={"show running-config": "no service password-encryption\n"},
        ip="192.0.2.2",
    )

    assert enabled.status == "NotAFinding"
    assert disabled.status == "Open"


def test_every_vty_section_requires_approved_five_minute_timeout():
    check = next(
        check
        for check in load_check_library(
            DATA_DIR / "checks" / "iosxe_ndm.yaml"
        ).checks
        if check.vuln_id == "V-220544"
    )
    engine = CheckEngine(load_profile())
    compliant = """\
line con 0
 session-timeout 10
line vty 0 4
 session-timeout 5
 transport input ssh
line vty 5 15
 exec-timeout 5 0
 no exec
 transport input none
!
"""
    missing_second_timeout = """\
line vty 0 4
 session-timeout 5
 transport input ssh
line vty 5 15
 no exec
 transport input none
!
"""
    wrong_timeout = """\
line vty 0 15
 session-timeout 10
 transport input ssh
!
"""

    compliant_result = engine.evaluate(
        check,
        outputs={"show running-config": compliant},
        ip="192.0.2.1",
    )
    missing_result = engine.evaluate(
        check,
        outputs={"show running-config": missing_second_timeout},
        ip="192.0.2.2",
    )
    wrong_result = engine.evaluate(
        check,
        outputs={"show running-config": wrong_timeout},
        ip="192.0.2.3",
    )
    no_vty_result = engine.evaluate(
        check,
        outputs={"show running-config": "hostname SWITCH\n"},
        ip="192.0.2.4",
    )

    assert compliant_result.status == "NotAFinding"
    assert missing_result.status == "Open"
    assert wrong_result.status == "Open"
    assert no_vty_result.status == "Open"


def test_vty_session_limit_policy_uses_limit_or_counts_unique_vty_lines():
    profile = load_profile()
    profile.variables["max_concurrent_management_sessions"] = 10
    engine = CheckEngine(profile)
    check = next(
        check
        for check in load_check_library(
            DATA_DIR / "checks" / "iosxe_ndm.yaml"
        ).checks
        if check.vuln_id == "V-220518"
    )
    configurations = {
        "count_below_maximum": (
            "line vty 0 4\n"
            " transport input ssh\n"
            "!\n"
        ),
        "count_at_maximum": (
            "line vty 0 4\n"
            " transport input ssh\n"
            "line vty 5 9\n"
            " transport input ssh\n"
            "!\n"
        ),
        "count_above_maximum": (
            "line vty 0 4\n"
            " transport input ssh\n"
            "line vty 5 15\n"
            " transport input ssh\n"
            "!\n"
        ),
        "limits_at_or_below_maximum": (
            "line vty 0 4\n"
            " session-limit 10\n"
            " transport input ssh\n"
            "line vty 5 15\n"
            " session-limit 8\n"
            " transport input ssh\n"
            "!\n"
        ),
        "limit_above_maximum": (
            "line vty 0 15\n"
            " session-limit 11\n"
            " transport input ssh\n"
            "!\n"
        ),
        "partial_limit_coverage": (
            "line vty 0 4\n"
            " session-limit 10\n"
            " transport input ssh\n"
            "line vty 5 15\n"
            " transport input ssh\n"
            "!\n"
        ),
        "malformed_limit": (
            "line vty 0 15\n"
            " session-limit unlimited\n"
            " transport input ssh\n"
            "!\n"
        ),
    }

    results = {
        name: engine.evaluate(
            check,
            outputs={"show running-config": output},
            ip="192.0.2.1",
        )
        for name, output in configurations.items()
    }

    assert results["count_below_maximum"].status == "NotAFinding"
    assert results["count_at_maximum"].status == "NotAFinding"
    assert results["count_above_maximum"].status == "Open"
    assert results["limits_at_or_below_maximum"].status == "NotAFinding"
    assert results["limit_above_maximum"].status == "Open"
    assert results["partial_limit_coverage"].status == "Open"
    assert results["malformed_limit"].status == "Open"


def test_catalyst_center_backup_check_is_temporarily_not_a_finding():
    check = next(
        check
        for check in load_check_library(
            DATA_DIR / "checks" / "iosxe_ndm.yaml"
        ).checks
        if check.vuln_id == "V-220566"
    )
    result = CheckEngine(load_profile()).evaluate(
        check,
        outputs={},
        ip="192.0.2.1",
    )

    assert result.status == "NotAFinding"
    assert result.comments == (
        "Configuration backups are performed through Cisco Catalyst Center."
    )


def test_public_key_certificate_check_is_tailored_not_applicable():
    check = next(
        check
        for check in load_check_library(
            DATA_DIR / "checks" / "iosxe_ndm.yaml"
        ).checks
        if check.vuln_id == "V-220567"
    )
    result = CheckEngine(load_profile()).evaluate(
        check,
        outputs={},
        ip="192.0.2.1",
    )

    assert result.status == "Not_Applicable"
    assert "does not use organization-managed public key certificates" in (
        result.comments
    )
    assert "Cisco factory-installed/default certificates" in result.comments


def test_radius_server_policy_requires_server_blocks_keys_and_group_membership():
    profile = load_profile()
    profile.endpoint_authentication.radius_group = "ISE-RADIUS"
    profile.endpoint_authentication.radius_servers = [
        "ISE1-EDU-01",
        "ISE2-EDU-02",
    ]
    profile.endpoint_authentication.radius_server_addresses = {
        "ISE1-EDU-01": "192.0.2.18",
        "ISE2-EDU-02": "192.0.2.19",
    }
    engine = CheckEngine(profile)
    check = next(
        check
        for check in load_check_library(
            DATA_DIR / "checks" / "iosxe_ndm.yaml"
        ).checks
        if check.vuln_id == "V-220565"
    )
    compliant = """\
radius server ISE1-EDU-01
 address ipv4 192.0.2.18 auth-port 1812 acct-port 1813
 key 7 SECRET1
!
radius server ISE2-EDU-02
 address ipv4 192.0.2.19 auth-port 1812 acct-port 1813
 key SECRET2
!
aaa group server radius ISE-RADIUS
 server name ISE1-EDU-01
 server name ISE2-EDU-02
!
"""
    configurations = {
        "compliant": compliant,
        "missing_key": compliant.replace(" key SECRET2\n", ""),
        "wrong_address": compliant.replace("192.0.2.19", "192.0.2.99"),
        "wrong_port": compliant.replace(
            "auth-port 1812 acct-port 1813",
            "auth-port 1645 acct-port 1646",
            1,
        ),
        "missing_group_member": compliant.replace(
            " server name ISE2-EDU-02\n",
            "",
        ),
    }

    results = {
        name: engine.evaluate(
            check,
            outputs={"show running-config": output},
            ip="192.0.2.1",
        )
        for name, output in configurations.items()
    }

    assert results["compliant"].status == "NotAFinding"
    assert results["missing_key"].status == "Open"
    assert results["wrong_address"].status == "Open"
    assert results["wrong_port"].status == "Open"
    assert results["missing_group_member"].status == "Open"
    assert all(
        "SECRET" not in result.finding_details
        for result in results.values()
    )


def test_profile_any_accepts_only_exact_supported_iosxe_versions():
    profile = load_profile()
    profile.variables["supported_iosxe_versions"] = [
        "17.09.05",
        "17.12.04",
    ]
    engine = CheckEngine(profile)
    check = next(
        check
        for check in load_check_library(
            DATA_DIR / "checks" / "iosxe_ndm.yaml"
        ).checks
        if check.vuln_id == "V-220569"
    )
    outputs = {
        "first_allowed": "Cisco IOS XE Software, Version 17.09.05\n",
        "second_allowed": (
            "Cisco Catalyst L3 Switch Software (CAT9K_IOSXE), "
            "Version 17.12.04, RELEASE SOFTWARE\n"
        ),
        "unsupported": "Cisco IOS XE Software, Version 16.12.04\n",
        "suffix_lookalike": "Cisco IOS XE Software, Version 17.09.05a\n",
        "numeric_lookalike": "Cisco IOS XE Software, Version 17.09.050\n",
    }

    results = {
        name: engine.evaluate(
            check,
            outputs={"show version": output},
            ip="192.0.2.1",
        )
        for name, output in outputs.items()
    }

    assert results["first_allowed"].status == "NotAFinding"
    assert results["second_allowed"].status == "NotAFinding"
    assert results["unsupported"].status == "Open"
    assert results["suffix_lookalike"].status == "Open"
    assert results["numeric_lookalike"].status == "Open"


def test_dod_banner_policy_requires_complete_standard_text_inside_login_banner():
    check = CheckDefinition.model_validate(
        {
            "vuln_id": "V-220525",
            "stig_id": "CISC-ND-000160",
            "title": "Standard Mandatory DoD Notice and Consent Banner",
            "stig_family": "IOSXE_NDM",
            "severity": "cat2",
            "check_type": "dod_banner_policy",
            "commands": ["show running-config"],
            "conditions": {
                "command": "show running-config",
                "banner_type": "login",
            },
        }
    )
    banner_text = """\
You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent
to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject
to routine monitoring, interception, and search, and may be disclosed or used
for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls)
to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM,
LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or
services by attorneys, psychotherapists, or clergy, and their assistants.
Such communications and work product are private and confidential.
See User Agreement for details."""
    configurations = {
        "complete_control_c": f"banner login ^C\n{banner_text}\n^C\n",
        "complete_hash": f"banner login #\n{banner_text}\n#\n",
        "missing_clause": (
            "banner login ^C\n"
            + banner_text.replace("See User Agreement for details.", "")
            + "\n^C\n"
        ),
        "text_outside_banner": (
            f"{banner_text}\n"
            "banner login ^C\nAuthorized users only.\n^C\n"
        ),
        "motd_only": f"banner motd ^C\n{banner_text}\n^C\n",
    }

    results = {
        name: CheckEngine(load_profile()).evaluate(
            check,
            outputs={"show running-config": output},
            ip="192.0.2.1",
        )
        for name, output in configurations.items()
    }

    assert results["complete_control_c"].status == "NotAFinding"
    assert results["complete_hash"].status == "NotAFinding"
    assert results["missing_clause"].status == "Open"
    assert "User Agreement reference" in results["missing_clause"].finding_details
    assert results["text_outside_banner"].status == "Open"
    assert results["motd_only"].status == "Open"


def test_acl_deny_logging_policy_checks_only_interface_bound_acls():
    check = CheckDefinition.model_validate(
        {
            "vuln_id": "V-220529",
            "stig_id": "CISC-ND-000290",
            "title": "Interface ACL denies require log-input",
            "stig_family": "IOSXE_NDM",
            "severity": "cat2",
            "check_type": "acl_deny_logging_policy",
            "commands": ["show running-config", "show ip access-lists"],
            "conditions": {
                "deny_statements": {
                    "interface_bound_only": True,
                    "include_standard_acls": True,
                    "include_extended_acls": True,
                    "include_ipv6_acls": False,
                    "require_keyword": "log-input",
                }
            },
        }
    )
    running_config = """\
interface GigabitEthernet1/0/1
 ip access-group BLOCK_INBOUND in
!
interface GigabitEthernet1/0/2
 ip access-group 10 out
!
"""
    compliant_acls = """\
Extended IP access list BLOCK_INBOUND
    10 deny icmp any any log-input
    20 permit ip any any
Standard IP access list 10
    10 deny any log-input
Extended IP access list UNUSED
    10 deny ip any any
"""
    configurations = {
        "compliant": (running_config, compliant_acls),
        "bound_extended_missing": (
            running_config,
            compliant_acls.replace("deny icmp any any log-input", "deny icmp any any"),
        ),
        "bound_standard_missing": (
            running_config,
            compliant_acls.replace("deny any log-input", "deny any"),
        ),
        "only_unused_missing": (
            "interface GigabitEthernet1/0/1\n description no ACL here\n!\n",
            compliant_acls,
        ),
    }

    results = {
        name: CheckEngine(load_profile()).evaluate(
            check,
            outputs={
                "show running-config": running,
                "show ip access-lists": access_lists,
            },
            ip="192.0.2.1",
        )
        for name, (running, access_lists) in configurations.items()
    }

    assert results["compliant"].status == "NotAFinding"
    assert results["bound_extended_missing"].status == "Open"
    assert "GigabitEthernet1/0/1 in" in (
        results["bound_extended_missing"].finding_details
    )
    assert results["bound_standard_missing"].status == "Open"
    assert "GigabitEthernet1/0/2 out" in (
        results["bound_standard_missing"].finding_details
    )
    assert results["only_unused_missing"].status == "NotAFinding"


def test_management_access_policy_requires_acl_on_every_vty_and_only_approved_sources():
    profile = load_profile()
    profile.management_access.acl_name = "MANAGEMENT_NET"
    profile.management_access.networks = [
        ManagementNetwork(
            network_address="192.0.2.0",
            subnet_mask="255.255.255.0",
        )
    ]
    engine = CheckEngine(profile)
    check = CheckDefinition.model_validate(
        {
            "vuln_id": "V-220523",
            "stig_id": "CISC-ND-000140",
            "title": "VTY management access control",
            "stig_family": "IOSXE_NDM",
            "severity": "cat2",
            "check_type": "management_access_policy",
            "commands": ["show running-config"],
        }
    )
    compliant_standard = """\
ip access-list standard MANAGEMENT_NET
 permit 192.0.2.0 0.0.0.255
 deny any log-input
!
line vty 0 4
 access-class MANAGEMENT_NET in
 transport input ssh
!
line vty 5 15
 access-class MANAGEMENT_NET in
 transport input none
!
"""
    compliant_extended = """\
ip access-list extended MANAGEMENT_NET
 permit ip 192.0.2.0 0.0.0.255 any
 deny ip any any log-input
!
line vty 0 15
 access-class MANAGEMENT_NET in
 transport input ssh
!
"""
    configurations = {
        "standard": compliant_standard,
        "extended": compliant_extended,
        "missing_second_vty_acl": compliant_standard.replace(
            "line vty 5 15\n access-class MANAGEMENT_NET in\n",
            "line vty 5 15\n",
        ),
        "wrong_vty_acl": compliant_standard.replace(
            "access-class MANAGEMENT_NET in",
            "access-class OTHER_NET in",
            1,
        ),
        "unapproved_permit": compliant_standard.replace(
            " permit 192.0.2.0 0.0.0.255\n",
            " permit 192.0.2.0 0.0.0.255\n permit 198.51.100.0 0.0.0.255\n",
        ),
        "wrong_management_network": compliant_standard.replace(
            "permit 192.0.2.0 0.0.0.255",
            "permit 198.51.100.0 0.0.0.255",
        ),
    }

    results = {
        name: engine.evaluate(
            check,
            outputs={"show running-config": running_config},
            ip="192.0.2.1",
        )
        for name, running_config in configurations.items()
    }

    assert results["standard"].status == "NotAFinding"
    assert results["extended"].status == "NotAFinding"
    assert results["missing_second_vty_acl"].status == "Open"
    assert "line vty 5 15" in results["missing_second_vty_acl"].finding_details
    assert results["wrong_vty_acl"].status == "Open"
    assert results["unapproved_permit"].status == "Open"
    assert "not a profile-approved" in results["unapproved_permit"].finding_details
    assert results["wrong_management_network"].status == "Open"


def test_ntp_authentication_policy_requires_sha2_key_on_every_profile_server():
    profile = load_profile()
    profile.variables["ntp_servers"] = ["192.0.2.20", "192.0.2.21"]
    engine = CheckEngine(profile)
    check = CheckDefinition.model_validate(
        {
            "vuln_id": "V-220554",
            "stig_id": "CISC-ND-001150",
            "title": "Cryptographically authenticated NTP sources",
            "stig_family": "IOSXE_NDM",
            "severity": "cat2",
            "check_type": "ntp_authentication_policy",
            "commands": ["show running-config"],
            "conditions": {
                "command": "show running-config",
                "ntp_servers_profile_key": "ntp_servers",
                "minimum_servers": 2,
                "approved_algorithms": ["hmac-sha2-256"],
            },
        }
    )
    compliant = """\
ntp authentication-key 1 hmac-sha2-256 SECRET-ONE 7
ntp authentication-key 650 hmac-sha2-256 SECRET-TWO 7
ntp authenticate
ntp trusted-key 1
ntp trusted-key 650
ntp server 192.0.2.20 key 1 prefer
ntp server 192.0.2.21 key 650
"""
    configurations = {
        "compliant": compliant,
        "md5_key": compliant.replace(
            "ntp authentication-key 1 hmac-sha2-256",
            "ntp authentication-key 1 md5",
        ),
        "server_without_key": compliant.replace(
            "ntp server 192.0.2.21 key 650",
            "ntp server 192.0.2.21",
        ),
        "untrusted_key": compliant.replace("ntp trusted-key 650\n", ""),
        "undefined_key": compliant.replace(
            "ntp authentication-key 650 hmac-sha2-256 SECRET-TWO 7\n",
            "",
        ),
        "authentication_disabled": compliant.replace("ntp authenticate\n", ""),
    }

    results = {
        name: engine.evaluate(
            check,
            outputs={"show running-config": running_config},
            ip="192.0.2.1",
        )
        for name, running_config in configurations.items()
    }

    assert results["compliant"].status == "NotAFinding"
    assert results["md5_key"].status == "Open"
    assert "unapproved algorithm md5" in results["md5_key"].finding_details
    assert results["server_without_key"].status == "Open"
    assert "has no authentication key" in (
        results["server_without_key"].finding_details
    )
    assert results["untrusted_key"].status == "Open"
    assert "is not trusted" in results["untrusted_key"].finding_details
    assert results["undefined_key"].status == "Open"
    assert "is not defined" in results["undefined_key"].finding_details
    assert results["authentication_disabled"].status == "Open"
    assert all(
        "SECRET-" not in result.finding_details for result in results.values()
    )
