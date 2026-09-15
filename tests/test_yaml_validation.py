from __future__ import annotations

from tests.conftest import DATA_DIR
from stig_audit_pro.core.yaml_loader import load_check_library, load_exceptions, load_profile


def test_check_library_and_profile_validate():
    library = load_check_library(DATA_DIR / "checks" / "iosxe_l2.yaml")
    ndm_library = load_check_library(DATA_DIR / "checks" / "iosxe_ndm.yaml")
    profile = load_profile(DATA_DIR / "profiles" / "example_site.yaml")
    exceptions = load_exceptions(DATA_DIR / "exceptions" / "exceptions.yaml")

    assert len(library.checks) == 22
    assert len(ndm_library.checks) == 42
    assert any(check.vuln_id == "V-220659" for check in library.checks)
    assert any(check.vuln_id == "V-220569" for check in ndm_library.checks)
    assert profile.profile_name == "example_site"
    assert profile.unused_vlan == 999
    assert profile.dhcp_snooping.vlans == [10, 20, 30]
    assert exceptions.exceptions[0].force_status == "NotAFinding"

    base_profile = load_profile(DATA_DIR / "profiles" / "base_iosxe_access.yaml")
    assert int(base_profile.variables["max_concurrent_management_sessions"]) > 0
    assert len(base_profile.variables["ntp_servers"]) >= 2
    assert set(base_profile.endpoint_authentication.radius_server_addresses) == set(
        base_profile.endpoint_authentication.radius_servers
    )


def test_building_profiles_override_site_specific_vlans():
    building_1 = load_profile(DATA_DIR / "profiles" / "building_1.yaml")
    building_2 = load_profile(DATA_DIR / "profiles" / "building_2.yaml")

    assert building_1.profile_name == "building_1"
    assert building_1.dhcp_snooping.vlans == [110, 120, 130]
    assert building_1.arp_inspection.vlans == [110, 120, 130]

    assert building_2.profile_name == "building_2"
    assert building_2.dhcp_snooping.vlans == [210, 220, 230]
    assert building_2.arp_inspection.vlans == [210, 220, 230]

def test_l2_automated_checks_use_editable_string_policies():
    library = load_check_library(DATA_DIR / "checks" / "iosxe_l2.yaml")
    editable_policy_types = {
        "command_pattern_policy",
        "interface_config_policy",
        "root_guard_neighbor_policy",
    }

    non_editable = [
        f"{check.vuln_id}: {check.check_type}"
        for check in library.checks
        if check.automated and check.check_type not in editable_policy_types
    ]

    assert non_editable == []


def test_ndm_archive_checks_use_completed_hierarchy_policy():
    library = load_check_library(DATA_DIR / "checks" / "iosxe_ndm.yaml")
    checks = {check.vuln_id: check for check in library.checks}

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
    expected_descriptions = [
        "archive configuration section",
        "log config subsection under archive",
        "logging enable under archive log config",
    ]

    for vuln_id in archive_check_ids:
        check = checks[vuln_id]
        assert check.check_type == "command_pattern_policy"
        assert [item["description"] for item in check.conditions["all"]] == expected_descriptions
        assert all(item.get("pattern") for item in check.conditions["all"])
        assert check.evidence.include_failed_objects is True

    assert checks["V-220529"].check_type == "acl_deny_logging_policy"
    assert checks["V-220531"].result.fail_status == "Not_Applicable"
    assert checks["V-220566"].result.fail_status == "NotAFinding"
    assert checks["V-220567"].result.fail_status == "Not_Applicable"
