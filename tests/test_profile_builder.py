from __future__ import annotations

from pathlib import Path

import pytest

from stig_audit_pro.storage.profile_builder import (
    ProfileBuildError,
    materialize_profile,
    save_profile,
    validate_profile_data,
)


BASE = {
    "profile_name": "base_iosxe_access",
    "inherits": None,
    "unused_vlan": 997,
    "native_vlan": 20,
    "management_vlan": 10,
    "dhcp_snooping": {"enabled": True, "vlans": [30], "required_global_commands": ["ip dhcp snooping"]},
    "arp_inspection": {"enabled": True, "vlans": [30]},
    "root_guard": {"upstream_switches": ["CORE-DIST-01"]},
    "management_access": {
        "acl_name": "EXAMPLE-MGMT-ACL",
        "networks": [{"network_address": "192.0.2.0", "subnet_mask": "255.255.255.0"}],
    },
    "variables": {"required_user_vlans": [30], "site_label": "Base"},
}


def test_materialize_profile_recursively_merges_and_replaces_lists():
    result = materialize_profile(
        BASE,
        {
            "profile_name": "building_1",
            "dhcp_snooping": {"vlans": [110, 120]},
            "variables": {"site_label": "Building 1"},
        },
        "building_1",
    )

    assert result["profile_name"] == "building_1"
    assert "inherits" not in result
    assert result["dhcp_snooping"]["enabled"] is True
    assert result["dhcp_snooping"]["vlans"] == [110, 120]
    assert result["variables"]["required_user_vlans"] == [30]
    assert result["variables"]["site_label"] == "Building 1"


def test_materialize_profile_preserves_intentional_empty_list():
    result = materialize_profile(
        BASE,
        {"root_guard": {"upstream_switches": []}},
        "building_2",
    )

    assert result["root_guard"]["upstream_switches"] == []


def test_validate_profile_data_rejects_invalid_profile():
    invalid = {"profile_name": "bad", "unused_vlan": 5000}

    with pytest.raises(ProfileBuildError, match="profile validation failed"):
        validate_profile_data(invalid, Path("profiles"))


def test_save_profile_writes_flattened_yaml_and_validates_before_publish(tmp_path):
    path = save_profile(tmp_path / "building_1.yaml", BASE | {"profile_name": "building_1"}, tmp_path)

    assert path.name == "building_1.yaml"
    assert "inherits" not in path.read_text(encoding="utf-8")
    assert validate_profile_data(
        {"profile_name": "building_1", "unused_vlan": 997}, tmp_path
    ).profile_name == "building_1"


def test_save_profile_does_not_replace_existing_file_on_validation_error(tmp_path):
    destination = tmp_path / "building_1.yaml"
    destination.write_text("profile_name: existing\n", encoding="utf-8")

    with pytest.raises(ProfileBuildError):
        save_profile(destination, {"profile_name": "bad", "unused_vlan": 5000}, tmp_path)

    assert destination.read_text(encoding="utf-8") == "profile_name: existing\n"
