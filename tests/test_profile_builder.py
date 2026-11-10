from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from stig_audit_pro.storage import profile_builder

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


def test_import_profile_makes_valid_standalone_copy(tmp_path):
    source = tmp_path / "old_run" / "site.yml"
    source.parent.mkdir()
    source.write_text(yaml.safe_dump(BASE | {"profile_name": "Building One"}), encoding="utf-8")
    destination = profile_builder.import_profile(source, tmp_path / "current")

    assert destination == tmp_path / "current" / "Building_One.yaml"
    assert profile_builder.load_profile_data(destination)["profile_name"] == "Building One"
    assert source.is_file()


def test_import_profile_flattens_base_from_previous_run(tmp_path):
    old = tmp_path / "old_run"
    old.mkdir()
    (old / "base_iosxe_access.yaml").write_text(yaml.safe_dump(BASE), encoding="utf-8")
    source = old / "building.yaml"
    source.write_text(yaml.safe_dump({
        "profile_name": "building_from_old_run", "inherits": "base_iosxe_access",
        "dhcp_snooping": {"vlans": [110, 120]},
    }), encoding="utf-8")

    destination = profile_builder.import_profile(source, tmp_path / "current")
    saved = profile_builder.load_profile_data(destination)
    assert "inherits" not in saved
    assert saved["dhcp_snooping"]["vlans"] == [110, 120]
    assert saved["management_access"]["acl_name"] == "EXAMPLE-MGMT-ACL"


def test_import_profile_never_silently_replaces_existing_profile(tmp_path):
    source = tmp_path / "old.yaml"
    source.write_text(yaml.safe_dump(BASE | {"profile_name": "building"}), encoding="utf-8")
    current = tmp_path / "current"
    current.mkdir()
    existing = current / "building.yaml"
    existing.write_text("profile_name: building\nunused_vlan: 900\n", encoding="utf-8")

    with pytest.raises(ProfileBuildError, match="already exists"):
        profile_builder.import_profile(source, current)
    assert "unused_vlan: 900" in existing.read_text(encoding="utf-8")
    profile_builder.import_profile(source, current, overwrite=True)
    assert profile_builder.load_profile_data(existing)["unused_vlan"] == 997


def test_import_profile_rejects_invalid_or_unsafe_source(tmp_path):
    current = tmp_path / "current"
    invalid = tmp_path / "invalid.yaml"
    invalid.write_text("profile_name: bad\nunused_vlan: 5000\n", encoding="utf-8")
    with pytest.raises(ProfileBuildError, match="validation failed"):
        profile_builder.import_profile(invalid, current)
    traversal = tmp_path / "traversal.yaml"
    traversal.write_text("profile_name: bad\ninherits: ../outside.yaml\n", encoding="utf-8")
    with pytest.raises(ProfileBuildError, match="base profile"):
        profile_builder.import_profile(traversal, current)
    assert not current.exists()


def test_import_profile_does_not_replace_bundled_base(tmp_path):
    source = tmp_path / "old_run" / "base.yaml"
    source.parent.mkdir()
    source.write_text(yaml.safe_dump(BASE | {"unused_vlan": 900}), encoding="utf-8")
    current = tmp_path / "current"
    current.mkdir()
    existing = current / "base_iosxe_access.yaml"
    existing.write_text("profile_name: base_iosxe_access\nunused_vlan: 997\n", encoding="utf-8")

    with pytest.raises(ProfileBuildError, match="Base profiles cannot be replaced"):
        profile_builder.import_profile(source, current, overwrite=True)
    assert "unused_vlan: 997" in existing.read_text(encoding="utf-8")
