from __future__ import annotations

import pytest

from stig_audit_pro.storage.device_groups import (
    DeviceGroup,
    DeviceGroupStore,
    DeviceGroupValidationError,
    DeviceTargetRecord,
    normalize_device_addresses,
)


def test_device_group_store_round_trip(tmp_path):
    store = DeviceGroupStore(tmp_path)
    group = DeviceGroup(
        group_name="building_a_access",
        profile_name="example_site",
        targets=[
            DeviceTargetRecord(ip="192.0.2.25", checked=True),
            DeviceTargetRecord(ip="192.0.2.26", profile_override="base_iosxe_access", checked=False),
        ],
    )

    path = store.save_group(group)
    loaded = store.load_group("building_a_access")

    assert path.name == "building_a_access.yaml"
    assert store.list_groups() == ["building_a_access"]
    assert loaded.profile_name == "example_site"
    assert [target.ip for target in loaded.targets] == ["192.0.2.25", "192.0.2.26"]
    assert loaded.targets[1].profile_override == "base_iosxe_access"
    assert loaded.targets[1].checked is False


def test_normalize_device_addresses_rejects_duplicates_and_invalid_values():
    assert normalize_device_addresses([" 192.0.2.25 ", "switch-a.example.mil"]) == [
        "192.0.2.25",
        "switch-a.example.mil",
    ]

    with pytest.raises(DeviceGroupValidationError, match="duplicate"):
        normalize_device_addresses(["192.0.2.25", "192.0.2.25"])

    with pytest.raises(DeviceGroupValidationError, match="invalid"):
        normalize_device_addresses(["not a host name"])


def test_save_group_rejects_empty_groups(tmp_path):
    store = DeviceGroupStore(tmp_path)

    with pytest.raises(DeviceGroupValidationError, match="at least one"):
        store.save_group(DeviceGroup(group_name="empty", targets=[]))
