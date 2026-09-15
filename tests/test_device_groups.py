from __future__ import annotations

from stig_audit_pro.storage.device_groups import DeviceGroup, DeviceGroupStore, DeviceTargetRecord


def test_device_group_store_round_trip(tmp_path):
    store = DeviceGroupStore(tmp_path)
    group = DeviceGroup(
        group_name="building_a_access",
        profile_name="example_site",
        targets=[
            DeviceTargetRecord(ip="10.50.10.25", checked=True),
            DeviceTargetRecord(ip="10.50.10.26", profile_override="base_iosxe_access", checked=False),
        ],
    )

    path = store.save_group(group)
    loaded = store.load_group("building_a_access")

    assert path.name == "building_a_access.yaml"
    assert store.list_groups() == ["building_a_access"]
    assert loaded.profile_name == "example_site"
    assert [target.ip for target in loaded.targets] == ["10.50.10.25", "10.50.10.26"]
    assert loaded.targets[1].profile_override == "base_iosxe_access"
    assert loaded.targets[1].checked is False
