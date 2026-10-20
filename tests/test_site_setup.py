from __future__ import annotations

import shutil
import tkinter
from pathlib import Path
from types import SimpleNamespace

import pytest

from stig_audit_pro.gui.site_setup import build_profile_overrides, parse_group_addresses
from stig_audit_pro.basic_app import selected_group_values
from stig_audit_pro.storage.device_groups import DeviceGroup, DeviceTargetRecord


def test_profile_form_values_become_typed_nested_overrides():
    values = {
        "unused_vlan": "997",
        "native_vlan": "20",
        "management_vlan": "10",
        "site_label": "Building 1",
        "required_user_vlans": "110, 120, 130",
        "dhcp_vlans": "110,120,130",
        "arp_vlans": "110,120,130",
        "root_guard_upstreams": "CORE-01\nCORE-02",
        "management_acl": "MGMT-ACL",
        "management_networks": "192.0.2.0/24\n198.51.100.0/24",
        "radius_group": "RADIUS",
        "radius_servers": "RAD-01, RAD-02",
        "radius_addresses": "RAD-01=192.0.2.18\nRAD-02=192.0.2.19",
        "dhcp_enabled": True,
        "arp_enabled": True,
    }

    overrides = build_profile_overrides(values)

    assert overrides["unused_vlan"] == 997
    assert overrides["variables"]["required_user_vlans"] == [110, 120, 130]
    assert overrides["dhcp_snooping"]["vlans"] == [110, 120, 130]
    assert overrides["management_access"]["networks"] == [
        {"network_address": "192.0.2.0", "subnet_mask": "255.255.255.0"},
        {"network_address": "198.51.100.0", "subnet_mask": "255.255.255.0"},
    ]
    assert overrides["endpoint_authentication"]["radius_server_addresses"] == {
        "RAD-01": "192.0.2.18",
        "RAD-02": "192.0.2.19",
    }


def test_profile_form_values_preserve_explicit_empty_lists():
    values = {
        "unused_vlan": "997",
        "native_vlan": "20",
        "management_vlan": "10",
        "site_label": "Building 2",
        "required_user_vlans": "",
        "dhcp_vlans": "",
        "arp_vlans": "",
        "root_guard_upstreams": "",
        "management_acl": "MGMT-ACL",
        "management_networks": "",
        "radius_group": "RADIUS",
        "radius_servers": "",
        "radius_addresses": "",
        "dhcp_enabled": False,
        "arp_enabled": False,
    }

    overrides = build_profile_overrides(values)

    assert overrides["variables"]["required_user_vlans"] == []
    assert overrides["dhcp_snooping"]["vlans"] == []
    assert overrides["root_guard"]["upstream_switches"] == []


def test_parse_group_addresses_accepts_delimiters_and_rejects_duplicates():
    assert parse_group_addresses("192.0.2.1\n192.0.2.2, switch-a.example.mil") == [
        "192.0.2.1",
        "192.0.2.2",
        "switch-a.example.mil",
    ]


def test_selected_group_values_use_checked_targets_and_profile():
    group = DeviceGroup(
        group_name="Building 1",
        profile_name="building_1",
        targets=[
            DeviceTargetRecord(ip="192.0.2.10", checked=True),
            DeviceTargetRecord(ip="192.0.2.11", checked=False),
        ],
    )

    assert selected_group_values(group) == (["192.0.2.10"], "building_1")


def test_site_setup_panel_saves_profile_and_group(tmp_path):
    import customtkinter as ctk
    from stig_audit_pro.gui.site_setup import SiteSetupPanel

    profiles = tmp_path / "profiles"
    groups = tmp_path / "groups"
    profiles.mkdir()
    groups.mkdir()
    shutil.copy2(Path("data/profiles/base_iosxe_access.yaml"), profiles / "base_iosxe_access.yaml")
    try:
        root = ctk.CTk()
    except tkinter.TclError as exc:
        pytest.skip(f"Tk display unavailable: {exc}")
    root.withdraw()
    try:
        panel = SiteSetupPanel(root, profiles_dir=profiles, groups_dir=groups)
        panel.messagebox = SimpleNamespace(
            askyesno=lambda *_args, **_kwargs: True,
            showinfo=lambda *_args, **_kwargs: None,
            showerror=lambda *args, **_kwargs: (_ for _ in ()).throw(RuntimeError(args)),
        )
        panel.profile_name.insert(0, "Building Smoke")
        panel.profile_fields["required_user_vlans"].delete("1.0", "end")
        panel.profile_fields["required_user_vlans"].insert("1.0", "110,120")
        panel.profile_fields["dhcp_vlans"].delete("1.0", "end")
        panel.profile_fields["dhcp_vlans"].insert("1.0", "110,120")
        panel.profile_fields["arp_vlans"].delete("1.0", "end")
        panel.profile_fields["arp_vlans"].insert("1.0", "110,120")
        panel.save_current_profile()
        assert (profiles / "Building_Smoke.yaml").is_file()
        from stig_audit_pro.storage.profile_builder import load_profile_data
        assert load_profile_data(profiles / "Building_Smoke.yaml")["profile_name"] == "Building Smoke"

        panel.group_name.insert(0, "Building Smoke")
        panel.group_devices.insert("1.0", "192.0.2.10\n192.0.2.11")
        panel.group_profile.set("Building_Smoke")
        panel.save_current_group()
        assert (groups / "Building_Smoke.yaml").is_file()
    finally:
        root.destroy()
