from __future__ import annotations

import pytest

from stig_audit_pro.storage.inventory_importer import (
    InventoryImportError,
    build_inventory_plan,
    inventory_template_csv,
)


def test_build_inventory_plan_groups_rows_and_resolves_profiles():
    source = """building,profile,platform,hostname,ip
Building 1,Building_1,IOS XE,SW-B1-01,192.0.2.10
Building 1,Building_1,IOS XE,SW-B1-02,192.0.2.11
Building 2,Building_2,IOS XE,SW-B2-01,192.0.2.20
"""

    plan = build_inventory_plan(source, ["Building_1", "Building_2"])

    assert plan.source_rows == 3
    assert [(group.group_name, group.profile_name) for group in plan.groups] == [
        ("Building 1", "Building_1"),
        ("Building 2", "Building_2"),
    ]
    assert [target.ip for target in plan.groups[0].targets] == ["192.0.2.10", "192.0.2.11"]


def test_build_inventory_plan_matches_building_to_profile_when_profile_is_blank():
    source = """building,platform,ip
Building 1,IOS XE,192.0.2.10
"""

    plan = build_inventory_plan(source, ["Building_1"])

    assert plan.groups[0].profile_name == "Building_1"


def test_build_inventory_plan_rejects_mixed_profiles_in_one_building():
    source = """building,profile,ip
Building 1,Building_1,192.0.2.10
Building 1,Building_1_Alternate,192.0.2.11
"""

    with pytest.raises(InventoryImportError, match="multiple profiles"):
        build_inventory_plan(source, ["Building_1", "Building_1_Alternate"])


def test_build_inventory_plan_rejects_mixed_platforms_even_when_first_row_is_blank():
    source = """building,profile,platform,ip
Building 1,Building_1,,192.0.2.10
Building 1,Building_1,IOS XE,192.0.2.11
Building 1,Building_1,IOS,192.0.2.12
"""

    with pytest.raises(InventoryImportError, match="multiple platforms"):
        build_inventory_plan(source, ["Building_1"])


def test_build_inventory_plan_rejects_duplicates_across_buildings():
    source = """building,profile,ip
Building 1,Building_1,192.0.2.10
Building 2,Building_2,192.0.2.10
"""

    with pytest.raises(InventoryImportError, match="duplicate device"):
        build_inventory_plan(source, ["Building_1", "Building_2"])


def test_build_inventory_plan_requires_building_and_address_columns():
    with pytest.raises(InventoryImportError, match="building"):
        build_inventory_plan("profile,ip\nBuilding_1,192.0.2.10\n", ["Building_1"])

    with pytest.raises(InventoryImportError, match="address"):
        build_inventory_plan("building,profile\nBuilding 1,Building_1\n", ["Building_1"])


def test_inventory_template_has_required_and_optional_columns():
    template = inventory_template_csv()

    assert template.splitlines()[0] == "building,profile,platform,hostname,ip"
    assert "Building 1,Building_1,IOS XE,SW-B1-01,10.10.1.11" in template

